from flask import Flask, render_template, jsonify, request, send_file, Response, session, redirect
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
import requests
import threading
import os
import json
import tempfile
import io
import zipfile
import logging
from datetime import datetime, timedelta
import hashlib
import base64
import jwt
from functools import wraps
import time
import urllib3
import uuid
import secrets
import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import psycopg2
import psycopg2.extras
import subprocess
import asyncio
from threading import Thread

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Application version - build timestamp
APP_VERSION = "4.0.0"
BUILD_TIMESTAMP = f"{APP_VERSION}-{int(datetime.now().timestamp())}"

# Database connection for multi-user authentication
# import bcrypt  # Replaced with SHA-256 for better compatibility

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Global flag to ensure database is initialized only once
_db_initialized = False

# Global variables for update status tracking
update_status = {
    'in_progress': False,
    'completed': False,
    'success': False,
    'message': 'Ready',
    'progress': 0,
    'error': None
}

# GitHub repository information
GITHUB_REPO = 'alexbnn/ca-manager'
GITHUB_API_URL = f'https://api.github.com/repos/{GITHUB_REPO}'

def ensure_database_initialized():
    """Ensure database is initialized exactly once"""
    global _db_initialized
    if not _db_initialized:
        logging.info("Initializing database for CA Manager...")
        if initialize_database():
            _db_initialized = True
            logging.info("Database initialization completed successfully")
        else:
            logging.error("Database initialization failed!")
    return _db_initialized

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://pkiuser:pkipass@postgres:5432/pkiauth')

# Email configuration for verification
SMTP_HOST = os.getenv('SMTP_HOST', 'localhost')
SMTP_PORT = int(os.getenv('SMTP_PORT', '25'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'false').lower() == 'true'
SMTP_FROM_EMAIL = os.getenv('SMTP_FROM_EMAIL', 'noreply@ca.bonner.com')
EMAIL_VERIFICATION_REQUIRED = os.getenv('EMAIL_VERIFICATION_REQUIRED', 'true').lower() == 'true'

def get_db_connection():
    """Get database connection"""
    try:
        return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    except Exception as e:
        logging.error(f"Database connection failed: {e}")
        return None

def initialize_database():
    """Initialize database with schema and default data if needed"""
    try:
        logging.info("Checking database initialization...")
        conn = get_db_connection()
        if not conn:
            logging.error("Cannot initialize database: connection failed")
            return False
        
        cursor = conn.cursor()
        
        # Check if users table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'users'
            );
        """)
        
        table_exists = cursor.fetchone()['exists']
        
        if not table_exists:
            logging.info("Database not initialized. Running initialization scripts...")
            
            # Execute database schema files in order
            schema_files = [
                '01-schema.sql',
                '02-initial-data.sql', 
                '03-tenant-schema.sql',
                '04-ocsp-schema.sql',
                '05-system-config.sql',
                '06-intermediate-ca-schema.sql'
            ]
            
            for schema_file in schema_files:
                try:
                    with open(f'/app/database/{schema_file}', 'r') as f:
                        schema_sql = f.read()
                    cursor.execute(schema_sql)
                    logging.info(f"Database schema file {schema_file} executed successfully")
                except FileNotFoundError:
                    logging.warning(f"Schema file {schema_file} not found, skipping")
                    continue
                except Exception as e:
                    logging.error(f"Schema file {schema_file} execution failed: {e}")
                    conn.rollback()
                    return False
            
            conn.commit()
            logging.info("Database initialization completed successfully")
        else:
            logging.info("Database already initialized")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        logging.error(f"Database initialization error: {e}")
        return False

def authenticate_user(username, password):
    """Authenticate user with database"""
    # Ensure database is initialized before authentication
    ensure_database_initialized()
    
    try:
        conn = get_db_connection()
        if not conn:
            logging.error("Failed to get database connection")
            return None
        
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.username, u.email, u.full_name, u.password_hash, u.is_admin, u.is_active,
                       array_agg(r.name) as roles
                FROM users u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.id
                WHERE u.username = %s AND u.is_active = true
                GROUP BY u.id, u.username, u.email, u.full_name, u.password_hash, u.is_admin, u.is_active
            """, (username,))
            
            user = cursor.fetchone()
            if user:
                logging.info(f"User found: {username}, has_password_hash: {bool(user['password_hash'])}")
                # Log first few chars of hash for debugging (safely)
                if user['password_hash']:
                    logging.debug(f"Password hash starts with: {user['password_hash'][:10]}...")
                
                # Regular password authentication for all users
                if user['password_hash'] and password:
                    try:
                        # SHA-256 hash verification
                        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                        if password_hash == user['password_hash']:
                            conn.close()
                            logging.info(f"Authentication successful for user: {username}")
                            return dict(user)
                        else:
                            logging.warning(f"Password verification failed for user: {username}")
                    except Exception as e:
                        logging.error(f"SHA-256 hash error for user {username}: {e}")
                else:
                    logging.warning(f"Missing password hash or password for user: {username}")
            
        conn.close()
        return None
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return None

def get_user_by_id(user_id):
    """Get user by ID with roles"""
    try:
        conn = get_db_connection()
        if not conn:
            return None
        
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.username, u.email, u.full_name, u.is_admin, u.is_active,
                       array_agg(r.name) as roles
                FROM users u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.id
                WHERE u.id = %s AND u.is_active = true
                GROUP BY u.id, u.username, u.email, u.full_name, u.is_admin, u.is_active
            """, (user_id,))
            
            user = cursor.fetchone()
        
        conn.close()
        return dict(user) if user else None
    except Exception as e:
        logging.error(f"Error getting user: {e}")
        return None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/audit.log'),
        logging.StreamHandler()
    ]
)

# Rate limiter configuration - temporarily disabled
# REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379')
# limiter = Limiter(
#     get_remote_address,
#     app=app,
#     default_limits=["200 per day", "50 per hour"],
#     storage_uri=REDIS_URL
# )

# Configuration for the EasyRSA container
# Use tenant-specific container names when TENANT_ID is provided
TENANT_ID = os.getenv('TENANT_ID', '')
if TENANT_ID:
    # Multi-tenant deployment - use tenant-specific container names
    TERMINAL_CONTAINER_URL = os.getenv('TERMINAL_CONTAINER_URL', f'http://easyrsa-{TENANT_ID}:8080')
    SCEP_SERVER_URL = os.getenv('SCEP_SERVER_URL', f'http://scep-{TENANT_ID}:8090')
else:
    # Single-tenant deployment - use standard container names
    TERMINAL_CONTAINER_URL = os.getenv('TERMINAL_CONTAINER_URL', 'http://easyrsa-container:8080')
    SCEP_SERVER_URL = os.getenv('SCEP_SERVER_URL', 'http://scep-server:8090')

TERMINAL_ENDPOINT = os.getenv('TERMINAL_ENDPOINT', '/execute')
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '300'))

# Authentication settings
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH', 'admin')  # Legacy fallback
AUTHENTICATION_ENABLED = os.getenv('AUTHENTICATION_ENABLED', 'false').lower() == 'true'
MULTI_USER_MODE = os.getenv('MULTI_USER_MODE', 'true').lower() == 'true'

def log_operation(operation, details=None):
    """Log operations for audit trail"""
    user_id = session.get('user_id')
    username = session.get('username', 'anonymous')
    
    # Log to database if available
    if MULTI_USER_MODE:
        try:
            conn = get_db_connection()
            if conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO audit_logs (user_id, username, operation, details, ip_address, user_agent, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        user_id,
                        username,
                        operation,
                        json.dumps(details) if details else None,
                        request.remote_addr,
                        request.user_agent.string if request.user_agent else None,
                        'success'
                    ))
                    conn.commit()
                conn.close()
        except Exception as e:
            logging.error(f"Failed to log to database: {e}")
    
    # Also log to file for backwards compatibility
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'operation': operation,
        'user': username,
        'ip': request.remote_addr,
        'details': details
    }
    logging.info(f"AUDIT: {json.dumps(log_entry)}")

def get_system_config(config_key, default_value=None):
    """Get system configuration value from database"""
    conn = get_db_connection()
    if not conn:
        return default_value
    
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT config_value FROM system_config WHERE config_key = %s",
                (config_key,)
            )
            result = cursor.fetchone()
        conn.close()
        return result['config_value'] if result else default_value
    except Exception as e:
        logging.error(f"Error getting system config {config_key}: {e}")
        if conn:
            conn.close()
        return default_value

def set_system_config(config_key, config_value, user_id=None, description=None):
    """Set system configuration value in database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cursor:
            # Check if config exists
            cursor.execute(
                "SELECT id FROM system_config WHERE config_key = %s",
                (config_key,)
            )
            exists = cursor.fetchone()
            
            if exists:
                # Update existing config
                cursor.execute(
                    """UPDATE system_config 
                       SET config_value = %s, updated_by = %s, updated_at = CURRENT_TIMESTAMP
                       WHERE config_key = %s""",
                    (config_value, user_id, config_key)
                )
            else:
                # Insert new config
                cursor.execute(
                    """INSERT INTO system_config (config_key, config_value, description, updated_by)
                       VALUES (%s, %s, %s, %s)""",
                    (config_key, config_value, description, user_id)
                )
            conn.commit()
        conn.close()
        return True
    except Exception as e:
        logging.error(f"Error setting system config {config_key}: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False

def auth_required(permission=None):
    """Authentication decorator with optional permission check"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not AUTHENTICATION_ENABLED:
                return f(*args, **kwargs)
            
            # Check if user is authenticated
            if MULTI_USER_MODE:
                # Multi-user mode: check session
                if not session.get('authenticated'):
                    return _handle_auth_error()
                
                # Check permission if specified (admins bypass permission checks)
                if permission and not session.get('is_admin', False):
                    user_roles = session.get('roles', [])
                    # Simple role-based permission check
                    if permission == 'admin' and 'admin' not in user_roles:
                        return _handle_permission_error()
                    elif permission == 'operator' and not any(role in user_roles for role in ['admin', 'operator']):
                        return _handle_permission_error()
                        
            else:
                # Legacy single-user mode
                if 'authenticated' not in session:
                    return _handle_auth_error()
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def _handle_auth_error():
    """Handle authentication errors"""
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    else:
        return redirect('/login')

def _handle_permission_error():
    """Handle permission errors"""
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'status': 'error', 'message': 'Insufficient permissions'}), 403
    else:
        return render_template('error.html', message='Insufficient permissions'), 403

@app.before_request
def log_request():
    """Log all requests"""
    if request.endpoint not in ['static', 'health']:
        logging.info(f"Request: {request.method} {request.path} from {request.remote_addr}")

@app.route('/')
def index():
    # Ensure database is initialized on first access
    ensure_database_initialized()
    
    if AUTHENTICATION_ENABLED:
        if MULTI_USER_MODE:
            if not session.get('authenticated'):
                return render_template('login.html', version=BUILD_TIMESTAMP)
        else:
            if 'authenticated' not in session:
                return render_template('login.html', version=BUILD_TIMESTAMP)
    
    # Get user info for template
    user_info = {
        'username': session.get('username', 'guest'),
        'is_admin': session.get('is_admin', False),
        'roles': session.get('roles', [])
    }
    
    return render_template('index.html', user=user_info)

@app.route('/login')
def login_page():
    """Serve the login page"""
    if AUTHENTICATION_ENABLED:
        if MULTI_USER_MODE:
            if not session.get('authenticated'):
                return render_template('login.html', version=BUILD_TIMESTAMP)
        else:
            if 'authenticated' not in session:
                return render_template('login.html', version=BUILD_TIMESTAMP)
    return redirect('/')

@app.route('/health')
def health():
    """Health check endpoint for Docker"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()}), 200

@app.route('/api/login', methods=['POST'])
def login():
    """Authentication endpoint supporting both multi-user and legacy modes"""
    if not AUTHENTICATION_ENABLED:
        return jsonify({'status': 'success', 'message': 'Authentication disabled'})
    
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    
    if not username:
        return jsonify({'status': 'error', 'message': 'Username required'}), 400
    
    # Password is always required
    if not password:
        return jsonify({'status': 'error', 'message': 'Password required'}), 400
    
    if MULTI_USER_MODE:
        # Multi-user authentication
        logging.info(f"Multi-user mode login attempt for user: {username}")
        try:
            # First check if database is accessible
            conn = get_db_connection()
            if not conn:
                logging.error("Database connection failed - possible password mismatch. Check if postgres volume needs to be reset.")
                return jsonify({
                    'status': 'error', 
                    'message': 'Database connection failed. If you recently ran setup, you may need to reset the database volume. Run: docker volume rm ca-manager-f_postgres-data',
                    'details': 'The database password may have changed. Please check the logs or reset the database volume.'
                }), 503
            conn.close()
            
            user = authenticate_user(username, password)
            if user:
                # Extract role names from the user data
                role_names = user.get('roles', [])
                if role_names and role_names[0] is None:
                    role_names = []
                
                # Set session data
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                session['roles'] = role_names
                session['authenticated'] = True
                
                log_operation('login', {'username': username, 'user_id': user['id']})
                
                return jsonify({
                    'status': 'success', 
                    'message': 'Login successful',
                    'user': {
                        'id': user['id'],
                        'username': user['username'],
                        'email': user['email'],
                        'full_name': user['full_name'],
                        'is_admin': user['is_admin'],
                        'roles': role_names
                    }
                })
            else:
                log_operation('login_failed', {'username': username})
                return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
                
        except Exception as e:
            logging.error(f"Login error: {e}")
            return jsonify({'status': 'error', 'message': 'Authentication service unavailable'}), 503
    
    else:
        # Legacy single-user authentication
        # For backward compatibility, check both plain text and SHA-256 hash
        password_matches = False
        
        # Check if ADMIN_PASSWORD_HASH is a SHA-256 hash (64 hex characters)
        if len(ADMIN_PASSWORD_HASH) == 64 and all(c in '0123456789abcdef' for c in ADMIN_PASSWORD_HASH.lower()):
            # It's a SHA-256 hash, verify properly
            try:
                password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                password_matches = (password_hash == ADMIN_PASSWORD_HASH)
            except:
                password_matches = False
        else:
            # Plain text comparison for backward compatibility
            password_matches = (password == ADMIN_PASSWORD_HASH)
        
        if username == ADMIN_USERNAME and password_matches:
            session['authenticated'] = True
            session['username'] = username
            session['is_admin'] = True
            log_operation('login', {'username': username})
            return jsonify({'status': 'success', 'message': 'Login successful'})
        
        log_operation('login_failed', {'username': username})
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    """API logout endpoint"""
    username = session.get('username')
    session_token = session.get('session_token')
    
    # Invalidate session token if in multi-user mode
    # Session cleanup handled by session.clear()
    
    log_operation('logout', {'username': username})
    session.clear()
    return jsonify({'status': 'success', 'message': 'Logged out successfully'})

@app.route('/logout')
def logout_page():
    """Web logout endpoint"""
    username = session.get('username')
    session_token = session.get('session_token')
    
    # Invalidate session token if in multi-user mode
    # Session cleanup handled by session.clear()
    
    log_operation('logout', {'username': username})
    session.clear()
    return redirect('/login')

def make_easyrsa_request(operation, params=None):
    """Helper function to make requests to EasyRSA container"""
    if params is None:
        params = {}
    
    data = {
        "operation": operation,
        "params": params
    }
    
    try:
        response = requests.post(
            f"{TERMINAL_CONTAINER_URL}{TERMINAL_ENDPOINT}",
            json=data,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return {
                "status": "error",
                "message": f"EasyRSA container returned status {response.status_code}: {response.text}"
            }
    except requests.exceptions.Timeout:
        return {"status": "error", "message": "Operation timed out"}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "message": "Could not connect to EasyRSA container"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# PKI Management Endpoints
@app.route('/api/pki/init', methods=['POST'])
@auth_required(permission='pki_init')
# @limiter.limit("5 per minute")
def init_pki():
    """Initialize PKI"""
    log_operation('init_pki')
    result = make_easyrsa_request('init-pki')
    return jsonify(result)

@app.route('/api/pki/status', methods=['GET'])
@auth_required(permission='pki_read')
def pki_status():
    """Get PKI status"""
    result = make_easyrsa_request('status')
    return jsonify(result)

# Certificate Authority Endpoints
@app.route('/api/ca/build', methods=['POST'])
@auth_required(permission='ca_build')
# @limiter.limit("2 per hour")
def build_ca():
    """Build Certificate Authority with full configuration"""
    data = request.get_json() or {}
    
    # Extract CA configuration parameters
    ca_config = {
        'common_name': data.get('common_name', 'Easy-RSA CA'),
        'country': data.get('country', 'US'),
        'state': data.get('state', 'CA'),
        'city': data.get('city', 'San Francisco'),
        'organization': data.get('organization', 'My Organization'),
        'organizational_unit': data.get('organizational_unit', 'IT Department'),
        'email': data.get('email', 'admin@myorg.com'),
        'ca_validity_days': data.get('ca_validity_days', 3650),
        'cert_validity_days': data.get('cert_validity_days', 365),
        'key_size': data.get('key_size', 2048),
        'digest_algorithm': data.get('digest_algorithm', 'sha256')
    }
    
    log_operation('build_ca', ca_config)
    result = make_easyrsa_request('build-ca', ca_config)
    return jsonify(result)

@app.route('/api/ca/show', methods=['GET'])
@auth_required(permission='ca_read')
def show_ca():
    """Show CA certificate details"""
    result = make_easyrsa_request('show-ca')
    return jsonify(result)

@app.route('/api/ca/download', methods=['GET'])
@auth_required(permission='ca_read')
def download_ca():
    """Download CA certificate"""
    try:
        log_operation('download_ca')
        response = requests.get(f"{TERMINAL_CONTAINER_URL}/download-ca", timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            ca_content = response.content
            file_obj = io.BytesIO(ca_content)
            
            return send_file(
                file_obj,
                as_attachment=True,
                download_name='ca.pem',
                mimetype='application/x-pem-file'
            )
        else:
            return jsonify({
                "status": "error", 
                "message": f"CA certificate not found. Container response: {response.status_code}"
            }), 404
            
    except requests.exceptions.ConnectionError:
        return jsonify({
            "status": "error",
            "message": "Could not connect to EasyRSA container"
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to download CA certificate: {str(e)}"
        }), 500

# Certificate Management Endpoints
@app.route('/api/certificates/create-full', methods=['POST'])
@auth_required()
# @limiter.limit("10 per minute")
def create_full_certificate():
    """Create a full certificate (generate + sign)"""
    data = request.get_json() or {}
    name = data.get('name')
    cert_type = data.get('type', 'client')
    
    if not name:
        return jsonify({"status": "error", "message": "Certificate name is required"}), 400
    
    log_operation('create_full_certificate', {'name': name, 'type': cert_type})
    operation = 'build-client-full' if cert_type == 'client' else 'build-server-full'
    result = make_easyrsa_request(operation, {'name': name})
    return jsonify(result)

@app.route('/api/certificates/generate-request', methods=['POST'])
@auth_required()
# @limiter.limit("10 per minute")
def generate_request():
    """Generate certificate request"""
    data = request.get_json() or {}
    name = data.get('name')
    
    if not name:
        return jsonify({"status": "error", "message": "Certificate name is required"}), 400
    
    log_operation('generate_request', {'name': name})
    result = make_easyrsa_request('gen-req', {'name': name})
    return jsonify(result)

@app.route('/api/certificates/sign-request', methods=['POST'])
@auth_required()
# @limiter.limit("10 per minute")
def sign_request():
    """Sign certificate request"""
    data = request.get_json() or {}
    name = data.get('name')
    cert_type = data.get('type', 'client')
    
    if not name:
        return jsonify({"status": "error", "message": "Certificate name is required"}), 400
    
    log_operation('sign_request', {'name': name, 'type': cert_type})
    result = make_easyrsa_request('sign-req', {'name': name, 'type': cert_type})
    return jsonify(result)

@app.route('/api/certificates/show/<name>', methods=['GET'])  # Fixed the bug here
@auth_required()
def show_certificate(name):
    """Show certificate details"""
    log_operation('show_certificate', {'name': name})
    result = make_easyrsa_request('show-cert', {'name': name})
    return jsonify(result)

@app.route('/api/certificates/download/<name>', methods=['GET'])
@auth_required()
def download_certificate(name):
    """Download certificate bundle"""
    try:
        cert_type = request.args.get('format', 'zip')  # zip, p12, pem
        include_key = request.args.get('include_key', 'true').lower() == 'true'
        
        log_operation('download_certificate', {'name': name, 'format': cert_type})
        
        # Get certificate files from EasyRSA container
        result = make_easyrsa_request('get-cert-files', {'name': name, 'include_key': include_key})
        
        if result.get('status') != 'success':
            return jsonify(result), 404
        
        if cert_type == 'zip':
            # Create ZIP bundle
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add certificate
                if 'certificate' in result:
                    zip_file.writestr(f"{name}.crt", result['certificate'])
                
                # Add private key if requested
                if include_key and 'private_key' in result:
                    zip_file.writestr(f"{name}.key", result['private_key'])
                
                # Add CA certificate
                if 'ca_certificate' in result:
                    zip_file.writestr("ca.pem", result['ca_certificate'])
            
            zip_buffer.seek(0)
            return send_file(
                zip_buffer,
                as_attachment=True,
                download_name=f"{name}-bundle.zip",
                mimetype='application/zip'
            )
        
        elif cert_type == 'pem':
            # Return PEM bundle
            pem_content = result.get('certificate', '')
            if include_key and 'private_key' in result:
                pem_content += '\n' + result['private_key']
            
            return send_file(
                io.BytesIO(pem_content.encode()),
                as_attachment=True,
                download_name=f"{name}.pem",
                mimetype='application/x-pem-file'
            )
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to download certificate: {str(e)}"
        }), 500

@app.route('/api/certificates/validate/<name>', methods=['GET'])
@auth_required()
def validate_certificate(name):
    """Validate certificate expiry, chain, etc."""
    log_operation('validate_certificate', {'name': name})
    result = make_easyrsa_request('validate-cert', {'name': name})
    return jsonify(result)

@app.route('/api/certificates/revoke', methods=['POST'])
@auth_required()
# @limiter.limit("5 per minute")
def revoke_certificate():
    """Revoke a certificate"""
    data = request.get_json() or {}
    name = data.get('name')
    
    if not name:
        return jsonify({"status": "error", "message": "Certificate name is required"}), 400
    
    log_operation('revoke_certificate', {'name': name})
    result = make_easyrsa_request('revoke', {'name': name})
    return jsonify(result)

@app.route('/api/certificates/list', methods=['GET'])
@auth_required()
def list_certificates():
    """List all certificates"""
    result = make_easyrsa_request('list-certs')
    return jsonify(result)

@app.route('/api/certificates/expiring', methods=['GET'])
@auth_required()
def get_expiring_certificates():
    """Get certificates expiring within specified days"""
    days = request.args.get('days', 30)
    result = make_easyrsa_request('check-expiring', {'days': int(days)})
    return jsonify(result)

@app.route('/api/certificates/<path:cert_name>/resend-email', methods=['POST'])
@auth_required()
def resend_certificate_email(cert_name):
    """Resend certificate email to the certificate owner"""
    try:
        # First, get certificate files from EasyRSA
        files_result = make_easyrsa_request("get-cert-files", {"name": cert_name, "include_key": True})
        
        if files_result.get("status") != "success":
            return jsonify({'error': 'Certificate not found or could not be retrieved'}), 404
        
        cert_pem = files_result.get("certificate")
        key_pem = files_result.get("private_key")
        ca_cert_pem = files_result.get("ca_certificate", "")
        
        if not cert_pem or not key_pem:
            return jsonify({'error': 'Certificate or private key data missing'}), 400
        
        # Extract email from certificate CN (assuming format: user@domain.com)
        try:
            # Parse certificate to get CN
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            # Get the subject common name
            common_name = None
            for attribute in cert_obj.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break
            
            if not common_name or '@' not in common_name:
                return jsonify({'error': 'Certificate does not contain a valid email address in the common name'}), 400
            
            recipient_email = common_name
            recipient_name = common_name.split('@')[0].title()  # Use username part as name
            
        except Exception as e:
            logging.error(f"Error parsing certificate for {cert_name}: {e}")
            return jsonify({'error': 'Failed to parse certificate'}), 500
        
        # Generate a fake request ID for the email (since this is a resend)
        request_id = f"resend-{cert_name}-{int(datetime.now().timestamp())}"
        
        # Send the certificate email
        logging.info(f"Resending certificate email for {cert_name} to {recipient_email}")
        email_sent = send_certificate_email_with_data(
            request_id, recipient_email, recipient_name, common_name,
            cert_pem, key_pem, ca_cert_pem
        )
        
        if email_sent:
            logging.info(f"Certificate email resent successfully for {cert_name} to {recipient_email}")
            return jsonify({
                'status': 'success',
                'message': f'Certificate email resent successfully to {recipient_email}',
                'recipient': recipient_email
            })
        else:
            return jsonify({'error': 'Failed to send certificate email'}), 500
            
    except Exception as e:
        logging.error(f"Error resending certificate email for {cert_name}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/certificates/expiry-dashboard', methods=['GET'])
@auth_required()
def get_expiry_dashboard():
    """Get comprehensive certificate expiry dashboard data"""
    try:
        # Get all certificates using list-certs which includes expiry information
        all_certs = make_easyrsa_request('list-certs')
        if all_certs.get('status') != 'success':
            return jsonify({'status': 'error', 'message': 'Failed to retrieve certificates'})
        
        # Categorize certificates by expiry status
        dashboard_data = {
            'expired': [],
            'critical': [],    # Expiring in 7 days
            'warning': [],     # Expiring in 30 days
            'normal': [],      # Expiring in 90 days
            'healthy': [],     # More than 90 days
            'statistics': {
                'total': 0,
                'expired': 0,
                'critical': 0,
                'warning': 0,
                'normal': 0,
                'healthy': 0
            }
        }
        
        # Process all certificates from list-certs
        certificates = all_certs.get('certificates', [])
        for cert in certificates:
            # Only process issued certificates with expiry information
            if cert.get('type') == 'issued' and 'expires_in_days' in cert:
                days_until_expiry = cert['expires_in_days']
                cert['days_until_expiry'] = days_until_expiry
                
                # Categorize based on expiry time
                if days_until_expiry < 0:
                    cert['expiry_status'] = 'expired'
                    dashboard_data['expired'].append(cert)
                elif days_until_expiry <= 7:
                    cert['expiry_status'] = 'critical'
                    dashboard_data['critical'].append(cert)
                elif days_until_expiry <= 30:
                    cert['expiry_status'] = 'warning'
                    dashboard_data['warning'].append(cert)
                elif days_until_expiry <= 90:
                    cert['expiry_status'] = 'normal'
                    dashboard_data['normal'].append(cert)
                else:
                    cert['expiry_status'] = 'healthy'
                    dashboard_data['healthy'].append(cert)
        
        # Update statistics (count only issued certificates with expiry data)
        issued_certs = [cert for cert in certificates if cert.get('type') == 'issued' and 'expires_in_days' in cert]
        dashboard_data['statistics']['total'] = len(issued_certs)
        dashboard_data['statistics']['expired'] = len(dashboard_data['expired'])
        dashboard_data['statistics']['critical'] = len(dashboard_data['critical'])
        dashboard_data['statistics']['warning'] = len(dashboard_data['warning'])
        dashboard_data['statistics']['normal'] = len(dashboard_data['normal'])
        dashboard_data['statistics']['healthy'] = len(dashboard_data['healthy'])
        
        # Add renewal recommendations
        dashboard_data['recommendations'] = []
        if dashboard_data['statistics']['expired'] > 0:
            dashboard_data['recommendations'].append({
                'priority': 'critical',
                'message': f"{dashboard_data['statistics']['expired']} certificates have expired and need immediate renewal"
            })
        if dashboard_data['statistics']['critical'] > 0:
            dashboard_data['recommendations'].append({
                'priority': 'high',
                'message': f"{dashboard_data['statistics']['critical']} certificates expire within 7 days"
            })
        if dashboard_data['statistics']['warning'] > 0:
            dashboard_data['recommendations'].append({
                'priority': 'medium',
                'message': f"{dashboard_data['statistics']['warning']} certificates expire within 30 days"
            })
        
        return jsonify({'status': 'success', 'dashboard': dashboard_data})
        
    except Exception as e:
        logging.error(f"Failed to generate expiry dashboard: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

# CRL (Certificate Revocation List) Endpoints
@app.route('/api/crl/generate', methods=['POST'])
@auth_required()
# @limiter.limit("5 per minute")
def generate_crl():
    """Generate Certificate Revocation List"""
    log_operation('generate_crl')
    result = make_easyrsa_request('gen-crl')
    return jsonify(result)

# Backup and Restore Endpoints
@app.route('/api/backup/create', methods=['POST'])
@auth_required()
# @limiter.limit("2 per hour")
def create_backup():
    """Create complete PKI backup"""
    log_operation('create_backup')
    result = make_easyrsa_request('create-backup')
    
    if result.get('status') == 'success' and 'backup_data' in result:
        # Decode base64-encoded backup data
        backup_data = base64.b64decode(result['backup_data'])
        backup_filename = f"pki-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
        
        return send_file(
            io.BytesIO(backup_data),
            as_attachment=True,
            download_name=backup_filename,
            mimetype='application/gzip'
        )
    
    return jsonify(result)

@app.route('/api/backup/restore', methods=['POST'])
@auth_required()
# @limiter.limit("1 per hour")
def restore_backup():
    """Restore PKI from backup"""
    if 'backup' not in request.files:
        return jsonify({"status": "error", "message": "No backup file provided"}), 400
    
    backup_file = request.files['backup']
    log_operation('restore_backup', {'filename': backup_file.filename})
    
    # Forward file to EasyRSA container
    # Implementation depends on how you want to handle file uploads
    return jsonify({"status": "error", "message": "Backup restore not yet implemented"})

# Monitoring and Metrics
@app.route('/api/metrics', methods=['GET'])
@auth_required()
def get_metrics():
    """Get system metrics and dashboard data"""
    result = make_easyrsa_request('get-metrics')
    return jsonify(result)

@app.route('/api/scep/health', methods=['GET'])
@auth_required()
def get_scep_health():
    """Get SCEP server health status"""
    try:
        # Always use internal container URL for container-to-container communication
        internal_scep_url = "http://scep-server:8090"
        health_check_method = 'internal_container'
        
        # Add debugging information
        debug_info = {
            'health_check_method': health_check_method,
            'internal_scep_url': internal_scep_url,
            'tenant_id_env': TENANT_ID,
            'scep_server_url_env': os.getenv('SCEP_SERVER_URL', '')
        }
        
        # Check SCEP server health - disable SSL verification for self-signed certificates
        scep_response = requests.get(f"{internal_scep_url}/health", timeout=5, verify=False)
        
        if scep_response.status_code == 200:
            scep_data = scep_response.json()
            return jsonify({
                "status": "success",
                "scep_health": scep_data,
                "debug_info": debug_info,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"SCEP server returned status {scep_response.status_code}",
                "scep_health": {"status": "unhealthy"},
                "debug_info": debug_info,
                "timestamp": datetime.now().isoformat()
            })
            
    except requests.exceptions.RequestException as e:
        return jsonify({
            "status": "error",
            "message": f"Cannot connect to SCEP server: {str(e)}",
            "scep_health": {"status": "offline"},
            "debug_info": debug_info if 'debug_info' in locals() else {},
            "timestamp": datetime.now().isoformat()
        })

@app.route('/api/scep/info', methods=['GET'])
@auth_required()
def get_scep_info():
    """Get SCEP server information"""
    try:
        # Always use internal container URL for container-to-container communication
        internal_scep_url = "http://scep-server:8090"
        
        # Log the URL being used for debugging
        print(f"Attempting to connect to SCEP server at: {internal_scep_url}")
        
        # Get SCEP server information - disable SSL verification for self-signed certificates
        scep_response = requests.get(f"{internal_scep_url}/scep", timeout=10, verify=False)
        
        if scep_response.status_code == 200:
            scep_data = scep_response.json()
            
            # Rewrite internal URLs to public URLs
            if 'endpoints' in scep_data:
                # Get current request host for public URLs
                host = request.headers.get('Host', 'localhost')
                # Always use HTTPS for public URLs (we're behind Traefik with SSL termination)
                protocol = 'https'
                public_base_url = f"{protocol}://{host}"
                
                # Update all endpoint URLs to use public domain
                updated_endpoints = {}
                for endpoint_name, internal_url in scep_data['endpoints'].items():
                    if internal_url.startswith('http://scep-server:8090'):
                        # Replace internal URL with public URL
                        public_url = internal_url.replace('http://scep-server:8090', public_base_url)
                        updated_endpoints[endpoint_name] = public_url
                    elif internal_url.startswith(f'{internal_scep_url}'):
                        # Replace internal URL with public URL
                        public_url = internal_url.replace(internal_scep_url, public_base_url)
                        updated_endpoints[endpoint_name] = public_url
                    else:
                        updated_endpoints[endpoint_name] = internal_url
                
                scep_data['endpoints'] = updated_endpoints
                
                # Add public base URL for reference
                scep_data['public_base_url'] = public_base_url
            
            return jsonify({
                "status": "success",
                "scep_info": scep_data,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"SCEP server returned status {scep_response.status_code}",
                "debug_info": {
                    "scep_url_attempted": f"{internal_scep_url}/scep",
                    "tenant_id": TENANT_ID,
                    "configured_scep_url": SCEP_SERVER_URL
                },
                "timestamp": datetime.now().isoformat()
            })
            
    except requests.exceptions.RequestException as e:
        return jsonify({
            "status": "error",
            "message": f"Cannot connect to SCEP server: {str(e)}",
            "debug_info": {
                "scep_url_attempted": f"{internal_scep_url}/scep" if 'internal_scep_url' in locals() else "URL not determined",
                "tenant_id": TENANT_ID,
                "configured_scep_url": SCEP_SERVER_URL
            },
            "timestamp": datetime.now().isoformat()
        })

def ensure_ca_subdomain(url):
    """Ensure URL has ca subdomain for SCEP endpoints"""
    from urllib.parse import urlparse, urlunparse
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    if not hostname:
        return url
    
    # Don't modify localhost or IP addresses
    if 'localhost' in hostname or hostname.replace('.', '').replace(':', '').isdigit():
        return url
    
    # Check if we need to add/modify subdomain
    parts = hostname.split('.')
    if len(parts) >= 2:
        if parts[0] != 'ca':
            # Either add ca. prefix or replace existing subdomain
            if len(parts) == 2:
                # Just domain.com, add ca. prefix
                new_hostname = f'ca.{hostname}'
            else:
                # Has subdomain, replace with ca
                base_domain = '.'.join(parts[-2:])
                new_hostname = f'ca.{base_domain}'
            
            # Reconstruct URL with new hostname
            new_netloc = new_hostname
            if parsed.port:
                new_netloc = f'{new_hostname}:{parsed.port}'
            
            return urlunparse((
                parsed.scheme,
                new_netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
    
    return url

@app.route('/api/scep/url', methods=['GET'])
@auth_required()
def get_scep_url():
    """Get the SCEP server URL for this tenant"""
    try:
        # Get the current request host for external URL generation
        host = request.headers.get('Host', 'localhost')
        app.logger.info(f"SCEP URL - Raw host header: {host}")
        subdomain = host.split('.')[0] if '.' in host else 'localhost'
        scep_identifier = f"pki-{subdomain}"
        
        # Get the protocol
        protocol = 'https' if request.is_secure else 'http'
        
        # Check if SCEP_SERVER_URL is properly configured with external domain
        if SCEP_SERVER_URL.startswith('https://') and not any(internal in SCEP_SERVER_URL for internal in ['scep-server:', 'scep-', ':8090']):
            # SCEP_SERVER_URL is properly configured with external domain
            base_url = SCEP_SERVER_URL.rstrip('/scep').rstrip('/')
            # Ensure ca subdomain for SCEP URLs
            base_url = ensure_ca_subdomain(base_url)
            scep_client_url = f"{base_url}/scep/{scep_identifier}"
            test_base_url = base_url
        elif SCEP_SERVER_URL.startswith('http://') and not any(internal in SCEP_SERVER_URL for internal in ['scep-server:', 'scep-', ':8090']):
            # SCEP_SERVER_URL is configured with external domain but using HTTP
            base_url = SCEP_SERVER_URL.rstrip('/scep').rstrip('/')
            base_url = base_url.replace('http://', 'https://')
            # Ensure ca subdomain for SCEP URLs
            base_url = ensure_ca_subdomain(base_url)
            scep_client_url = f"{base_url}/scep/{scep_identifier}"
            test_base_url = base_url
        else:
            # SCEP_SERVER_URL is not configured or uses internal container names
            # Fall back to using current request host for external access
            # For SCEP, always use ca.domain.com format
            if 'localhost' in host or host.replace('.', '').replace(':', '').isdigit():
                # It's localhost or IP address, use as-is
                scep_host = host
            else:
                # It's a domain - ensure it has ca. prefix for SCEP
                # If host is already ca.domain.com, use it as-is
                # If host is just domain.com, add ca. prefix
                # If host is subdomain.domain.com where subdomain != ca, replace with ca.domain.com
                host_parts = host.split('.')
                if len(host_parts) >= 2:
                    if host_parts[0] == 'ca':
                        # Already has ca subdomain, use as-is
                        scep_host = host
                    elif len(host_parts) == 2:
                        # It's just domain.com, add ca. prefix
                        scep_host = f"ca.{host}"
                    else:
                        # It's subdomain.domain.com, replace subdomain with ca
                        # Keep the base domain (last two parts)
                        base_domain = '.'.join(host_parts[-2:])
                        scep_host = f"ca.{base_domain}"
                else:
                    # Single part host (shouldn't happen for real domains)
                    scep_host = host
            
            scep_client_url = f"https://{scep_host}/scep/{scep_identifier}"
            test_base_url = f"https://{scep_host}"
            
            app.logger.info(f"SCEP URL - Final scep_host: {scep_host}, scep_client_url: {scep_client_url}")
        
        return jsonify({
            "status": "success",
            "scep_url": scep_client_url,
            "base_url": test_base_url,
            "scep_identifier": scep_identifier,
            "configured_url": SCEP_SERVER_URL
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error getting SCEP URL: {str(e)}"
        })

@app.route('/api/scep/url/public', methods=['GET'])
def get_scep_url_public():
    """Get the SCEP server URL for this tenant - Public endpoint for simulators"""
    try:
        # Get the current request host for external URL generation
        host = request.headers.get('Host', 'localhost')
        subdomain = host.split('.')[0] if '.' in host else 'localhost'  
        scep_identifier = f"pki-{subdomain}"
        
        # Get the protocol
        protocol = 'https' if request.is_secure else 'http'
        
        # Check if SCEP_SERVER_URL is properly configured with external domain
        if SCEP_SERVER_URL.startswith('https://') and not any(internal in SCEP_SERVER_URL for internal in ['scep-server:', 'scep-', ':8090']):
            # SCEP_SERVER_URL is properly configured with external domain
            base_url = SCEP_SERVER_URL.rstrip('/scep').rstrip('/')
            # Ensure ca subdomain for SCEP URLs
            base_url = ensure_ca_subdomain(base_url)
            scep_client_url = f"{base_url}/scep/{scep_identifier}"
            test_base_url = base_url
        elif SCEP_SERVER_URL.startswith('http://') and not any(internal in SCEP_SERVER_URL for internal in ['scep-server:', 'scep-', ':8090']):
            # SCEP_SERVER_URL is configured with external domain but using HTTP
            base_url = SCEP_SERVER_URL.rstrip('/scep').rstrip('/')
            base_url = base_url.replace('http://', 'https://')
            # Ensure ca subdomain for SCEP URLs
            base_url = ensure_ca_subdomain(base_url)
            scep_client_url = f"{base_url}/scep/{scep_identifier}"
            test_base_url = base_url
        else:
            # SCEP_SERVER_URL is not configured or uses internal container names
            # Fall back to using current request host for external access
            # For SCEP, always use ca.domain.com format
            if 'localhost' in host or host.replace('.', '').replace(':', '').isdigit():
                # It's localhost or IP address, use as-is
                scep_host = host
            else:
                # It's a domain - ensure it has ca. prefix for SCEP
                # If host is already ca.domain.com, use it as-is
                # If host is just domain.com, add ca. prefix
                # If host is subdomain.domain.com where subdomain != ca, replace with ca.domain.com
                host_parts = host.split('.')
                if len(host_parts) >= 2:
                    if host_parts[0] == 'ca':
                        # Already has ca subdomain, use as-is
                        scep_host = host
                    elif len(host_parts) == 2:
                        # It's just domain.com, add ca. prefix
                        scep_host = f"ca.{host}"
                    else:
                        # It's subdomain.domain.com, replace subdomain with ca
                        # Keep the base domain (last two parts)
                        base_domain = '.'.join(host_parts[-2:])
                        scep_host = f"ca.{base_domain}"
                else:
                    # Single part host (shouldn't happen for real domains)
                    scep_host = host
            
            scep_client_url = f"https://{scep_host}/scep/{scep_identifier}"
            test_base_url = f"https://{scep_host}"
            
            app.logger.info(f"SCEP URL - Final scep_host: {scep_host}, scep_client_url: {scep_client_url}")
        
        return jsonify({
            "status": "success",
            "scep_url": scep_client_url,
            "base_url": test_base_url,
            "scep_identifier": scep_identifier,
            "configured_url": SCEP_SERVER_URL
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error getting SCEP URL: {str(e)}"
        })

@app.route('/api/internal/scep-password', methods=['GET'])
def get_scep_password_internal():
    """Internal endpoint for SCEP server to get password from database (no auth required)"""
    # Only allow internal service calls
    if request.remote_addr not in ['127.0.0.1', 'localhost'] and not request.remote_addr.startswith('172.'):
        return jsonify({"error": "Forbidden"}), 403
    
    try:
        current_password = get_system_config('scep_password', 'MySecretSCEPPassword123')
        return jsonify({
            "status": "success",
            "password": current_password,
            "password_length": len(current_password)
        })
    except Exception as e:
        logging.error(f"Error getting SCEP password for internal service: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scep/password', methods=['GET', 'POST'])
@auth_required()
def manage_scep_password():
    """Get or update SCEP challenge password"""
    try:
        if request.method == 'GET':
            # Get current SCEP password from database first
            current_password = get_system_config('scep_password', 'MySecretSCEPPassword123')
            
            # Sync with SCEP server to ensure it has the latest password
            try:
                scep_config_response = requests.post(
                    "http://scep-server:8090/reload-config",
                    json={"password": current_password},  # Send current DB password to SCEP server
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                if scep_config_response.status_code == 200:
                    scep_info = scep_config_response.json()
                    password_length = len(current_password)
                    password_set = bool(current_password)
                    logging.info(f"SCEP server synced with database password: length={password_length}")
                else:
                    # SCEP server couldn't be synced, but we have the DB value
                    logging.warning(f"SCEP server sync returned non-200 status: {scep_config_response.status_code}")
                    password_set = bool(current_password)
                    password_length = len(current_password) if current_password else 0
                    
            except Exception as e:
                logging.warning(f"Could not sync with SCEP server: {e}")
                # Still return the database value
                password_set = bool(current_password)
                password_length = len(current_password) if current_password else 0
                logging.info(f"Using database password: length={password_length}")
            
            # Check if user is admin to include actual password for hover tooltip
            response_data = {
                "status": "success",
                "password_configured": password_set,
                "password_length": password_length,
                "masked_password": "*" * min(password_length, 12) if password_length > 0 else ""
            }
            
            # Include actual password for admin users (for hover tooltip)
            if session.get('is_admin') or 'admin' in session.get('roles', []):
                response_data["actual_password"] = current_password
            
            return jsonify(response_data)
            
        elif request.method == 'POST':
            # Update SCEP password
            data = request.get_json()
            new_password = data.get('password', '').strip()
            
            if not new_password:
                return jsonify({
                    "status": "error",
                    "message": "Password cannot be empty"
                }), 400
                
            if len(new_password) < 8:
                return jsonify({
                    "status": "error", 
                    "message": "Password must be at least 8 characters long"
                }), 400
                
            # Save to database for persistence
            user_id = session.get('user_id')
            if not set_system_config('scep_password', new_password, user_id, 'SCEP challenge password for device enrollment'):
                return jsonify({
                    "status": "error",
                    "message": "Failed to save password to database"
                }), 500
            
            # Update the current environment variable for immediate effect
            os.environ['SCEP_PASSWORD'] = new_password
            
            # Notify SCEP server about password change via internal URL
            try:
                scep_response = requests.post(
                    "http://scep-server:8090/reload-config",
                    json={"password": new_password},
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                if scep_response.status_code == 200:
                    logging.info("Successfully updated SCEP server password")
                else:
                    logging.warning(f"SCEP server password update returned status {scep_response.status_code}")
            except Exception as e:
                logging.warning(f"Could not notify SCEP server about password change: {e}")
            
            log_operation('scep_password_update', {'password_length': len(new_password)})
            
            return jsonify({
                "status": "success",
                "message": "SCEP password updated successfully and persisted to database",
                "password_length": len(new_password),
                "note": "Password updated and will persist across restarts"
            })
            
    except Exception as e:
        logging.error(f"Error managing SCEP password: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error managing SCEP password: {str(e)}"
        }), 500

# ================================
# OCSP and Certificate Revocation APIs
# ================================

@app.route('/api/ocsp/status/<serial_number>', methods=['GET'])
def get_certificate_status(serial_number):
    """Get certificate status for OCSP responder (public endpoint)"""
    try:
        # Convert serial number to hex format for EasyRSA index lookup
        try:
            # Handle both hex and decimal serial numbers
            if isinstance(serial_number, str) and serial_number.isdigit():
                serial_int = int(serial_number)
                serial_hex = format(serial_int, 'X')
            else:
                # Assume it's already hex
                serial_hex = serial_number.upper().replace('0X', '')
                serial_int = int(serial_hex, 16)
        except:
            return jsonify({
                'status': 'success',
                'certificate_status': 'unknown',
                'serial_number': serial_number,
                'message': 'Invalid serial number format'
            })
        
        # Get index.txt from EasyRSA container to check certificate status
        response = requests.post(
            f"{TERMINAL_CONTAINER_URL}{TERMINAL_ENDPOINT}",
            json={"operation": "get-index"},
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code != 200:
            return jsonify({
                'status': 'success',
                'certificate_status': 'unknown',
                'serial_number': serial_number,
                'message': 'Unable to retrieve certificate database'
            })
            
        result = response.json()
        if result.get('status') != 'success':
            return jsonify({
                'status': 'success', 
                'certificate_status': 'unknown',
                'serial_number': serial_number,
                'message': 'Certificate database unavailable'
            })
        
        # Parse index.txt content to find certificate
        index_content = result.get('index_content', '')
        cert_status = 'unknown'
        revocation_time = None
        revocation_reason = None
        
        for line in index_content.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Parse index.txt format: status, expiry, revocation, serial, filename, subject
            parts = line.split('\t')
            if len(parts) >= 4:
                status_flag = parts[0]
                expiry = parts[1]
                revocation_info = parts[2] if len(parts) > 2 else ''
                cert_serial = parts[3]
                
                # Compare serial numbers (handle both hex formats)
                if cert_serial.upper() == serial_hex or cert_serial.upper() == f"{serial_hex:0>2}":
                    if status_flag == 'V':
                        # Check if expired
                        from datetime import datetime
                        try:
                            expiry_date = datetime.strptime(expiry, '%y%m%d%H%M%SZ')
                            if expiry_date < datetime.now():
                                cert_status = 'expired'
                            else:
                                cert_status = 'valid'
                        except:
                            cert_status = 'valid'  # Default to valid if can't parse date
                    elif status_flag == 'R':
                        cert_status = 'revoked'
                        # Parse revocation info if available
                        if revocation_info:
                            try:
                                # Format: YYMMDDHHMMSSZ[,reason]
                                rev_parts = revocation_info.split(',')
                                rev_date_str = rev_parts[0]
                                revocation_time = datetime.strptime(rev_date_str, '%y%m%d%H%M%SZ').isoformat()
                                if len(rev_parts) > 1:
                                    revocation_reason = int(rev_parts[1])
                            except:
                                pass
                    else:
                        cert_status = 'unknown'
                    break
        
        response_data = {
            'status': 'success',
            'certificate_status': cert_status,
            'serial_number': serial_number
        }
        
        # Add revocation details if certificate is revoked
        if cert_status == 'revoked':
            if revocation_time:
                response_data['revocation_time'] = revocation_time
            if revocation_reason is not None:
                response_data['revocation_reason'] = revocation_reason
        
        return jsonify(response_data)
        
    except Exception as e:
        logging.error(f"Error checking certificate status: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

@app.route('/api/ocsp/info', methods=['GET'])
def get_ocsp_info():
    """Get OCSP responder information"""
    try:
        # Construct the external OCSP URL
        domain = os.getenv('DOMAIN', 'localhost')
        ocsp_url = f"https://ca.{domain}/ocsp"
        
        return jsonify({
            'status': 'success',
            'ocsp_url': ocsp_url,
            'protocol': 'RFC 6960 (OCSP)',
            'methods': ['GET', 'POST'],
            'content_types': {
                'request': 'application/ocsp-request',
                'response': 'application/ocsp-response'
            },
            'status_codes': {
                'good': 0,
                'revoked': 1,
                'unknown': 2
            }
        })
    except Exception as e:
        logging.error(f"Error getting OCSP info: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

@app.route('/api/ocsp/health', methods=['GET'])
def get_ocsp_health():
    """Get OCSP responder health status"""
    try:
        import requests
        import time
        
        # Test OCSP responder health
        start_time = time.time()
        try:
            # Try to reach the OCSP responder health endpoint
            health_response = requests.get(
                f"{TERMINAL_CONTAINER_URL.replace('/execute', '')}/../ocsp-responder:8091/health",
                timeout=5
            )
            response_time = round((time.time() - start_time) * 1000, 2)
            ocsp_healthy = health_response.status_code == 200
        except:
            response_time = None
            ocsp_healthy = False
        
        # Test dependencies
        ca_manager_healthy = True  # We're in the CA manager
        easyrsa_healthy = False
        try:
            easyrsa_response = requests.get(f"{TERMINAL_CONTAINER_URL.replace('/execute', '')}/health", timeout=5)
            easyrsa_healthy = easyrsa_response.status_code == 200
        except:
            pass
        
        overall_status = 'healthy' if (ocsp_healthy and easyrsa_healthy) else 'degraded'
        
        return jsonify({
            'status': overall_status,
            'timestamp': datetime.now().isoformat(),
            'response_time': response_time,
            'ca_manager_connection': 'healthy' if ca_manager_healthy else 'unhealthy',
            'easyrsa_connection': 'healthy' if easyrsa_healthy else 'unhealthy',
            'certificate_db': 'available'
        })
    except Exception as e:
        logging.error(f"Error checking OCSP health: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

@app.route('/api/certificates', methods=['GET'])
@auth_required()
def get_certificates():
    """List all certificates in the database"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("""
                SELECT c.id, c.serial_number, c.subject_dn, c.issuer_dn,
                       c.not_before, c.not_after, c.status, c.certificate_type,
                       c.issued_by, c.created_at,
                       r.revocation_time, r.revocation_reason_text
                FROM certificates c
                LEFT JOIN certificate_revocations r ON c.serial_number = r.serial_number
                ORDER BY c.created_at DESC
            """)
            
            certificates = cursor.fetchall()
            
            return jsonify({
                'status': 'success',
                'certificates': [dict(cert) for cert in certificates],
                'count': len(certificates)
            })
        
    except Exception as e:
        logging.error(f"Error listing certificates: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/certificates', methods=['POST'])
@auth_required()
def add_certificate():
    """Add a certificate to the database"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        required_fields = ['serial_number', 'subject_dn', 'issuer_dn', 'not_before', 'not_after', 'certificate_pem']
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'message': f'Missing required field: {field}'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO certificates (
                    serial_number, subject_dn, issuer_dn, not_before, not_after,
                    certificate_pem, key_usage, extended_key_usage, sans,
                    certificate_type, issued_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                data['serial_number'],
                data['subject_dn'],
                data['issuer_dn'],
                data['not_before'],
                data['not_after'],
                data['certificate_pem'],
                data.get('key_usage', []),
                data.get('extended_key_usage', []),
                data.get('sans', []),
                data.get('certificate_type', 'client'),
                session.get('username', 'system')
            ))
            
            cert_id = cursor.fetchone()[0]
            conn.commit()
            
            log_operation('certificate_added', {
                'certificate_id': cert_id,
                'serial_number': data['serial_number'],
                'subject': data['subject_dn']
            })
            
            return jsonify({
                'status': 'success',
                'message': 'Certificate added successfully',
                'certificate_id': cert_id
            })
        
    except psycopg2.IntegrityError as e:
        return jsonify({'status': 'error', 'message': 'Certificate with this serial number already exists'}), 409
    except Exception as e:
        logging.error(f"Error adding certificate: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/certificates/<serial_number>/revoke', methods=['POST'])
@auth_required()
def revoke_certificate_by_serial(serial_number):
    """Revoke a certificate"""
    try:
        data = request.get_json() or {}
        revocation_reason = data.get('reason', 0)  # Default: unspecified
        revocation_reason_text = data.get('reason_text', 'Unspecified')
        additional_info = data.get('additional_info', {})
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            # Check if certificate exists
            cursor.execute("SELECT id, status FROM certificates WHERE serial_number = %s", (serial_number,))
            cert = cursor.fetchone()
            
            if not cert:
                return jsonify({'status': 'error', 'message': 'Certificate not found'}), 404
            
            if cert['status'] == 'revoked':
                return jsonify({'status': 'error', 'message': 'Certificate is already revoked'}), 400
            
            # Check if already revoked
            cursor.execute("SELECT id FROM certificate_revocations WHERE serial_number = %s", (serial_number,))
            if cursor.fetchone():
                return jsonify({'status': 'error', 'message': 'Certificate is already revoked'}), 400
            
            # Add revocation record
            cursor.execute("""
                INSERT INTO certificate_revocations (
                    certificate_id, serial_number, revocation_reason, 
                    revocation_reason_text, revoked_by, revoked_by_user_id,
                    additional_info
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                cert['id'], serial_number, revocation_reason,
                revocation_reason_text, session.get('username', 'system'),
                session.get('user_id'), additional_info
            ))
            
            revocation_id = cursor.fetchone()[0]
            conn.commit()
            
            log_operation('certificate_revoked', {
                'certificate_id': cert['id'],
                'serial_number': serial_number,
                'revocation_reason': revocation_reason_text,
                'revocation_id': revocation_id
            })
            
            return jsonify({
                'status': 'success',
                'message': 'Certificate revoked successfully',
                'revocation_id': revocation_id
            })
        
    except Exception as e:
        logging.error(f"Error revoking certificate: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/ocsp/config', methods=['GET', 'POST'])
@auth_required()
def manage_ocsp_config():
    """Get or update OCSP configuration"""
    if not check_permission('ocsp_config'):
        return jsonify({'status': 'error', 'message': 'Insufficient permissions'}), 403
    
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        if request.method == 'GET':
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM ocsp_config ORDER BY parameter_name")
                config = cursor.fetchall()
                
                return jsonify({
                    'status': 'success',
                    'config': [dict(item) for item in config]
                })
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
            with conn.cursor() as cursor:
                for param_name, param_value in data.items():
                    cursor.execute("""
                        INSERT INTO ocsp_config (parameter_name, parameter_value, updated_by)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (parameter_name) 
                        DO UPDATE SET 
                            parameter_value = EXCLUDED.parameter_value,
                            updated_at = CURRENT_TIMESTAMP,
                            updated_by = EXCLUDED.updated_by
                    """, (param_name, param_value, session.get('username', 'system')))
                
                conn.commit()
                
                log_operation('ocsp_config_updated', {
                    'updated_parameters': list(data.keys())
                })
                
                return jsonify({
                    'status': 'success',
                    'message': 'OCSP configuration updated successfully'
                })
        
    except Exception as e:
        logging.error(f"Error managing OCSP config: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/ocsp/requests', methods=['GET'])
@auth_required()
def get_ocsp_requests():
    """Get OCSP request logs"""
    if not check_permission('ocsp_read'):
        return jsonify({'status': 'error', 'message': 'Insufficient permissions'}), 403
    
    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 100)), 1000)  # Max 1000 records
        offset = max(int(request.args.get('offset', 0)), 0)
        serial_filter = request.args.get('serial')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            query = """
                SELECT * FROM ocsp_requests
                WHERE ($1::text IS NULL OR serial_number ILIKE $1)
                ORDER BY request_time DESC
                LIMIT $2 OFFSET $3
            """
            
            serial_pattern = f"%{serial_filter}%" if serial_filter else None
            cursor.execute(query, (serial_pattern, limit, offset))
            
            requests_data = cursor.fetchall()
            
            # Get total count
            count_query = """
                SELECT COUNT(*) FROM ocsp_requests
                WHERE ($1::text IS NULL OR serial_number ILIKE $1)
            """
            cursor.execute(count_query, (serial_pattern,))
            total_count = cursor.fetchone()[0]
            
            return jsonify({
                'status': 'success',
                'requests': [dict(req) for req in requests_data],
                'total_count': total_count,
                'limit': limit,
                'offset': offset
            })
        
    except Exception as e:
        logging.error(f"Error getting OCSP requests: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/health/detailed')
@auth_required()
def detailed_health():
    """Detailed health check"""
    try:
        easyrsa_health = requests.get(f"{TERMINAL_CONTAINER_URL}/health", timeout=5)
        pki_status = make_easyrsa_request('status')
        
        health_data = {
            "timestamp": datetime.now().isoformat(),
            "easyrsa_container": "healthy" if easyrsa_health.status_code == 200 else "unhealthy",
            "pki_status": pki_status.get('pki_status', {}),
            "system_info": {
                "python_version": "3.11",
                "flask_version": "3.0.0"
            }
        }
        
        return jsonify(health_data)
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

# Legacy endpoints for backward compatibility
@app.route('/run-program', methods=['POST'])
@auth_required()
def run_program():
    """Run EasyRSA operation asynchronously (fire and forget) - Legacy endpoint"""
    try:
        data = request.get_json() or {}
        log_operation('legacy_run_program', data)
        
        def run_in_background():
            try:
                requests.post(
                    f"{TERMINAL_CONTAINER_URL}{TERMINAL_ENDPOINT}",
                    json=data,
                    timeout=REQUEST_TIMEOUT
                )
            except Exception as e:
                logging.error(f"Background execution error: {e}")
        
        thread = threading.Thread(target=run_in_background)
        thread.daemon = True
        thread.start()
        
        return jsonify({"status": "success", "message": "EasyRSA operation started successfully"})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/run-program-sync', methods=['POST'])
@auth_required()
def run_program_sync():
    """Run EasyRSA operation synchronously - Legacy endpoint"""
    try:
        data = request.get_json() or {}
        operation = data.get('operation', '')
        params = data.get('params', {})
        
        log_operation('legacy_run_program_sync', {'operation': operation})
        
        if not operation:
            return jsonify({
                "status": "error",
                "message": "No operation specified"
            }), 400
        
        result = make_easyrsa_request(operation, params)
        
        # Handle special cases for different operations
        if operation == 'list-certs' and 'certificates' in result:
            return jsonify({
                "status": "success",
                "certificates": result.get("certificates", []),
                "count": result.get("count", 0),
                "message": result.get("message", "Certificates retrieved successfully")
            })
        elif operation == 'status' and 'pki_status' in result:
            return jsonify({
                "status": "success",
                "pki_status": result.get("pki_status", {}),
                "message": result.get("message", "PKI status retrieved successfully")
            })
        else:
            return jsonify({
                "status": "success",
                "return_code": result.get("return_code", 0),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "message": result.get("message", "Operation completed successfully")
            })
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/status')
def status():
    """Check if EasyRSA container is reachable"""
    try:
        response = requests.get(f"{TERMINAL_CONTAINER_URL}/health", timeout=5)
        if response.status_code == 200:
            return jsonify({"status": "connected", "easyrsa_container": "reachable"})
        else:
            return jsonify({"status": "error", "easyrsa_container": "unreachable"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "easyrsa_container": "unreachable"}), 500

@app.route('/api/operations')
@auth_required()
def list_operations():
    """List available EasyRSA operations"""
    operations = [
        {
            "name": "init-pki",
            "description": "Initialize Public Key Infrastructure",
            "endpoint": "/api/pki/init",
            "method": "POST",
            "parameters": []
        },
        {
            "name": "build-ca",
            "description": "Build Certificate Authority",
            "endpoint": "/api/ca/build",
            "method": "POST",
            "parameters": ["ca_config (object with CA details)"]
        },
        {
            "name": "download-ca",
            "description": "Download Certificate Authority",
            "endpoint": "/api/ca/download",
            "method": "GET",
            "parameters": []
        },
        {
            "name": "create-full-cert",
            "description": "Create full certificate (generate + sign)",
            "endpoint": "/api/certificates/create-full",
            "method": "POST",
            "parameters": ["name (required)", "type (client/server)"]
        },
        {
            "name": "download-certificate",
            "description": "Download certificate bundle",
            "endpoint": "/api/certificates/download/<name>",
            "method": "GET",
            "parameters": ["name (in URL)", "format (zip/pem/p12)", "include_key (boolean)"]
        },
        {
            "name": "validate-certificate",
            "description": "Validate certificate status and expiry",
            "endpoint": "/api/certificates/validate/<name>",
            "method": "GET",
            "parameters": ["name (in URL path)"]
        },
        {
            "name": "expiring-certificates",
            "description": "Get certificates expiring soon",
            "endpoint": "/api/certificates/expiring",
            "method": "GET",
            "parameters": ["days (query parameter)"]
        },
        {
            "name": "expiry-dashboard",
            "description": "Get comprehensive certificate expiry dashboard with statistics",
            "endpoint": "/api/certificates/expiry-dashboard",
            "method": "GET",
            "parameters": []
        }
    ]
    
    return jsonify({"operations": operations})

# Duplicate endpoints removed - using the ones below with proper function names

# User management endpoints removed - not fully implemented


@app.route('/api/profile', methods=['GET'])
@auth_required()
def get_profile():
    """Get current user's profile"""
    if not MULTI_USER_MODE:
        return jsonify({'status': 'error', 'message': 'Multi-user mode not enabled'}), 400
    
    try:
        user_id = session.get('user_id')
        user = get_user_by_id(user_id)
        if user:
            # Convert roles array to list if needed
            if user.get('roles') and user['roles'][0] is None:
                user['roles'] = []
            return jsonify({'status': 'success', 'user': user})
        else:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
    except Exception as e:
        logging.error(f"Failed to get profile: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/profile/change-password', methods=['POST'])
@auth_required()
def change_password():
    """Change current user's password"""
    if not MULTI_USER_MODE:
        return jsonify({'status': 'error', 'message': 'Multi-user mode not enabled'}), 400
    
    try:
        data = request.get_json() or {}
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        # Validate required fields
        if not all([current_password, new_password, confirm_password]):
            return jsonify({'status': 'error', 'message': 'All password fields are required'}), 400
        
        # Validate new password confirmation
        if new_password != confirm_password:
            return jsonify({'status': 'error', 'message': 'New password and confirmation do not match'}), 400
        
        # Validate password strength
        if len(new_password) < 6:
            return jsonify({'status': 'error', 'message': 'New password must be at least 6 characters long'}), 400
        
        user_id = session.get('user_id')
        username = session.get('username')
        
        # Verify current password by attempting authentication
        auth_user = authenticate_user(username, current_password)
        if not auth_user:
            return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400
        
        # Update password in database
        try:
            conn = get_db_connection()
            if not conn:
                return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
            
            password_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET password_hash = %s WHERE id = %s",
                    (password_hash, user_id)
                )
                conn.commit()
            conn.close()
            
            log_operation('password_changed', {'user_id': user_id, 'username': username})
            return jsonify({'status': 'success', 'message': 'Password changed successfully'})
        except Exception as e:
            logging.error(f"Failed to update password: {e}")
            return jsonify({'status': 'error', 'message': 'Failed to update password'}), 500
            
    except Exception as e:
        logging.error(f"Failed to change password: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# User Management Endpoints simplified - full user management not implemented yet
@app.route('/api/users', methods=['GET'])
@auth_required()
def list_all_users():
    """List basic user info"""
    if not MULTI_USER_MODE:
        return jsonify({'status': 'error', 'message': 'Multi-user mode not enabled'}), 400
    
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, email, full_name, is_admin, is_active, created_at
                FROM users 
                WHERE is_active = true
                ORDER BY username
            """)
            users = cursor.fetchall()
        
        conn.close()
        return jsonify({'status': 'success', 'users': [dict(user) for user in users]})
    except Exception as e:
        logging.error(f"Failed to list users: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@auth_required()
def delete_user_by_id(user_id):
    """Delete (deactivate) a user"""
    if not MULTI_USER_MODE:
        return jsonify({'status': 'error', 'message': 'Multi-user mode not enabled'}), 400
    
    try:
        # Prevent self-deletion
        current_user_id = session.get('user_id')
        if user_id == current_user_id:
            return jsonify({'status': 'error', 'message': 'Cannot delete your own account'}), 400
        
        # Check if user exists
        existing_user = get_user_by_id(user_id)
        if not existing_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Deactivate user instead of hard delete
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET is_active = false WHERE id = %s",
                (user_id,)
            )
            conn.commit()
        
        conn.close()
        
        log_operation('user_deactivated', {
            'deactivated_user_id': user_id, 
            'username': existing_user.get('username')
        })
        
        return jsonify({'status': 'success', 'message': 'User deactivated successfully'})
        
    except Exception as e:
        logging.error(f"Failed to delete user: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/users', methods=['POST'])
@auth_required()
def create_user():
    """Create a new user"""
    if not MULTI_USER_MODE:
        return jsonify({'status': 'error', 'message': 'Multi-user mode not enabled'}), 400
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Extract and validate required fields
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        role = data.get('role', '').strip()
        
        # Validation
        if not username or len(username) < 3:
            return jsonify({'status': 'error', 'message': 'Username must be at least 3 characters long'}), 400
        
        if not all(c.isalnum() or c == '_' for c in username):
            return jsonify({'status': 'error', 'message': 'Username can only contain letters, numbers, and underscores'}), 400
        
        if not email or '@' not in email:
            return jsonify({'status': 'error', 'message': 'Valid email address is required'}), 400
        
        if not password or len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters long'}), 400
        
        if not full_name:
            return jsonify({'status': 'error', 'message': 'Full name is required'}), 400
        
        if role not in ['admin', 'operator', 'viewer']:
            return jsonify({'status': 'error', 'message': 'Role must be admin, operator, or viewer'}), 400
        
        # Hash password
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        # Check for existing users
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        with conn.cursor() as cursor:
            # Check if username exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                conn.close()
                return jsonify({'status': 'error', 'message': 'Username already exists'}), 409
            
            # Check if email exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                conn.close()
                return jsonify({'status': 'error', 'message': 'Email already exists'}), 409
            
            # Create user
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, full_name, is_admin, is_active)
                VALUES (%s, %s, %s, %s, %s, true)
                RETURNING id
            """, (username, email, password_hash, full_name, role == 'admin'))
            
            user_id = cursor.fetchone()['id']
            
            # Get or create role
            cursor.execute("SELECT id FROM roles WHERE name = %s", (role,))
            role_record = cursor.fetchone()
            
            if not role_record:
                # Create role if it doesn't exist
                cursor.execute("""
                    INSERT INTO roles (name, description)
                    VALUES (%s, %s)
                    RETURNING id
                """, (role, f'{role.capitalize()} role'))
                role_id = cursor.fetchone()['id']
            else:
                role_id = role_record['id']
            
            # Assign role to user
            cursor.execute("""
                INSERT INTO user_roles (user_id, role_id)
                VALUES (%s, %s)
            """, (user_id, role_id))
            
            conn.commit()
        
        conn.close()
        
        log_operation('user_created', {
            'new_user_id': user_id,
            'username': username,
            'role': role,
            'created_by': session.get('username')
        })
        
        return jsonify({
            'status': 'success', 
            'message': f'User {username} created successfully',
            'user_id': user_id
        })
        
    except Exception as e:
        logging.error(f"Failed to create user: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ================================
# Certificate Request Portal APIs
# ================================

@app.route('/certificate-request')
def certificate_request_portal():
    """Certificate request portal page"""
    return render_template('certificate_request.html')

@app.route('/test-js')
def test_js():
    """Test JavaScript functionality"""
    return render_template('test-js.html')

@app.route('/simple-test')
def simple_test():
    """Simple JavaScript test"""
    return render_template('simple-test.html')

@app.route('/diagnostic')
def diagnostic():
    """JavaScript diagnostic test"""
    return render_template('diagnostic.html')

@app.route('/test-minimal')
def test_minimal():
    """Minimal JavaScript test"""
    # Get user from session if authenticated
    user = None
    if 'user_id' in session:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, roles, is_admin FROM users WHERE id = %s", (session['user_id'],))
            user_data = cursor.fetchone()
            if user_data:
                user = {
                    'id': user_data['id'],
                    'username': user_data['username'],
                    'roles': user_data['roles'] or [],
                    'is_admin': user_data['is_admin']
                }
            cursor.close()
            conn.close()
    return render_template('test-minimal.html', user=user)

# ================================
# Email Verification Functions
# ================================

def send_verification_email(email, verification_code, verification_url):
    """Send verification email with code using database SMTP configuration"""
    try:
        # Get SMTP configuration from database
        conn = get_db_connection()
        if not conn:
            logging.error("Database connection failed while getting SMTP config")
            return False
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT smtp_server, smtp_port, smtp_username, smtp_password, 
                   sender_email, sender_name, use_tls
            FROM smtp_config ORDER BY id DESC LIMIT 1
        """)
        
        config_row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not config_row:
            # Fallback to environment variables if database config not found
            logging.warning("No SMTP configuration found in database, using environment variables")
            smtp_server, smtp_port, smtp_username, smtp_password = SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD
            sender_email, sender_name, use_tls = SMTP_FROM_EMAIL, "CA Manager", SMTP_USE_TLS
        else:
            # Access as dictionary since config_row is a RealDictRow
            smtp_server = config_row['smtp_server']
            smtp_port = config_row['smtp_port']
            smtp_username = config_row['smtp_username']
            smtp_password = config_row['smtp_password']
            sender_email = config_row['sender_email']
            sender_name = config_row['sender_name']
            use_tls = config_row['use_tls']
        
        # Validate required SMTP settings
        if not smtp_server or not sender_email:
            logging.error("SMTP server or sender email not configured")
            return False
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '802.1X Certificate Request - Email Verification'
        msg['From'] = f"{sender_name} <{sender_email}>" if sender_name else sender_email
        msg['To'] = email
        
        # Create the HTML content
        html = f"""
        <html>
        <head></head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #5B059C;">802.1X Certificate Request Verification</h2>
            <p>You have requested an 802.1X certificate for this email address.</p>
            
            <div style="background: #f4f4f4; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p><strong>Your verification code is:</strong></p>
                <h1 style="color: #5B059C; letter-spacing: 5px; text-align: center;">{verification_code}</h1>
            </div>
            
            <p>Or click the link below to verify your email:</p>
            <p><a href="{verification_url}" style="background: #5B059C; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email Address</a></p>
            
            <p style="color: #666; font-size: 12px; margin-top: 30px;">
                This verification code expires in 15 minutes. If you did not request this certificate, please ignore this email.
            </p>
        </body>
        </html>
        """
        
        # Create plain text version
        text = f"""
802.1X Certificate Request Verification

You have requested an 802.1X certificate for this email address.

Your verification code is: {verification_code}

Or visit this URL to verify your email:
{verification_url}

This verification code expires in 15 minutes. If you did not request this certificate, please ignore this email.
        """
        
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email using database configuration
        server = smtplib.SMTP(smtp_server, smtp_port)
        
        if use_tls:
            server.starttls()
        
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
        
        server.send_message(msg)
        server.quit()
        
        logging.info(f"Verification email sent successfully to {email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send verification email: {e}")
        return False

def verify_email_domain(email):
    """Check if email domain is in the allowed list"""
    try:
        domain = email.split('@')[1].lower()
        
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        # Check if domain or parent domain is allowed
        cursor.execute("""
            SELECT COUNT(*) as count FROM allowed_email_domains 
            WHERE enabled = true 
            AND (
                domain = %s 
                OR (allow_subdomains = true AND %s LIKE '%%.' || domain)
            )
        """, (domain, domain))
        
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return result['count'] > 0
    except Exception as e:
        logging.error(f"Error verifying email domain: {e}")
        return False

@app.route('/api/certificate-templates', methods=['GET'])
def get_certificate_templates():
    """Get available certificate templates"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT template_name, display_name, description, certificate_type, 
                       default_validity_days, max_validity_days, requires_approval
                FROM certificate_templates 
                WHERE is_active = true
                ORDER BY display_name
            """)
            templates = cursor.fetchall()
        
        conn.close()
        return jsonify(templates)
        
    except Exception as e:
        logging.error(f"Failed to get certificate templates: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/certificate-requests/start-verification', methods=['POST'])
def start_certificate_request_verification():
    """Start email verification for certificate request"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['requester_name', 'requester_email', 'common_name', 'certificate_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate email format
        email = data['requester_email'].lower().strip()
        if not '@' in email:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if email domain is allowed
        if not verify_email_domain(email):
            domain = email.split('@')[1]
            return jsonify({
                'error': f'Email domain "{domain}" is not authorized for certificate requests',
                'contact_admin': True
            }), 403
        
        # Generate verification code and token
        verification_code = f"{secrets.randbelow(1000000):06d}"
        verification_token = secrets.token_urlsafe(32)
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        # Store verification request
        cursor = conn.cursor()
        
        # Delete any existing pending verifications for this email
        cursor.execute("""
            DELETE FROM email_verifications 
            WHERE email = %s AND verified_at IS NULL
        """, (email,))
        
        # Create new verification
        cursor.execute("""
            INSERT INTO email_verifications (
                email, verification_code, token, request_data, 
                expires_at, ip_address, user_agent
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            email,
            verification_code,
            verification_token,
            json.dumps(data),
            datetime.now() + timedelta(minutes=15),
            request.remote_addr,
            request.headers.get('User-Agent', '')
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Send verification email
        domain = os.getenv('DOMAIN', 'ca.bonner.com')
        verification_url = f"https://{domain}/verify-email?token={verification_token}"
        
        if send_verification_email(email, verification_code, verification_url):
            return jsonify({
                'status': 'verification_sent',
                'message': f'Verification email sent to {email}',
                'verification_token': verification_token,
                'expires_minutes': 15
            })
        else:
            return jsonify({'error': 'Failed to send verification email'}), 500
            
    except Exception as e:
        logging.error(f"Error starting verification: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/certificate-requests', methods=['GET', 'POST'])
def handle_certificate_requests():
    """Handle certificate requests - GET to list, POST to create"""
    if request.method == 'GET':
        return list_certificate_requests()
    else:
        return create_certificate_request()

def list_certificate_requests():
    """List certificate requests with optional status filter"""
    try:
        status_filter = request.args.get('status')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Build query based on filter
        if status_filter:
            cursor.execute("""
                SELECT request_id, requester_name, requester_email, common_name, 
                       certificate_type, status, created_at, certificate_template,
                       department, key_algorithm, key_size, validity_days,
                       san_dns_names, san_emails, email_verified
                FROM certificate_requests 
                WHERE status = %s 
                ORDER BY created_at DESC
            """, (status_filter,))
        else:
            cursor.execute("""
                SELECT request_id, requester_name, requester_email, common_name, 
                       certificate_type, status, created_at, certificate_template,
                       department, key_algorithm, key_size, validity_days,
                       san_dns_names, san_emails, email_verified
                FROM certificate_requests 
                ORDER BY created_at DESC
            """)
        
        requests_data = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Convert to list of dictionaries
        requests_list = [dict(req) for req in requests_data]
        
        return jsonify(requests_list)
        
    except Exception as e:
        logging.error(f"Error listing certificate requests: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def create_certificate_request():
    """Create a new certificate request (requires email verification)"""
    try:
        data = request.json
        
        # Check if this is a verified request
        verification_token = data.get('verification_token')
        verification_code = data.get('verification_code')
        
        if not verification_token:
            return jsonify({'error': 'Email verification required. Please use /start-verification endpoint first.'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        # Verify the token and code
        cursor = conn.cursor()
        
        # Check verification
        cursor.execute("""
            SELECT * FROM email_verifications 
            WHERE token = %s AND expires_at > CURRENT_TIMESTAMP
        """, (verification_token,))
        
        verification = cursor.fetchone()
        
        if not verification:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid or expired verification token'}), 400
        
        # If code is provided, verify it matches
        if verification_code and verification['verification_code'] != verification_code:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid verification code'}), 400
        
        # Mark as verified
        cursor.execute("""
            UPDATE email_verifications 
            SET verified_at = CURRENT_TIMESTAMP 
            WHERE token = %s
        """, (verification_token,))
        
        # Get original request data
        request_data_raw = verification['request_data']
        if isinstance(request_data_raw, str):
            original_data = json.loads(request_data_raw)
        else:
            # Already parsed as dict
            original_data = request_data_raw
        
        # Use the original verified email
        data['requester_email'] = verification['email']
        
        # Validate required fields
        required_fields = ['requester_name', 'requester_email', 'common_name', 'certificate_type']
        for field in required_fields:
            if not data.get(field):
                cursor.close()
                conn.close()
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Generate request ID
        request_id = str(uuid.uuid4())
        
        # Check if template exists and get details
        template = None
        if data.get('certificate_template'):
            cursor.execute("""
                SELECT * FROM certificate_templates 
                WHERE template_name = %s AND is_active = true
            """, (data['certificate_template'],))
            template = cursor.fetchone()
        
        # Insert certificate request with verification flag
        cursor.execute("""
            INSERT INTO certificate_requests (
                request_id, requester_name, requester_email, department,
                common_name, san_dns_names, san_ip_addresses, san_emails,
                certificate_type, key_algorithm, key_size, validity_days,
                certificate_template, approval_required, status,
                request_metadata, email_verified, verification_token,
                verification_completed_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            request_id,
            data['requester_name'],
            data['requester_email'],
            data.get('department'),
            data['common_name'],
            data.get('san_dns_names', []),
            data.get('san_ip_addresses', []),
            data.get('san_emails', []),
            data['certificate_type'],
            data.get('key_algorithm', 'RSA'),
            data.get('key_size', 2048),
            data.get('validity_days', 365),
            data.get('certificate_template'),
            template['requires_approval'] if template else True,
            'pending',
            json.dumps({'notes': data.get('notes', ''), 'created_via': 'web_portal_verified'}),
            True,  # email_verified
            verification_token,
            datetime.now()
        ))
        
        result = cursor.fetchone()
        request_db_id = result['id'] if isinstance(result, dict) else result[0]
        conn.commit()
        cursor.close()
        conn.close()
        
        # If auto-approval is enabled, process immediately
        auto_approve = template and not template['requires_approval']
        if auto_approve:
            # Trigger certificate issuance
            update_request_status(request_db_id, 'approved', 'system', 'Auto-approved based on template settings')
            # Generate the actual certificate
            cert_generated = generate_certificate_for_request(request_db_id, request_id, data)
        
        log_operation('certificate_request_created', {
            'request_id': request_id,
            'common_name': data['common_name'],
            'requester': data['requester_email'],
            'email_verified': True
        })
        
        return jsonify({
            'status': 'success',
            'request_id': request_id,
            'message': 'Certificate request created successfully with verified email',
            'approval_required': template['requires_approval'] if template else True,
            'auto_approved': auto_approve
        })
            
    except Exception as e:
        logging.error(f"Error creating certificate request: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/certificate-requests/<request_id>/approve', methods=['POST'])
def approve_certificate_request(request_id):
    """Approve a certificate request"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Get the request details
        cursor.execute("""
            SELECT id, status FROM certificate_requests 
            WHERE request_id = %s
        """, (request_id,))
        
        request_row = cursor.fetchone()
        if not request_row:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Certificate request not found'}), 404
        
        request_db_id = request_row['id']
        current_status = request_row['status']
        
        if current_status != 'pending':
            cursor.close()
            conn.close()
            return jsonify({'error': f'Cannot approve request with status: {current_status}'}), 400
        
        # Update status to approved
        update_request_status(request_db_id, 'approved', session.get('username', 'admin'), 'Approved via web interface')
        
        # Get requester email before closing cursor
        cursor.execute("SELECT requester_email, requester_name, common_name FROM certificate_requests WHERE id = %s", (request_db_id,))
        requester_info = cursor.fetchone()
        requester_email = requester_info['requester_email'] if requester_info else None
        requester_name = requester_info['requester_name'] if requester_info else None
        common_name = requester_info['common_name'] if requester_info else None
        
        cursor.close()
        conn.close()
        
        # Trigger certificate generation
        cert_generated = generate_certificate_for_request(request_db_id, request_id, None)
        
        # Send certificate via email if generation was successful and we have email
        if cert_generated and requester_email:
            try:
                logging.info(f"Attempting to email certificate for request {request_id} to {requester_email} (CN: {common_name})")
                # Get the certificate data that was just generated
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT certificate_pem, private_key_pem 
                        FROM certificate_requests 
                        WHERE id = %s AND status = 'issued'
                    """, (request_db_id,))
                    cert_row = cursor.fetchone()
                    cursor.close()
                    conn.close()
                    
                    if cert_row and cert_row['certificate_pem'] and cert_row['private_key_pem']:
                        # Get CA certificate from the earlier EasyRSA get-cert-files call
                        ca_result = make_easyrsa_request("get-cert-files", {"name": common_name, "include_key": False})
                        ca_cert_pem = ca_result.get("ca_certificate", "") if ca_result.get("status") == "success" else ""
                        
                        email_sent = send_certificate_email_with_data(
                            request_id, requester_email, requester_name, common_name,
                            cert_row['certificate_pem'], cert_row['private_key_pem'], ca_cert_pem
                        )
                        if email_sent:
                            logging.info(f"Certificate for request {request_id} sent to {requester_email}")
                        else:
                            logging.error(f"Failed to send certificate email for {request_id}")
                    else:
                        logging.error(f"Certificate data not found in database for {request_id}")
                else:
                    logging.error(f"Database connection failed when trying to email certificate for {request_id}")
            except Exception as e:
                logging.error(f"Exception while sending certificate email for {request_id}: {e}")
                # Don't fail the approval if email fails
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate request approved and generated successfully',
            'request_id': request_id,
            'certificate_sent': cert_generated and requester_email is not None
        })
        
    except Exception as e:
        logging.error(f"Error approving certificate request: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/certificate-requests/<request_id>/reject', methods=['POST'])
def reject_certificate_request(request_id):
    """Reject a certificate request"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'No reason provided')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Get the request details
        cursor.execute("""
            SELECT id, status FROM certificate_requests 
            WHERE request_id = %s
        """, (request_id,))
        
        request_row = cursor.fetchone()
        if not request_row:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Certificate request not found'}), 404
        
        request_db_id = request_row['id']
        current_status = request_row['status']
        
        if current_status not in ['pending', 'approved']:
            cursor.close()
            conn.close()
            return jsonify({'error': f'Cannot reject request with status: {current_status}'}), 400
        
        # Delete the rejected request entirely
        cursor.execute("DELETE FROM certificate_requests WHERE id = %s", (request_db_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        logging.info(f"Certificate request {request_id} deleted (rejected) by {session.get('username', 'admin')}: {reason}")
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate request rejected and deleted successfully',
            'request_id': request_id,
            'reason': reason
        })
        
    except Exception as e:
        logging.error(f"Error rejecting certificate request: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def update_request_status(request_db_id, status, updated_by, notes=None):
    """Update certificate request status"""
    try:
        conn = get_db_connection()
        if not conn:
            logging.error("Database connection failed")
            return False
            
        cursor = conn.cursor()
        
        # Update the request status
        cursor.execute("""
            UPDATE certificate_requests 
            SET status = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (status, request_db_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logging.info(f"Request {request_db_id} status updated to {status} by {updated_by}")
        return True
        
    except Exception as e:
        logging.error(f"Error updating request status: {e}")
        return False

def send_certificate_email_with_data(request_id, recipient_email, recipient_name, common_name, cert_pem, key_pem, ca_cert_pem=""):
    """Send certificate in P12 format via email using provided certificate data"""
    try:
        if not cert_pem or not key_pem:
            logging.error(f"Certificate or private key data missing for {common_name}")
            return False
        
        logging.info(f"Using provided certificate data for {common_name}: cert={len(cert_pem)} chars, key={len(key_pem)} chars")
        
        # Create P12 data directly using the certificate generation helper
        from cryptography.hazmat.primitives import serialization
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import base64
        
        # Parse the certificate and private key
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        private_key_obj = serialization.load_pem_private_key(key_pem.encode(), password=None, backend=default_backend())
        
        # Use provided CA certificate
        if not ca_cert_pem:
            logging.error("CA certificate not provided")
            return False
        
        logging.info(f"Using provided CA certificate: {len(ca_cert_pem)} chars")
        ca_cert_obj = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
        
        # Create P12 with password protection - use full email as friendly name
        # Convert to bytes properly without length prefixes
        friendly_name_bytes = bytes(common_name, 'utf-8')
        logging.info(f"P12 friendly name bytes: {friendly_name_bytes} (length: {len(friendly_name_bytes)})")
        
        # Use a simple default password for P12 protection
        p12_password = "certificate"
        p12_data = serialization.pkcs12.serialize_key_and_certificates(
            name=friendly_name_bytes,
            key=private_key_obj,
            cert=cert_obj,
            cas=[ca_cert_obj],
            encryption_algorithm=serialization.BestAvailableEncryption(p12_password.encode())
        )
        
        # Get SMTP configuration
        conn = get_db_connection()
        if not conn:
            logging.error("Database connection failed while getting SMTP config for certificate email")
            return False
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT smtp_server, smtp_port, smtp_username, smtp_password, 
                   sender_email, sender_name, use_tls
            FROM smtp_config ORDER BY id DESC LIMIT 1
        """)
        
        config_row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not config_row:
            logging.error("No SMTP configuration found for sending certificate")
            return False
        
        # Access as dictionary since config_row is a RealDictRow
        smtp_server = config_row['smtp_server']
        smtp_port = config_row['smtp_port']
        smtp_username = config_row['smtp_username']
        smtp_password = config_row['smtp_password']
        sender_email = config_row['sender_email']
        sender_name = config_row['sender_name']
        use_tls = config_row['use_tls']
        
        # Create email message
        msg = MIMEMultipart()
        msg['Subject'] = f'Your 802.1X Certificate - {common_name}'
        msg['From'] = f"{sender_name} <{sender_email}>" if sender_name else sender_email
        msg['To'] = recipient_email
        
        # Create email body
        body = f"""
Hello {recipient_name or 'User'},

Your 802.1X certificate has been approved and is ready for use!

Certificate Details:
- Common Name: {common_name}
- Request ID: {request_id}
- Format: PKCS#12 (.p12)
- Password: certificate

Installation Instructions:
1. Download the attached certificate file ({common_name}.p12)
2. Double-click the file to install it on Windows/macOS
3. When prompted for a password, enter: certificate
4. For mobile devices, email the file to yourself and open on the device
5. The certificate will be used for 802.1X wireless network authentication

IMPORTANT: The P12 file is protected with the password "certificate" (without quotes).

If you need assistance with installation, please contact your IT administrator.

Best regards,
PKI Certificate Authority
"""
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach P12 certificate
        attachment = MIMEApplication(p12_data, _subtype='x-pkcs12')
        attachment.add_header('Content-Disposition', 'attachment', filename=f'{common_name}.p12')
        msg.attach(attachment)
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        if use_tls:
            server.starttls()
        
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
        
        server.send_message(msg)
        server.quit()
        
        logging.info(f"Certificate email sent successfully to {recipient_email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send certificate email: {e}")
        return False

@app.route('/api/verify-email', methods=['POST'])
def verify_email_code():
    """Verify email with code"""
    try:
        data = request.json
        token = data.get('token')
        code = data.get('code')
        
        if not token or not code:
            return jsonify({'error': 'Token and code are required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Check verification
        cursor.execute("""
            SELECT * FROM email_verifications 
            WHERE token = %s AND verification_code = %s 
            AND expires_at > CURRENT_TIMESTAMP
        """, (token, code))
        
        verification = cursor.fetchone()
        
        if not verification:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid or expired verification code'}), 400
        
        # Mark as verified
        cursor.execute("""
            UPDATE email_verifications 
            SET verified_at = CURRENT_TIMESTAMP 
            WHERE token = %s
        """, (token,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'verified',
            'message': 'Email verified successfully',
            'email': verification['email']
        })
        
    except Exception as e:
        logging.error(f"Error verifying email: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/verify-email')
def verify_email_page():
    """Email verification page (URL from email)"""
    token = request.args.get('token')
    if not token:
        return "Invalid verification link", 400
    
    return render_template('email_verification.html', token=token)

# ================================
# Email Domain Management APIs
# ================================

@app.route('/api/email-domains', methods=['GET'])
def list_email_domains():
    """List allowed email domains"""
    logging.info("Email domains endpoint called")
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT domain, description, allow_subdomains, enabled, created_at, created_by
            FROM allowed_email_domains 
            ORDER BY domain
        """)
        
        domains = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'domains': [dict(domain) for domain in domains]
        })
        
    except Exception as e:
        logging.error(f"Error listing email domains: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/email-domains', methods=['POST'])
def add_email_domain():
    """Add allowed email domain"""
    try:
        data = request.json
        domain = data.get('domain', '').lower().strip()
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return jsonify({'error': 'Invalid domain format'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO allowed_email_domains (
                    domain, description, allow_subdomains, enabled, created_by
                ) VALUES (%s, %s, %s, %s, %s)
            """, (
                domain,
                data.get('description', ''),
                data.get('allow_subdomains', False),
                data.get('enabled', True),
                session.get('username', 'system')
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'message': f'Domain {domain} added successfully'
            })
            
        except psycopg2.IntegrityError:
            cursor.close()
            conn.close()
            return jsonify({'error': f'Domain {domain} already exists'}), 409
        
    except Exception as e:
        logging.error(f"Error adding email domain: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/email-domains/<domain>', methods=['DELETE'])
def delete_email_domain(domain):
    """Delete allowed email domain"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("DELETE FROM allowed_email_domains WHERE domain = %s", (domain.lower(),))
        
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Domain not found'}), 404
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': f'Domain {domain} deleted successfully'
        })
        
    except Exception as e:
        logging.error(f"Error deleting email domain: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ================================
# SMTP Configuration Endpoints
# ================================

@app.route('/api/smtp-config', methods=['GET'])
def get_smtp_config():
    """Get SMTP configuration"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT smtp_server, smtp_port, smtp_username, smtp_password, 
                   sender_email, sender_name, use_tls, last_test_status, last_test_message
            FROM smtp_config ORDER BY id DESC LIMIT 1
        """)
        
        config_row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if config_row:
            config = {
                'smtp_server': config_row['smtp_server'] or '',
                'smtp_port': config_row['smtp_port'] or 587,
                'smtp_username': config_row['smtp_username'] or '',
                'smtp_password': '****' if config_row['smtp_password'] else '',
                'sender_email': config_row['sender_email'] or '',
                'sender_name': config_row['sender_name'] or '',
                'use_tls': config_row['use_tls'] if config_row['use_tls'] is not None else True,
                'last_test_status': config_row['last_test_status'],
                'last_test_message': config_row['last_test_message']
            }
        else:
            config = {}
        
        return jsonify({
            'status': 'success',
            'config': config
        })
        
    except Exception as e:
        logging.error(f"Error getting SMTP config: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/smtp-config', methods=['POST'])
def save_smtp_config():
    """Save SMTP configuration"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['smtp_server', 'sender_email']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS smtp_config (
                id SERIAL PRIMARY KEY,
                smtp_server VARCHAR(255) NOT NULL,
                smtp_port INTEGER DEFAULT 587,
                smtp_username VARCHAR(255),
                smtp_password VARCHAR(255),
                sender_email VARCHAR(255) NOT NULL,
                sender_name VARCHAR(255),
                use_tls BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_test_status VARCHAR(20),
                last_test_message TEXT
            )
        """)
        
        # Get existing password if not provided in request
        existing_password = None
        if 'smtp_password' not in data:
            cursor.execute("SELECT smtp_password FROM smtp_config ORDER BY id DESC LIMIT 1")
            existing_row = cursor.fetchone()
            if existing_row:
                existing_password = existing_row['smtp_password']
        
        # Clear existing config (single config system)
        cursor.execute("DELETE FROM smtp_config")
        
        # Insert new config, preserving existing password if not provided
        password_to_use = data.get('smtp_password') if 'smtp_password' in data else existing_password
        
        cursor.execute("""
            INSERT INTO smtp_config 
            (smtp_server, smtp_port, smtp_username, smtp_password, sender_email, sender_name, use_tls)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            data['smtp_server'],
            data.get('smtp_port', 587),
            data.get('smtp_username'),
            password_to_use,
            data['sender_email'],
            data.get('sender_name'),
            data.get('use_tls', True)
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': 'SMTP configuration saved successfully'
        })
        
    except Exception as e:
        logging.error(f"Error saving SMTP config: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/smtp-test', methods=['POST'])
def test_smtp_connection():
    """Test SMTP connection by sending a test email"""
    try:
        data = request.get_json()
        test_email = data.get('test_email')
        
        if not test_email:
            return jsonify({'error': 'Test email address is required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT smtp_server, smtp_port, smtp_username, smtp_password, 
                   sender_email, sender_name, use_tls
            FROM smtp_config ORDER BY id DESC LIMIT 1
        """)
        
        config_row = cursor.fetchone()
        
        if not config_row:
            cursor.close()
            conn.close()
            return jsonify({'error': 'SMTP configuration not found'}), 404
        
        # Test the SMTP connection
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        smtp_server = config_row['smtp_server']
        smtp_port = config_row['smtp_port']
        smtp_username = config_row['smtp_username']
        smtp_password = config_row['smtp_password']
        sender_email = config_row['sender_email']
        sender_name = config_row['sender_name']
        use_tls = config_row['use_tls']
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = f"{sender_name} <{sender_email}>" if sender_name else sender_email
            msg['To'] = test_email
            msg['Subject'] = "CA Manager SMTP Test"
            
            body = """
            This is a test email from CA Manager to verify SMTP configuration.
            
            If you received this email, your SMTP settings are working correctly.
            
            CA Manager Email Verification System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server
            logging.info(f"Connecting to SMTP server: {smtp_server}:{smtp_port}")
            server = smtplib.SMTP(smtp_server, smtp_port)
            logging.info(f"Connected to SMTP server")
            
            if use_tls:
                logging.info("Starting TLS...")
                server.starttls()
                logging.info("TLS started successfully")
            else:
                logging.info("TLS not enabled")
            
            if smtp_username and smtp_password:
                logging.info(f"Attempting login with username: {smtp_username}")
                server.login(smtp_username, smtp_password)
                logging.info("Login successful")
            
            # Send email
            server.send_message(msg)
            server.quit()
            
            # Update test status in database
            cursor.execute("""
                UPDATE smtp_config SET 
                last_test_status = 'success',
                last_test_message = 'Test email sent successfully'
                WHERE id = (SELECT id FROM smtp_config ORDER BY id DESC LIMIT 1)
            """)
            conn.commit()
            
            cursor.close()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'message': 'Test email sent successfully'
            })
            
        except Exception as smtp_error:
            # Update test status in database
            error_msg = str(smtp_error)
            cursor.execute("""
                UPDATE smtp_config SET 
                last_test_status = 'error',
                last_test_message = %s
                WHERE id = (SELECT id FROM smtp_config ORDER BY id DESC LIMIT 1)
            """, (error_msg[:255],))  # Truncate error message
            conn.commit()
            
            cursor.close()
            conn.close()
            
            return jsonify({
                'status': 'error',
                'error': f'SMTP test failed: {error_msg}'
            }), 400
            
    except Exception as e:
        logging.error(f"Error testing SMTP: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ================================
# Certificate Generation Functions  
# ================================

def generate_certificate_for_request(request_db_id, request_id, request_data):
    """Generate certificate for the given request"""
    try:
        logging.info(f"Generating certificate for request {request_id}")
        
        conn = get_db_connection()
        if not conn:
            return False
        
        # Get the request details
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM certificate_requests WHERE id = %s", (request_db_id,))
        request_row = cursor.fetchone()
        
        if not request_row:
            logging.error(f"Certificate request {request_db_id} not found")
            return False
        
        # Extract certificate details
        common_name = request_row["common_name"]
        san_dns_names = request_row.get("san_dns_names", [])
        san_emails = request_row.get("san_emails", [])
        key_algorithm = request_row.get("key_algorithm", "RSA")
        key_size = request_row.get("key_size", 2048)
        validity_days = request_row.get("validity_days", 365)
        
        # Generate certificate using the existing helper function
        cert_params = {
            "name": common_name,
            "san_dns": san_dns_names,
            "san_email": san_emails,
            "key_size": key_size,
            "validity": validity_days
        }
        
        logging.info(f"Sending certificate generation request to EasyRSA: {cert_params}")
        result = make_easyrsa_request("build-client-full", cert_params)
        
        logging.info(f"EasyRSA certificate creation response: {result}")
        
        if result.get("status") != "success":
            logging.error(f"Certificate generation failed: {result.get('message', 'Unknown error')}")
            return False
        
        # Now get the certificate files after creation
        logging.info(f"Retrieving certificate files for {common_name}")
        files_result = make_easyrsa_request("get-cert-files", {"name": common_name, "include_key": True})
        
        logging.info(f"EasyRSA get-cert-files response: {files_result}")
        
        if files_result.get("status") != "success":
            logging.error(f"Failed to retrieve certificate files: {files_result.get('message', 'Unknown error')}")
            return False
        
        # Extract certificate and private key from files response
        cert_pem = files_result.get("certificate", "")
        key_pem = files_result.get("private_key", "")
        
        logging.info(f"Certificate data length: {len(cert_pem)}, Private key data length: {len(key_pem)}")
        
        if not cert_pem or not key_pem:
            logging.error(f"Certificate or private key not returned by get-cert-files. Full result: {files_result}")
            return False
        
        with conn.cursor() as cursor:
            # Extract serial number from certificate
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            try:
                cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                serial_number = str(cert_obj.serial_number)
                expires_at = cert_obj.not_valid_after
            except:
                serial_number = None
                expires_at = datetime.now() + timedelta(days=validity_days)
            
            cursor.execute("""
                UPDATE certificate_requests 
                SET certificate_pem = %s,
                    private_key_pem = %s,
                    status = 'issued',
                    serial_number = %s,
                    issued_at = CURRENT_TIMESTAMP,
                    expires_at = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (cert_pem, key_pem, serial_number, expires_at, request_db_id))
            
            conn.commit()
        
        conn.close()
        
        logging.info(f"Successfully generated certificate for request {request_id} (CN: {common_name})")
        return True
        
    except Exception as e:
        logging.error(f"Failed to generate certificate for request {request_id}: {e}")
        return False

# Version Management API Endpoints

@app.route('/api/version-info', methods=['GET'])
@auth_required()
def get_version_info():
    """Get current version information"""
    try:
        # Get current branch
        result = subprocess.run(['git', 'branch', '--show-current'], 
                              capture_output=True, text=True, cwd='/app')
        current_branch = result.stdout.strip() if result.returncode == 0 else 'unknown'
        
        # Get current commit hash
        result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                              capture_output=True, text=True, cwd='/app')
        current_commit = result.stdout.strip() if result.returncode == 0 else 'unknown'
        
        # Get last update time from git log
        result = subprocess.run(['git', 'log', '-1', '--format=%cd', '--date=iso'], 
                              capture_output=True, text=True, cwd='/app')
        last_updated = result.stdout.strip() if result.returncode == 0 else 'unknown'
        
        return jsonify({
            'status': 'success',
            'branch': current_branch,
            'commit': current_commit,
            'last_updated': last_updated,
            'app_version': APP_VERSION
        })
        
    except Exception as e:
        logging.error(f"Error getting version info: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/available-branches', methods=['GET'])
@auth_required()
def get_available_branches():
    """Get available branches from GitHub"""
    try:
        # Get current branch for comparison
        result = subprocess.run(['git', 'branch', '--show-current'], 
                              capture_output=True, text=True, cwd='/app')
        current_branch = result.stdout.strip() if result.returncode == 0 else 'unknown'
        
        # Fetch branches from GitHub API
        response = requests.get(f'{GITHUB_API_URL}/branches', timeout=10)
        if response.status_code != 200:
            return jsonify({'status': 'error', 'message': 'Failed to fetch branches from GitHub'}), 500
        
        branches_data = response.json()
        branches = []
        
        for branch in branches_data:
            branches.append({
                'name': branch['name'],
                'commit': branch['commit']['sha'],
                'current': branch['name'] == current_branch
            })
        
        return jsonify({
            'status': 'success',
            'branches': branches,
            'current_branch': current_branch
        })
        
    except Exception as e:
        logging.error(f"Error getting available branches: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/check-updates', methods=['GET'])
@auth_required()
def check_updates():
    """Check if updates are available for the current branch"""
    try:
        # Get current branch and commit
        result = subprocess.run(['git', 'branch', '--show-current'], 
                              capture_output=True, text=True, cwd='/app')
        current_branch = result.stdout.strip() if result.returncode == 0 else 'main'
        
        result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                              capture_output=True, text=True, cwd='/app')
        current_commit = result.stdout.strip() if result.returncode == 0 else ''
        
        # Get latest commit from GitHub API
        response = requests.get(f'{GITHUB_API_URL}/branches/{current_branch}', timeout=10)
        if response.status_code != 200:
            return jsonify({'status': 'error', 'message': f'Failed to check updates for branch {current_branch}'}), 500
        
        branch_data = response.json()
        latest_commit = branch_data['commit']['sha']
        
        # Check if update is available
        updates_available = current_commit != latest_commit
        
        response_data = {
            'status': 'success',
            'updates_available': updates_available,
            'current_commit': current_commit,
            'latest_commit': latest_commit,
            'branch': current_branch
        }
        
        if updates_available:
            response_data.update({
                'commit_message': branch_data['commit']['commit']['message'],
                'commit_date': branch_data['commit']['commit']['committer']['date']
            })
        
        return jsonify(response_data)
        
    except Exception as e:
        logging.error(f"Error checking for updates: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/update-branch', methods=['POST'])
@auth_required()
def update_current_branch():
    """Update to the latest version of the current branch"""
    global update_status
    
    if not session.get('is_admin'):
        return jsonify({'status': 'error', 'message': 'Admin privileges required'}), 403
    
    if update_status['in_progress']:
        return jsonify({'status': 'error', 'message': 'Update already in progress'}), 409
    
    # Start update process in background thread
    thread = Thread(target=perform_update, args=(None,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'success', 'message': 'Update started'})

@app.route('/api/switch-branch', methods=['POST'])
@auth_required()
def switch_branch():
    """Switch to a different branch"""
    global update_status
    
    if not session.get('is_admin'):
        return jsonify({'status': 'error', 'message': 'Admin privileges required'}), 403
    
    if update_status['in_progress']:
        return jsonify({'status': 'error', 'message': 'Update already in progress'}), 409
    
    data = request.get_json()
    target_branch = data.get('branch')
    
    if not target_branch:
        return jsonify({'status': 'error', 'message': 'Branch name required'}), 400
    
    # Start branch switch process in background thread
    thread = Thread(target=perform_update, args=(target_branch,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'success', 'message': f'Switching to branch {target_branch}'})

@app.route('/api/update-status', methods=['GET'])
@auth_required()
def get_update_status():
    """Get current update status"""
    return jsonify({
        'status': 'success',
        'in_progress': update_status['in_progress'],
        'completed': update_status['completed'],
        'success': update_status['success'],
        'message': update_status['message'],
        'progress': update_status['progress'],
        'error': update_status['error']
    })

def perform_update(target_branch=None):
    """Perform the actual update/branch switch process"""
    global update_status
    
    try:
        update_status.update({
            'in_progress': True,
            'completed': False,
            'success': False,
            'message': 'Starting update process...',
            'progress': 0,
            'error': None
        })
        
        # Step 1: Fetch latest changes
        update_status.update({'message': 'Fetching latest changes...', 'progress': 10})
        result = subprocess.run(['git', 'fetch', 'origin'], 
                              capture_output=True, text=True, cwd='/app', timeout=30)
        if result.returncode != 0:
            raise Exception(f'Git fetch failed: {result.stderr}')
        
        # Step 2: Switch branch if specified
        if target_branch:
            update_status.update({'message': f'Switching to branch {target_branch}...', 'progress': 30})
            result = subprocess.run(['git', 'checkout', f'origin/{target_branch}'], 
                                  capture_output=True, text=True, cwd='/app', timeout=30)
            if result.returncode != 0:
                raise Exception(f'Branch switch failed: {result.stderr}')
        else:
            # Step 3: Pull latest changes for current branch
            update_status.update({'message': 'Pulling latest changes...', 'progress': 30})
            result = subprocess.run(['git', 'pull', 'origin'], 
                                  capture_output=True, text=True, cwd='/app', timeout=30)
            if result.returncode != 0:
                raise Exception(f'Git pull failed: {result.stderr}')
        
        # Step 4: Use the update script for Docker operations
        update_status.update({'message': 'Executing system update...', 'progress': 50})
        if target_branch:
            result = subprocess.run(['/app/update-system.sh', 'switch', target_branch], 
                                  capture_output=True, text=True, timeout=600)
        else:
            result = subprocess.run(['/app/update-system.sh', 'update'], 
                                  capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            raise Exception(f'System update failed: {result.stderr}')
        
        # Success
        update_status.update({
            'message': 'Update completed successfully!',
            'progress': 100,
            'completed': True,
            'success': True,
            'in_progress': False
        })
        
    except Exception as e:
        logging.error(f"Update failed: {e}")
        update_status.update({
            'message': 'Update failed',
            'error': str(e),
            'completed': True,
            'success': False,
            'in_progress': False
        })

if __name__ == '__main__':
    # Ensure logs directory exists
    os.makedirs('/app/logs', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Initialize database if needed
    logging.info("Starting CA Manager application...")
    if not initialize_database():
        logging.error("Database initialization failed. Exiting.")
        exit(1)
    
    # In production, use a proper WSGI server like gunicorn
    app.run(host='0.0.0.0', port=5000, debug=False)

