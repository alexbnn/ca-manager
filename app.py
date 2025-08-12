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

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Application version - build timestamp
APP_VERSION = "4.0.0"
BUILD_TIMESTAMP = f"{APP_VERSION}-{int(datetime.now().timestamp())}"

# Database connection for multi-user authentication
import psycopg2
import psycopg2.extras
import bcrypt

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Global flag to ensure database is initialized only once
_db_initialized = False

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
        
        table_exists = cursor.fetchone()[0]
        
        if not table_exists:
            logging.info("Database not initialized. Running initialization scripts...")
            
            # Execute database schema files in order
            schema_files = [
                '01-schema.sql',
                '02-initial-data.sql', 
                '03-tenant-schema.sql',
                '04-ocsp-schema.sql'
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
                        if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                            conn.close()
                            logging.info(f"Authentication successful for user: {username}")
                            return dict(user)
                        else:
                            logging.warning(f"Password verification failed for user: {username}")
                    except Exception as e:
                        logging.error(f"Bcrypt error for user {username}: {e}")
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
        # For backward compatibility, check both plain text and bcrypt hash
        password_matches = False
        
        # First check if ADMIN_PASSWORD_HASH is a bcrypt hash (starts with $2)
        if ADMIN_PASSWORD_HASH.startswith('$2'):
            # It's a bcrypt hash, verify properly
            try:
                password_matches = bcrypt.checkpw(password.encode('utf-8'), ADMIN_PASSWORD_HASH.encode('utf-8'))
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
                download_name='ca.crt',
                mimetype='application/x-x509-ca-cert'
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
                    zip_file.writestr("ca.crt", result['ca_certificate'])
            
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

@app.route('/api/scep/password', methods=['GET', 'POST'])
@auth_required()
def manage_scep_password():
    """Get or update SCEP challenge password"""
    try:
        if request.method == 'GET':
            # Get current SCEP password status from the SCEP server for real-time info
            try:
                # Query SCEP server for current password info
                scep_config_response = requests.post(
                    "http://scep-server:8090/reload-config",
                    json={},  # Empty payload to just get current status
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                if scep_config_response.status_code == 200:
                    scep_info = scep_config_response.json()
                    password_length = scep_info.get('password_length', 0)
                    password_set = password_length > 0
                    
                    # Get the actual current password from SCEP server response
                    current_password = scep_info.get('current_password', os.getenv('SCEP_PASSWORD', 'MySecretSCEPPassword123'))
                    logging.info(f"SCEP server returned password info: length={password_length}, password={current_password[:4]}***")
                else:
                    # Fallback to environment variable
                    logging.warning(f"SCEP server returned non-200 status: {scep_config_response.status_code}")
                    current_password = os.getenv('SCEP_PASSWORD', 'MySecretSCEPPassword123')
                    password_set = bool(current_password)
                    password_length = len(current_password) if current_password else 0
                    logging.info(f"Using fallback environment password (non-200): length={password_length}, password={current_password[:4]}***")
                    
            except Exception as e:
                logging.warning(f"Could not query SCEP server for password info: {e}")
                logging.warning(f"Exception type: {type(e)}, Exception details: {str(e)}")
                # Fallback to environment variable
                current_password = os.getenv('SCEP_PASSWORD', 'MySecretSCEPPassword123')
                password_set = bool(current_password)
                password_length = len(current_password) if current_password else 0
                logging.info(f"Using fallback environment password: length={password_length}, password={current_password[:4]}***")
            
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
            
            return jsonify({
                "status": "success",
                "message": "SCEP password updated successfully",
                "password_length": len(new_password),
                "note": "Password updated in real-time - no restart required"
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
            
            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
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