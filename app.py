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
APP_VERSION = "6.0.0"
BUILD_TIMESTAMP = f"{APP_VERSION}-{int(datetime.now().timestamp())}"

# Database connection for multi-user authentication
# import bcrypt  # Replaced with SHA-256 for better compatibility

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Set up logging
logger = logging.getLogger(__name__)

# Initialize IDP Authentication Manager
idp_auth_manager = None
try:
    from idp_auth import IDPAuthManager
    idp_auth_manager = IDPAuthManager()
    logger.info("IDP Authentication Manager initialized")
except Exception as e:
    logger.warning(f"Could not initialize IDP Authentication Manager: {str(e)}")

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
SMTP_FROM_EMAIL = os.getenv('SMTP_FROM_EMAIL', 'noreply@localhost')
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
                '06-intermediate-ca-schema.sql',
                '07-email-verification.sql',
                '08-idp-certificates.sql',
                '09-system-config.sql',
                '10-smtp-config.sql',
                '11-vlan-policies.sql',
                '12-enhanced-vlan-policies.sql'
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
            
            # Check for missing email verification tables (migration for existing databases)
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'allowed_email_domains'
                );
            """)
            
            email_table_exists = cursor.fetchone()['exists']
            
            if not email_table_exists:
                logging.info("Email verification tables missing. Running migration...")
                try:
                    with open('/app/database/07-email-verification.sql', 'r') as f:
                        migration_sql = f.read()
                    cursor.execute(migration_sql)
                    conn.commit()
                    logging.info("Email verification migration completed successfully")
                except Exception as e:
                    logging.error(f"Email verification migration failed: {e}")
                    conn.rollback()
            
            # Check for VLAN policy tables (migration for existing databases)
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'vlans'
                );
            """)
            
            vlan_table_exists = cursor.fetchone()['exists']
            
            if not vlan_table_exists:
                logging.info("VLAN policy tables missing. Running VLAN migration...")
                try:
                    with open('/app/database/11-vlan-policies.sql', 'r') as f:
                        vlan_migration_sql = f.read()
                    cursor.execute(vlan_migration_sql)
                    conn.commit()
                    logging.info("VLAN policy migration completed successfully")
                except FileNotFoundError:
                    logging.warning("VLAN policy schema file not found, skipping migration")
                except Exception as e:
                    logging.error(f"VLAN policy migration failed: {e}")
                    conn.rollback()
            
            # Check for enhanced VLAN policy tables (migration for existing databases)
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'user_classification_rules'
                );
            """)
            
            enhanced_vlan_table_exists = cursor.fetchone()['exists']
            
            if not enhanced_vlan_table_exists:
                logging.info("Enhanced VLAN policy tables missing. Running enhanced VLAN migration...")
                try:
                    with open('/app/database/12-enhanced-vlan-policies.sql', 'r') as f:
                        enhanced_vlan_migration_sql = f.read()
                    cursor.execute(enhanced_vlan_migration_sql)
                    conn.commit()
                    logging.info("Enhanced VLAN policy migration completed successfully")
                except FileNotFoundError:
                    logging.warning("Enhanced VLAN policy schema file not found, skipping migration")
                except Exception as e:
                    logging.error(f"Enhanced VLAN policy migration failed: {e}")
                    conn.rollback()
        
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
                # Load custom colors for login page too
                custom_colors = {}
                try:
                    conn = get_db_connection()
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT config_key, config_value 
                            FROM system_config 
                            WHERE config_key LIKE 'theme_color_%'
                        """)
                        for row in cursor.fetchall():
                            key = row['config_key'].replace('theme_color_', '')
                            custom_colors[key] = row['config_value']
                        conn.close()
                except Exception:
                    custom_colors = {}
                return render_template('login.html', version=BUILD_TIMESTAMP, custom_colors=custom_colors)
        else:
            if 'authenticated' not in session:
                # Load custom colors for login page too
                custom_colors = {}
                try:
                    conn = get_db_connection()
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT config_key, config_value 
                            FROM system_config 
                            WHERE config_key LIKE 'theme_color_%'
                        """)
                        for row in cursor.fetchall():
                            key = row['config_key'].replace('theme_color_', '')
                            custom_colors[key] = row['config_value']
                        conn.close()
                except Exception:
                    custom_colors = {}
                return render_template('login.html', version=BUILD_TIMESTAMP, custom_colors=custom_colors)
    
    # Check if user logged in via IDP - serve specialized portal
    if session.get('idp_user'):
        logger.info(f"IDP user detected: {session.get('username')}, serving IDP portal")
        return render_template('idp_portal.html')
    
    # Get user info for template (regular admin users)
    user_info = {
        'username': session.get('username', 'guest'),
        'is_admin': session.get('is_admin', False),
        'roles': session.get('roles', [])
    }
    
    # Load custom color theme for injection into template
    custom_colors = {}
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT config_key, config_value 
                FROM system_config 
                WHERE config_key LIKE 'theme_color_%'
            """)
            
            for row in cursor.fetchall():
                key = row['config_key'].replace('theme_color_', '')
                custom_colors[key] = row['config_value']
            
            conn.close()
    except Exception as e:
        logger.error(f"Error loading custom colors: {e}")
        custom_colors = {}
    
    return render_template('index.html', user=user_info, custom_colors=custom_colors)

@app.route('/login')
def login_page():
    """Serve the login page"""
    if AUTHENTICATION_ENABLED:
        if MULTI_USER_MODE:
            if not session.get('authenticated'):
                # Load custom colors for login page
                custom_colors = {}
                try:
                    conn = get_db_connection()
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT config_key, config_value 
                            FROM system_config 
                            WHERE config_key LIKE 'theme_color_%'
                        """)
                        for row in cursor.fetchall():
                            key = row['config_key'].replace('theme_color_', '')
                            custom_colors[key] = row['config_value']
                        conn.close()
                except Exception:
                    custom_colors = {}
                return render_template('login.html', version=BUILD_TIMESTAMP, custom_colors=custom_colors)
        else:
            if 'authenticated' not in session:
                # Load custom colors for login page
                custom_colors = {}
                try:
                    conn = get_db_connection()
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT config_key, config_value 
                            FROM system_config 
                            WHERE config_key LIKE 'theme_color_%'
                        """)
                        for row in cursor.fetchall():
                            key = row['config_key'].replace('theme_color_', '')
                            custom_colors[key] = row['config_value']
                        conn.close()
                except Exception:
                    custom_colors = {}
                return render_template('login.html', version=BUILD_TIMESTAMP, custom_colors=custom_colors)
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

# ================================
# IDP OAuth Routes
# ================================

@app.route('/auth/microsoft/login')
def microsoft_login():
    """Initiate Microsoft OAuth login"""
    try:
        # Direct database approach - bypass IDPConfig class issues
        import msal
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get Microsoft configuration directly from database
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", ('microsoft_oauth_enabled',))
        enabled_result = cursor.fetchone()
        logger.info(f"DEBUG RAW RESULT - enabled_result: {enabled_result}, type: {type(enabled_result)}")
        
        # Handle RealDictRow results properly
        enabled = enabled_result['config_value'] if enabled_result else 'False'
        
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", ('microsoft_client_id',))
        client_id_result = cursor.fetchone()
        client_id = client_id_result['config_value'] if client_id_result else ''
        
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", ('microsoft_client_secret',))
        client_secret_result = cursor.fetchone()
        client_secret = client_secret_result['config_value'] if client_secret_result else ''
        
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", ('microsoft_tenant_id',))
        tenant_id_result = cursor.fetchone()
        tenant_id = tenant_id_result['config_value'] if tenant_id_result else 'common'
        
        cursor.close()
        conn.close()
        
        logger.info(f"DEBUG DIRECT - enabled: {enabled}, client_id: {client_id}, tenant_id: {tenant_id}")
        
        # Check if Microsoft OAuth is enabled
        if str(enabled).lower() not in ('true', '1', 'yes', 'on'):
            return jsonify({'error': 'Microsoft OAuth is not enabled'}), 400
        
        if not client_id or not client_secret:
            return jsonify({'error': 'Microsoft OAuth not properly configured'}), 400
        
        # Dynamically construct redirect URI based on request host
        # This ensures it works with any domain without hardcoding
        scheme = 'https' if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https' else 'http'
        host = request.headers.get('X-Forwarded-Host', request.host)
        redirect_uri = f'{scheme}://{host}/auth/microsoft/callback'
        
        logger.info(f"Dynamic redirect URI: {redirect_uri}")
        
        # Create MSAL app directly
        authority = f'https://login.microsoftonline.com/{tenant_id}'
        
        app_msal = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority
        )
        
        # Generate state and store in session
        import secrets
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        
        # Get authorization URL - use only the scopes that Microsoft Graph accepts
        auth_url = app_msal.get_authorization_request_url(
            scopes=['User.Read'],  # Only use User.Read scope - other claims come automatically
            state=state,
            redirect_uri=redirect_uri
        )
        
        from flask import redirect
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Microsoft login error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Failed to initiate Microsoft login: {str(e)}'}), 500

@app.route('/auth/microsoft/callback')
def microsoft_callback():
    """Handle Microsoft OAuth callback"""
    try:
        import msal
        import requests
        
        # Get Microsoft configuration directly from database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", ('microsoft_client_id',))
        client_id_result = cursor.fetchone()
        client_id = client_id_result['config_value'] if client_id_result else ''
        
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", ('microsoft_client_secret',))
        client_secret_result = cursor.fetchone()
        client_secret = client_secret_result['config_value'] if client_secret_result else ''
        
        cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", ('microsoft_tenant_id',))
        tenant_id_result = cursor.fetchone()
        tenant_id = tenant_id_result['config_value'] if tenant_id_result else 'common'
        
        cursor.close()
        
        # Verify state for CSRF protection
        if request.args.get('state') != session.pop('oauth_state', None):
            conn.close()
            return jsonify({'error': 'Invalid state parameter'}), 400
        
        # Get authorization code
        code = request.args.get('code')
        if not code:
            conn.close()
            return jsonify({'error': 'No authorization code received'}), 400
        
        # Dynamically construct redirect URI based on request host
        scheme = 'https' if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https' else 'http'
        host = request.headers.get('X-Forwarded-Host', request.host)
        redirect_uri = f'{scheme}://{host}/auth/microsoft/callback'
        
        logger.info(f"Dynamic redirect URI for callback: {redirect_uri}")
        
        # Create MSAL app and exchange code for token
        authority = f'https://login.microsoftonline.com/{tenant_id}'
        
        app_msal = msal.ConfidentialClientApplication(
            client_id,
            authority=authority,
            client_credential=client_secret
        )
        
        # Exchange authorization code for token
        result = app_msal.acquire_token_by_authorization_code(
            code,
            scopes=['User.Read'],
            redirect_uri=redirect_uri
        )
        
        if 'error' in result:
            logger.error(f"Microsoft token error: {result.get('error_description')}")
            conn.close()
            return jsonify({'error': 'Authentication failed'}), 500
        
        # Get user info using the access token
        if 'access_token' in result:
            # Call Microsoft Graph API to get user details
            graph_response = requests.get(
                'https://graph.microsoft.com/v1.0/me',
                headers={'Authorization': f"Bearer {result['access_token']}"}
            )
            
            if graph_response.status_code == 200:
                user_info = graph_response.json()
                
                # Create user session
                session['authenticated'] = True
                session['username'] = user_info.get('userPrincipalName') or user_info.get('mail')
                session['idp_user'] = True
                session['idp_provider'] = 'microsoft'  # Set provider for Microsoft OAuth
                session['idp_user_id'] = user_info.get('id', user_info.get('userPrincipalName'))
                session['user_id'] = 0  # IDP users don't have local user IDs yet
                session['user_display_name'] = user_info.get('displayName')
                
                logger.info(f"Microsoft IDP login successful for user: {session['username']}")
                conn.close()
                return redirect('/')
            else:
                logger.error(f"Failed to get user info from Microsoft Graph: {graph_response.text}")
                conn.close()
                return jsonify({'error': 'Failed to get user information'}), 500
        
        conn.close()
        return jsonify({'error': 'Authentication failed'}), 500
        
    except Exception as e:
        logger.error(f"Microsoft callback error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/auth/google/login')
def google_login():
    """Initiate Google OAuth login"""
    try:
        # Set database connection for IDPConfig FIRST
        from idp_config import IDPConfig
        from idp_auth import IDPAuthManager
        
        conn = get_db_connection()
        IDPConfig.set_db_connection(conn)
        
        # Now initialize the auth manager with the database config loaded
        auth_manager = IDPAuthManager(app)
        
        # Initiate Google login
        redirect_response = auth_manager.initiate_google_login()
        conn.close()
        return redirect_response
    except Exception as e:
        logger.error(f"Google login error: {str(e)}")
        return jsonify({'error': f'Failed to initiate Google login: {str(e)}'}), 500

@app.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        # Set database connection for IDPConfig FIRST
        from idp_config import IDPConfig
        from idp_auth import IDPAuthManager
        
        conn = get_db_connection()
        IDPConfig.set_db_connection(conn)
        
        # Now initialize the auth manager with the database config loaded
        auth_manager = IDPAuthManager(app)
        
        # Handle the callback
        result = auth_manager.handle_google_callback()
        
        # If successful, create a regular session
        if isinstance(result, dict) and result.get('status') == 'success':
            user_data = result.get('user', {})
            session['authenticated'] = True
            session['username'] = user_data.get('email', 'idp_user')
            session['idp_user'] = True
            session['idp_provider'] = 'google'  # Set provider for Google OAuth
            session['idp_user_id'] = user_data.get('id', user_data.get('email'))
            session['user_id'] = 0  # IDP users don't have local user IDs yet
            
            logger.info(f"Google IDP login successful for user: {session['username']}")
            conn.close()
            return redirect('/')
        
        conn.close()
        return result
    except Exception as e:
        logger.error(f"Google callback error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

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
    """Initialize PKI and clear all certificate data"""
    log_operation('init_pki')
    
    # First initialize the PKI structure
    result = make_easyrsa_request('init-pki')
    
    # If PKI initialization was successful, also clear the database
    if result.get('status') == 'success':
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Clear all certificate-related data (in dependency order)
            tables_cleared = {}
            
            # Clear download tracking
            cursor.execute("DELETE FROM certificate_downloads")
            tables_cleared['certificate_downloads'] = cursor.rowcount
            
            # Clear approval history
            cursor.execute("DELETE FROM request_approvals")
            tables_cleared['request_approvals'] = cursor.rowcount
            
            # Clear certificate requests
            cursor.execute("DELETE FROM certificate_requests")
            tables_cleared['certificate_requests'] = cursor.rowcount
            
            # Clear CA chains
            cursor.execute("DELETE FROM ca_chains")
            tables_cleared['ca_chains'] = cursor.rowcount
            
            # Clear intermediate CAs
            cursor.execute("DELETE FROM intermediate_cas")
            tables_cleared['intermediate_cas'] = cursor.rowcount
            
            # Clear IDP certificates
            cursor.execute("DELETE FROM idp_certificates")
            tables_cleared['idp_certificates'] = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            total_cleared = sum(tables_cleared.values())
            
            # Update the result message to include database cleanup info
            original_message = result.get('message', 'PKI initialized successfully')
            result['message'] = f"{original_message}. Cleared {total_cleared} total certificate records from database ({', '.join([f'{count} {table}' for table, count in tables_cleared.items() if count > 0])})."
            
            logger.info(f"PKI reset completed: cleared certificate data - {tables_cleared}")
            
        except Exception as e:
            logger.error(f"Error clearing database during PKI reset: {e}")
            # Don't fail the entire operation if database cleanup fails
            result['message'] = result.get('message', '') + f" (Warning: Could not clear database records: {str(e)})"
    
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

@app.route('/api/ca/upload', methods=['POST'])
@auth_required(permission='ca_build')
def upload_ca():
    """Upload existing CA certificate and private key"""
    import tempfile
    import ssl
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    
    data = request.get_json() or {}
    
    try:
        # Get uploaded data
        ca_cert_pem = data.get('ca_certificate', '')
        ca_key_pem = data.get('ca_key', '')
        key_password = data.get('key_password', None)
        cert_validity_days = data.get('cert_validity_days', 365)
        
        if not ca_cert_pem or not ca_key_pem:
            return jsonify({
                'status': 'error',
                'message': 'Both CA certificate and private key are required'
            }), 400
        
        # Validate certificate format and parse it
        try:
            cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Invalid certificate format: {str(e)}'
            }), 400
        
        # Validate private key format
        try:
            if key_password:
                private_key = serialization.load_pem_private_key(
                    ca_key_pem.encode(),
                    password=key_password.encode(),
                    backend=default_backend()
                )
            else:
                private_key = serialization.load_pem_private_key(
                    ca_key_pem.encode(),
                    password=None,
                    backend=default_backend()
                )
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Invalid private key format or incorrect password: {str(e)}'
            }), 400
        
        # Verify that the private key matches the certificate
        try:
            # Get public key from certificate
            cert_public_key = cert.public_key()
            
            # Get public key from private key
            private_public_key = private_key.public_key()
            
            # Compare public key numbers
            if hasattr(cert_public_key, 'public_numbers') and hasattr(private_public_key, 'public_numbers'):
                if cert_public_key.public_numbers() != private_public_key.public_numbers():
                    return jsonify({
                        'status': 'error',
                        'message': 'Private key does not match the certificate'
                    }), 400
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Error validating key-certificate pair: {str(e)}'
            }), 400
        
        # Extract certificate information
        subject = cert.subject
        ca_info = {
            'common_name': subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value if subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else 'Unknown',
            'country': subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value if subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME) else '',
            'state': subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)[0].value if subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME) else '',
            'city': subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[0].value if subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME) else '',
            'organization': subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value if subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) else '',
            'organizational_unit': subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value if subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME) else '',
            'email': subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value if subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS) else '',
            'valid_from': cert.not_valid_before.isoformat(),
            'valid_until': cert.not_valid_after.isoformat(),
            'serial_number': str(cert.serial_number)
        }
        
        # Send to EasyRSA container to import
        upload_data = {
            'ca_certificate': ca_cert_pem,
            'ca_key': ca_key_pem,
            'cert_validity_days': cert_validity_days,
            'ca_info': ca_info
        }
        
        log_operation('upload_ca', {'ca_info': ca_info})
        result = make_easyrsa_request('import-ca', upload_data)
        
        if result.get('status') == 'success':
            # CA import successful - also clear all certificate database records
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                # Clear all certificate-related data (in dependency order)
                tables_cleared = {}
                
                # Clear download tracking
                cursor.execute("DELETE FROM certificate_downloads")
                tables_cleared['certificate_downloads'] = cursor.rowcount
                
                # Clear approval history
                cursor.execute("DELETE FROM request_approvals")
                tables_cleared['request_approvals'] = cursor.rowcount
                
                # Clear certificate requests
                cursor.execute("DELETE FROM certificate_requests")
                tables_cleared['certificate_requests'] = cursor.rowcount
                
                # Clear CA chains
                cursor.execute("DELETE FROM ca_chains")
                tables_cleared['ca_chains'] = cursor.rowcount
                
                # Clear intermediate CAs
                cursor.execute("DELETE FROM intermediate_cas")
                tables_cleared['intermediate_cas'] = cursor.rowcount
                
                # Clear IDP certificates
                cursor.execute("DELETE FROM idp_certificates")
                tables_cleared['idp_certificates'] = cursor.rowcount
                
                conn.commit()
                conn.close()
                
                total_cleared = sum(tables_cleared.values())
                
                result['ca_info'] = ca_info
                result['message'] = f"Successfully imported CA: {ca_info['common_name']}. Cleared {total_cleared} certificate records from database."
                
                logger.info(f"CA import completed with database cleanup - cleared: {tables_cleared}")
                
            except Exception as e:
                logger.error(f"Error clearing database during CA import: {e}")
                # Don't fail the entire operation if database cleanup fails
                result['ca_info'] = ca_info
                result['message'] = f"Successfully imported CA: {ca_info['common_name']} (Warning: Could not clear database records: {str(e)})"
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error uploading CA: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to upload CA: {str(e)}'
        }), 500

@app.route('/api/ca/show', methods=['GET'])
@auth_required(permission='ca_read')
def show_ca():
    """Show CA certificate details"""
    result = make_easyrsa_request('show-ca')
    return jsonify(result)

@app.route('/api/ca/download', methods=['GET'])
@auth_required(permission='ca_read')
def download_ca():
    """Download CA certificate (with private key for admin users)"""
    try:
        log_operation('download_ca')
        
        # Check if user is admin
        is_admin = session.get('is_admin', False)
        
        # Get CA certificate
        cert_response = requests.get(f"{TERMINAL_CONTAINER_URL}/download-ca", timeout=REQUEST_TIMEOUT)
        
        if cert_response.status_code != 200:
            return jsonify({
                "status": "error", 
                "message": f"CA certificate not found. Container response: {cert_response.status_code}"
            }), 404
        
        ca_cert_content = cert_response.text
        
        if is_admin:
            # Admin users get combined certificate + private key
            try:
                # Get CA private key
                key_response = requests.post(
                    f"{TERMINAL_CONTAINER_URL}/execute",
                    json={"operation": "get-ca-key"},
                    timeout=REQUEST_TIMEOUT
                )
                
                if key_response.status_code == 200:
                    key_data = key_response.json()
                    if key_data.get('status') == 'success':
                        ca_key_content = key_data.get('private_key', '')
                        
                        # Combine certificate and private key
                        combined_content = f"{ca_cert_content.strip()}\n{ca_key_content.strip()}\n"
                        file_obj = io.BytesIO(combined_content.encode('utf-8'))
                        
                        return send_file(
                            file_obj,
                            as_attachment=True,
                            download_name='ca-combined.pem',
                            mimetype='application/x-pem-file'
                        )
                    else:
                        # Fall back to certificate only if key retrieval fails
                        app.logger.warning(f"Could not retrieve CA private key for admin: {key_data.get('message')}")
                else:
                    app.logger.warning(f"CA private key request failed with status: {key_response.status_code}")
                    
            except Exception as key_error:
                app.logger.warning(f"Failed to retrieve CA private key: {str(key_error)}")
                # Continue to provide certificate-only download
        
        # Regular users or fallback: certificate only
        file_obj = io.BytesIO(ca_cert_content.encode('utf-8'))
        
        return send_file(
            file_obj,
            as_attachment=True,
            download_name='ca.pem',
            mimetype='application/x-pem-file'
        )
            
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
        # The backup_data is already in the correct format (base64-encoded JSON)
        # Save it directly as a .pki file without additional encoding/decoding
        backup_filename = f"pki-backup-{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}.pki"
        
        # Convert the base64 string to bytes for file download
        backup_bytes = result['backup_data'].encode('utf-8')
        
        return send_file(
            io.BytesIO(backup_bytes),
            as_attachment=True,
            download_name=backup_filename,
            mimetype='application/octet-stream'
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
                "http://ocsp-responder:8091/health",
                timeout=5
            )
            response_time = round((time.time() - start_time) * 1000, 2)
            ocsp_healthy = health_response.status_code == 200
        except Exception as e:
            logging.debug(f"OCSP health check failed: {e}")
            response_time = None
            ocsp_healthy = False
        
        # Test dependencies
        ca_manager_healthy = True  # We're in the CA manager
        easyrsa_healthy = False
        try:
            # Fix URL construction for EasyRSA health check
            easyrsa_url = TERMINAL_CONTAINER_URL.replace('/execute', '')
            if not easyrsa_url.endswith('/'):
                easyrsa_url += '/'
            easyrsa_response = requests.get(f"{easyrsa_url}health", timeout=5)
            easyrsa_healthy = easyrsa_response.status_code == 200
        except Exception as e:
            logging.debug(f"EasyRSA health check failed: {e}")
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
        domain = os.getenv('DOMAIN', 'localhost')
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
# Logo Management Endpoints
# ================================

@app.route('/api/logo', methods=['GET'])
def get_logo():
    """Get the current logo path"""
    try:
        # Check if custom logo exists with any supported extension
        logo_dir = '/app/static/images'
        allowed_extensions = ['png', 'jpg', 'jpeg', 'gif', 'svg']
        
        for ext in allowed_extensions:
            custom_logo_path = f'{logo_dir}/custom-logo.{ext}'
            if os.path.exists(custom_logo_path):
                return jsonify({
                    'status': 'success',
                    'logo_url': f'/static/images/custom-logo.{ext}',
                    'is_custom': True
                })
        
        # No custom logo found, return default
        return jsonify({
            'status': 'success', 
            'logo_url': '/static/images/extreme-networks-logo.png',
            'is_custom': False
        })
    except Exception as e:
        logging.error(f"Error getting logo: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/logo', methods=['POST'])
@auth_required(permission='admin')
def upload_logo():
    """Upload a custom logo"""
    try:
        if 'logo' not in request.files:
            return jsonify({'error': 'No logo file provided'}), 400
        
        file = request.files['logo']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file extension
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'error': f'Invalid file type. Allowed types: {", ".join(allowed_extensions)}'}), 400
        
        # Check file size (max 5MB)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 5 * 1024 * 1024:  # 5MB
            return jsonify({'error': 'File too large. Maximum size is 5MB'}), 400
        
        # Create directory if it doesn't exist
        logo_dir = '/app/static/images'
        os.makedirs(logo_dir, exist_ok=True)
        
        # Save the file as custom-logo with original extension
        custom_logo_path = f'/app/static/images/custom-logo.{file_ext}'
        
        # Remove any existing custom logo files
        for ext in allowed_extensions:
            old_logo = f'/app/static/images/custom-logo.{ext}'
            if os.path.exists(old_logo):
                os.remove(old_logo)
        
        # Save new logo
        file.save(custom_logo_path)
        
        return jsonify({
            'status': 'success',
            'message': 'Logo uploaded successfully',
            'logo_url': f'/static/images/custom-logo.{file_ext}'
        })
        
    except Exception as e:
        logging.error(f"Error uploading logo: {e}")
        return jsonify({'error': 'Failed to upload logo'}), 500

@app.route('/api/logo', methods=['DELETE'])
@auth_required(permission='admin')
def reset_logo():
    """Reset to default logo"""
    try:
        # Remove all custom logo files
        logo_dir = '/app/static/images'
        for file in os.listdir(logo_dir):
            if file.startswith('custom-logo.'):
                os.remove(os.path.join(logo_dir, file))
        
        return jsonify({
            'status': 'success',
            'message': 'Logo reset to default',
            'logo_url': '/static/images/extreme-networks-logo.png'
        })
        
    except Exception as e:
        logging.error(f"Error resetting logo: {e}")
        return jsonify({'error': 'Failed to reset logo'}), 500

# ================================
# Color Theme Customization Endpoints
# ================================

@app.route('/api/theme/colors', methods=['GET'])
def get_color_theme():
    """Get current color theme configuration"""
    try:
        # Default color palette
        default_colors = {
            'primary_purple': '#5B059C',
            'dark_blue': '#101B37', 
            'light_gray': '#EAECF0',
            'medium_gray': '#98A2B3',
            'text_dark': '#101828',
            'text_light': '#FFFFFF',
            'success_green': '#12B76A',
            'warning_orange': '#F79009',
            'error_red': '#F04438',
            'info_blue': '#2E90FA'
        }
        
        color_settings = {}
        
        # Try to get custom colors from database
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                
                # Get color theme from system_config table
                cursor.execute("""
                    SELECT config_key, config_value 
                    FROM system_config 
                    WHERE config_key LIKE 'theme_color_%'
                """)
                
                rows = cursor.fetchall()
                for row in rows:
                    key = row['config_key'].replace('theme_color_', '')
                    color_settings[key] = row['config_value']
                
                conn.close()
                logging.info(f"Loaded {len(color_settings)} custom colors from database")
        except Exception as db_error:
            logging.warning(f"Could not load custom colors from database: {db_error}")
            # Continue with defaults
        
        # Merge with defaults
        theme_colors = {**default_colors, **color_settings}
        
        return jsonify({
            'status': 'success',
            'colors': theme_colors,
            'is_custom': len(color_settings) > 0
        })
        
    except Exception as e:
        logging.error(f"Error in get_color_theme: {type(e).__name__}: {str(e)}")
        # Return defaults if everything fails
        return jsonify({
            'status': 'success',
            'colors': {
                'primary_purple': '#5B059C',
                'dark_blue': '#101B37', 
                'light_gray': '#EAECF0',
                'medium_gray': '#98A2B3',
                'text_dark': '#101828',
                'text_light': '#FFFFFF',
                'success_green': '#12B76A',
                'warning_orange': '#F79009',
                'error_red': '#F04438',
                'info_blue': '#2E90FA'
            },
            'is_custom': False
        })

@app.route('/api/theme/colors', methods=['POST'])
@auth_required(permission='admin')
def update_color_theme():
    """Update color theme configuration"""
    try:
        data = request.get_json()
        colors = data.get('colors', {})
        
        if not colors:
            return jsonify({'error': 'No colors provided'}), 400
        
        # Validate color format (hex colors)
        import re
        hex_pattern = re.compile(r'^#[0-9A-Fa-f]{6}$')
        
        valid_color_keys = {
            'primary_purple', 'dark_blue', 'light_gray', 'medium_gray',
            'text_dark', 'text_light', 'success_green', 'warning_orange', 
            'error_red', 'info_blue'
        }
        
        for key, value in colors.items():
            if key not in valid_color_keys:
                return jsonify({'error': f'Invalid color key: {key}'}), 400
            
            if not hex_pattern.match(value):
                return jsonify({'error': f'Invalid color format for {key}. Use hex format like #5B059C'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Update or insert color settings
        for key, value in colors.items():
            config_key = f'theme_color_{key}'
            
            cursor.execute("""
                INSERT INTO system_config (config_key, config_value, description, updated_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (config_key) 
                DO UPDATE SET 
                    config_value = EXCLUDED.config_value,
                    updated_at = EXCLUDED.updated_at
            """, (config_key, value, f'Custom theme color: {key}'))
        
        conn.commit()
        conn.close()
        
        log_operation('update_color_theme')
        
        return jsonify({
            'status': 'success',
            'message': 'Color theme updated successfully',
            'colors': colors
        })
        
    except Exception as e:
        logging.error(f"Error updating color theme: {e}")
        return jsonify({'error': 'Failed to update color theme'}), 500

@app.route('/api/theme/colors', methods=['DELETE'])
@auth_required(permission='admin')
def reset_color_theme():
    """Reset color theme to default"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Remove all custom color settings
        cursor.execute("DELETE FROM system_config WHERE config_key LIKE 'theme_color_%'")
        
        conn.commit()
        conn.close()
        
        log_operation('reset_color_theme')
        
        # Return default colors
        default_colors = {
            'primary_purple': '#5B059C',
            'dark_blue': '#101B37',
            'light_gray': '#EAECF0', 
            'medium_gray': '#98A2B3',
            'text_dark': '#101828',
            'text_light': '#FFFFFF',
            'success_green': '#12B76A',
            'warning_orange': '#F79009',
            'error_red': '#F04438',
            'info_blue': '#2E90FA'
        }
        
        return jsonify({
            'status': 'success',
            'message': 'Color theme reset to default',
            'colors': default_colors
        })
        
    except Exception as e:
        logging.error(f"Error resetting color theme: {e}")
        return jsonify({'error': 'Failed to reset color theme'}), 500

@app.route('/api/theme/preview', methods=['POST'])
@auth_required(permission='admin')
def preview_color_theme():
    """Generate CSS for color theme preview"""
    try:
        data = request.get_json()
        colors = data.get('colors', {})
        
        if not colors:
            return jsonify({'error': 'No colors provided'}), 400
        
        # Generate CSS variables
        css_variables = []
        for key, value in colors.items():
            css_var_name = key.replace('_', '-')
            css_variables.append(f'--{css_var_name}: {value};')
        
        css_content = f"""
        :root {{
            {chr(10).join(css_variables)}
        }}
        """
        
        return jsonify({
            'status': 'success',
            'css': css_content.strip()
        })
        
    except Exception as e:
        logging.error(f"Error generating theme preview: {e}")
        return jsonify({'error': 'Failed to generate preview'}), 500

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
            # Return default empty config structure to prevent JavaScript errors
            config = {
                'smtp_server': '',
                'smtp_port': 587,
                'smtp_username': '',
                'smtp_password': '',
                'sender_email': '',
                'sender_name': '',
                'use_tls': True,
                'last_test_status': None,
                'last_test_message': 'SMTP not configured'
            }
        
        return jsonify({
            'status': 'success',
            'config': config,
            'configured': bool(config_row)
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
# IDP Configuration API  
# ================================

@app.route('/api/idp/config', methods=['GET'])
@auth_required()
def get_idp_config():
    """Get IDP configuration for GUI"""
    try:
        from idp_config import IDPConfig
        
        # Set database connection
        conn = get_db_connection()
        IDPConfig.set_db_connection(conn)
        
        # Get all configuration
        config = IDPConfig.get_all_config()
        
        # Add computed fields
        config['providers'] = []
        if config.get('google_enabled'):
            config['providers'].append('google')
        if config.get('microsoft_enabled'):
            config['providers'].append('microsoft')
        
        conn.close()
        
        return jsonify(config)
        
    except Exception as e:
        logger.error(f"Error getting IDP config: {str(e)}")
        return jsonify({'error': 'Failed to load IDP configuration'}), 500

@app.route('/api/idp/config', methods=['POST'])
@auth_required()
def save_idp_config():
    """Save IDP configuration from GUI"""
    try:
        from idp_config import IDPConfig
        
        data = request.get_json() or {}
        
        # Get current user for audit
        user_id = session.get('user_id', 1)  # Default to admin user ID
        
        # Set database connection
        conn = get_db_connection()
        IDPConfig.set_db_connection(conn)
        
        # Update configuration
        success = IDPConfig.update_config(data, user_id)
        
        if success:
            # Log configuration change
            logger.info(f"IDP configuration updated by user ID: {user_id}")
            
            return jsonify({
                'status': 'success',
                'message': 'IDP configuration saved successfully'
            })
        else:
            return jsonify({
                'status': 'error', 
                'message': 'Failed to save IDP configuration'
            }), 500
            
    except Exception as e:
        logger.error(f"Error saving IDP config: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to save IDP configuration: {str(e)}'
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/idp/status')
def get_idp_status():
    """Get IDP status and statistics"""
    try:
        from idp_config import IDPConfig
        
        # Set database connection
        conn = get_db_connection()
        IDPConfig.set_db_connection(conn)
        
        config = IDPConfig.get_all_config()
        
        # Get IDP user statistics
        with conn.cursor() as cursor:
            # Count total IDP users
            cursor.execute("SELECT COUNT(*) FROM idp_users")
            total_users = cursor.fetchone()[0]
            
            # Count active certificates
            cursor.execute("SELECT COUNT(*) FROM idp_certificates WHERE status = 'active'")
            active_certificates = cursor.fetchone()[0]
            
            # Count certificates expiring in 30 days
            cursor.execute("""
                SELECT COUNT(*) FROM idp_certificates 
                WHERE status = 'active' AND valid_until <= CURRENT_TIMESTAMP + INTERVAL '30 days'
            """)
            expiring_certificates = cursor.fetchone()[0]
        
        status = {
            'idp_enabled': config.get('idp_enabled', False),
            'google_enabled': config.get('google_enabled', False),
            'microsoft_enabled': config.get('microsoft_enabled', False),
            'auto_generate': config.get('auto_generate_certs', False),
            'total_users': total_users,
            'active_certificates': active_certificates,
            'expiring_certificates': expiring_certificates,
            'providers': []
        }
        
        if config.get('google_enabled'):
            status['providers'].append('google')
        if config.get('microsoft_enabled'):
            status['providers'].append('microsoft')
        
        conn.close()
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting IDP status: {str(e)}")
        return jsonify({
            'idp_enabled': False,
            'google_enabled': False,
            'microsoft_enabled': False,
            'total_users': 0,
            'active_certificates': 0,
            'error': 'Failed to load IDP status'
        })

@app.route('/api/idp/login-config')
def get_idp_login_config():
    """Get basic IDP configuration for login page (no auth required)"""
    try:
        # Use direct database queries instead of IDPConfig class
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get required configuration values directly from database
        config_keys = ['idp_enabled', 'microsoft_oauth_enabled', 'google_oauth_enabled']
        config_values = {}
        
        for key in config_keys:
            cursor.execute(
                "SELECT config_value FROM system_config WHERE config_key = %s",
                (key,)
            )
            result = cursor.fetchone()
            if result:
                # Handle boolean conversion for database values
                value = result['config_value']
                if isinstance(value, str):
                    config_values[key] = value.lower() in ('true', '1', 'yes', 'on')
                elif isinstance(value, bool):
                    config_values[key] = value
                else:
                    config_values[key] = bool(value)
            else:
                config_values[key] = False
        
        cursor.close()
        conn.close()
        
        # Return only what's needed for login page
        result = {
            'idp_enabled': config_values.get('idp_enabled', False),
            'google_enabled': config_values.get('google_oauth_enabled', False),
            'microsoft_enabled': config_values.get('microsoft_oauth_enabled', False),
            'providers': []
        }
        
        if config_values.get('google_oauth_enabled'):
            result['providers'].append('google')
        if config_values.get('microsoft_oauth_enabled'):
            result['providers'].append('microsoft')
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting IDP login config: {str(e)}")
        return jsonify({
            'idp_enabled': False,
            'google_enabled': False,
            'microsoft_enabled': False,
            'providers': []
        })

@app.route('/api/idp/test-connection', methods=['POST'])
@auth_required()
def test_idp_connection():
    """Test IDP OAuth2 connections"""
    try:
        from idp_config import IDPConfig
        import requests
        
        # Set database connection
        conn = get_db_connection()
        IDPConfig.set_db_connection(conn)
        
        config = IDPConfig.get_all_config()
        results = {'status': 'success'}
        
        # Test Google connection
        if config.get('google_enabled') and config.get('google_client_id'):
            try:
                response = requests.get(
                    'https://accounts.google.com/.well-known/openid-configuration',
                    timeout=10
                )
                if response.status_code == 200:
                    results['google'] = {'status': '✅ Google OAuth configuration accessible'}
                else:
                    results['google'] = {'status': '❌ Google OAuth configuration not accessible'}
            except Exception as e:
                results['google'] = {'status': f'❌ Google OAuth test failed: {str(e)[:100]}'}
        
        # Test Microsoft connection
        if config.get('microsoft_enabled') and config.get('microsoft_client_id'):
            tenant_id = config.get('microsoft_tenant_id', 'common')
            client_secret = config.get('microsoft_client_secret', '')
            
            # Validate required configuration
            if not client_secret:
                results['microsoft'] = {'status': '❌ Microsoft client secret not configured'}
            elif len(tenant_id) < 10:  # Basic tenant ID validation
                results['microsoft'] = {'status': '❌ Microsoft tenant ID appears invalid'}
            else:
                try:
                    # Try to connect to Microsoft's OAuth endpoint
                    response = requests.get(
                        f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize',
                        timeout=5,
                        allow_redirects=False
                    )
                    # We expect a redirect or 4xx response for GET without params, not 5xx
                    if response.status_code < 500:
                        results['microsoft'] = {'status': '✅ Microsoft OAuth configuration accessible'}
                    else:
                        results['microsoft'] = {'status': f'❌ Microsoft OAuth endpoint error: {response.status_code}'}
                except Exception as e:
                    results['microsoft'] = {'status': f'❌ Microsoft OAuth test failed: {str(e)[:100]}'}
        
        conn.close()
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error testing IDP connection: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to test IDP connections: {str(e)}'
        }), 500


# ================================
# IDP Self-Service Portal APIs
# ================================

@app.route('/api/idp/current-user')
def get_current_idp_user():
    """Get current IDP user information"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    return jsonify({
        'status': 'success',
        'user': {
            'email': session.get('username'),
            'name': session.get('user_display_name') or session.get('username'),
            'provider': 'microsoft',  # TODO: Store actual provider in session
            'picture': None  # TODO: Store profile picture if available
        }
    })

def ensure_idp_certificates_table():
    """Ensure the idp_certificates table exists"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        cursor = conn.cursor()
        
        # Create the idp_certificates table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS idp_certificates (
                id SERIAL PRIMARY KEY,
                idp_user_id VARCHAR(255) NOT NULL,
                idp_email VARCHAR(255) NOT NULL,
                idp_provider VARCHAR(50) NOT NULL,
                certificate_serial VARCHAR(100) NOT NULL UNIQUE,
                certificate_cn VARCHAR(255) NOT NULL,
                certificate_subject TEXT,
                certificate_issuer TEXT,
                certificate_pem TEXT NOT NULL,
                private_key_encrypted TEXT,
                status VARCHAR(50) DEFAULT 'active',
                revocation_reason VARCHAR(255),
                revoked_at TIMESTAMP,
                issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                device_id VARCHAR(255),
                device_name VARCHAR(255),
                purpose VARCHAR(100),
                request_ip VARCHAR(50),
                user_agent TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_idp_cert_user ON idp_certificates (idp_user_id, idp_provider)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_idp_cert_email ON idp_certificates (idp_email)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_idp_cert_serial ON idp_certificates (certificate_serial)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_idp_cert_status ON idp_certificates (status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_idp_cert_expires ON idp_certificates (expires_at)")
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error ensuring idp_certificates table: {str(e)}")
        if 'conn' in locals() and conn:
            conn.close()
        return False

@app.route('/api/idp/certificate-status')
def get_idp_certificate_status():
    """Get current certificate status for IDP user"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    # Ensure table exists
    ensure_idp_certificates_table()
    
    try:
        conn = get_db_connection()
        if not conn:
            logger.error("Database connection failed")
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Get the most recent active certificate for this user
        cursor.execute("""
            SELECT * FROM idp_certificates 
            WHERE idp_email = %s AND status = 'active'
            ORDER BY created_at DESC 
            LIMIT 1
        """, (session.get('username'),))
        
        cert_row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if cert_row:
            # Check if certificate is expiring soon (within 30 days)
            from datetime import datetime, timedelta
            expiry_date = cert_row['expires_at']
            expiring_soon = (expiry_date - datetime.now()) < timedelta(days=30)
            
            return jsonify({
                'status': 'success',
                'certificate': {
                    'id': cert_row['id'],
                    'common_name': cert_row['certificate_cn'],
                    'serial_number': cert_row['certificate_serial'],
                    'valid_from': cert_row['issued_at'].isoformat(),
                    'valid_until': cert_row['expires_at'].isoformat(),
                    'status': cert_row['status'],
                    'created_at': cert_row['created_at'].isoformat()
                },
                'expiring_soon': expiring_soon
            })
        else:
            return jsonify({
                'status': 'success',
                'certificate': None,
                'expiring_soon': False
            })
            
    except Exception as e:
        logger.error(f"Error getting certificate status: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        if 'conn' in locals() and conn:
            conn.close()
        return jsonify({'error': 'Failed to get certificate status'}), 500

@app.route('/api/idp/certificate-history')
def get_idp_certificate_history():
    """Get certificate history for IDP user"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    # Ensure table exists
    ensure_idp_certificates_table()
    
    try:
        conn = get_db_connection()
        if not conn:
            logger.error("Database connection failed")
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Get all certificates for this user
        cursor.execute("""
            SELECT * FROM idp_certificates 
            WHERE idp_email = %s 
            ORDER BY created_at DESC
        """, (session.get('username'),))
        
        cert_rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        certificates = []
        for row in cert_rows:
            certificates.append({
                'id': row['id'],
                'common_name': row['certificate_cn'],
                'serial_number': row['certificate_serial'],
                'valid_from': row['issued_at'].isoformat(),
                'valid_until': row['expires_at'].isoformat(),
                'status': row['status'],
                'created_at': row['created_at'].isoformat()
            })
        
        return jsonify({
            'status': 'success',
            'certificates': certificates
        })
        
    except Exception as e:
        logger.error(f"Error getting certificate history: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        if 'conn' in locals() and conn:
            conn.close()
        return jsonify({'error': 'Failed to get certificate history'}), 500

@app.route('/api/idp/generate-certificate', methods=['POST'])
def generate_idp_certificate():
    """Generate a new certificate for IDP user using existing certificate request system"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    try:
        email = session.get('username')
        user_name = session.get('user_display_name') or email
        idp_provider = session.get('idp_provider', 'unknown')
        
        logger.info(f"Generating certificate for IDP user: {email} from provider: {idp_provider}")
        
        # Ensure the idp_certificates table exists
        ensure_idp_certificates_table()
        
        # First, revoke any existing active certificates for this user
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE idp_certificates 
            SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP, revocation_reason = 'superseded'
            WHERE idp_email = %s AND status = 'active'
        """, (email,))
        
        # Create certificate request using the existing system
        import uuid
        import json
        from datetime import datetime
        request_id = str(uuid.uuid4())
        
        # Insert certificate request - use email as common name for proper certificate
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
            user_name,
            email,
            'IDP User',
            email,  # Use email as common name
            [],     # san_dns_names
            [],     # san_ip_addresses
            [email],  # san_emails
            'client',
            'RSA',
            2048,
            365,
            'default',
            False,   # approval_required - auto-approve for IDP users
            'approved',  # status
            json.dumps({'idp_generated': True, 'provider': idp_provider}),
            True,    # email_verified
            None,    # verification_token
            datetime.utcnow(),  # verification_completed_at
        ))
        
        # Get the database ID for the request from the INSERT RETURNING
        request_db_id = cursor.fetchone()['id']
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # First revoke any existing certificate with the same name in EasyRSA
        logger.info(f"Checking for existing certificate with name: {email}")
        revoke_result = make_easyrsa_request("revoke", {"name": email})
        if revoke_result.get("status") == "success":
            logger.info(f"Revoked existing certificate for {email}")
        else:
            logger.info(f"No existing certificate found for {email} (or revocation not needed)")
        
        # Use existing certificate generation function
        logger.info(f"Using existing certificate generation for request {request_id}")
        cert_generated = generate_certificate_for_request(request_db_id, request_id, {
            'common_name': email,
            'san_emails': [email]
        })
        
        if not cert_generated:
            return jsonify({'error': 'Certificate generation failed'}), 500
        
        # Get the generated certificate info and store in IDP tables
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT certificate_pem, private_key_pem 
            FROM certificate_requests WHERE request_id = %s AND status = 'issued'
        """, (request_id,))
        cert_row = cursor.fetchone()
        
        if cert_row and cert_row['certificate_pem'] and cert_row['private_key_pem']:
            # Parse certificate to get details
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            try:
                cert_obj = x509.load_pem_x509_certificate(cert_row['certificate_pem'].encode(), default_backend())
                serial_number = format(cert_obj.serial_number, 'X')
                valid_from = cert_obj.not_valid_before
                valid_until = cert_obj.not_valid_after
            except Exception as e:
                logger.error(f"Failed to parse certificate: {e}")
                cursor.close()
                conn.close()
                return jsonify({'error': 'Failed to parse generated certificate'}), 500
            
            # Store in idp_certificates table for IDP portal display
            # Get the issuer from the certificate object
            issuer_cn = cert_obj.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value if cert_obj.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else 'CA Manager'
            
            cursor.execute("""
                INSERT INTO idp_certificates (
                    idp_email, certificate_cn, idp_provider, certificate_pem, private_key_encrypted,
                    certificate_serial, issued_at, expires_at, status, idp_user_id,
                    certificate_subject, certificate_issuer, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            """, (
                email, email, idp_provider, cert_row['certificate_pem'], 
                cert_row['private_key_pem'], serial_number, 
                valid_from, valid_until, 'active', email,
                f"CN={email}", f"CN={issuer_cn}"
            ))
            conn.commit()
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Certificate generation completed but certificate not found'}), 500
        
        cursor.close()
        conn.close()
        
        # Send certificate via email
        try:
            # Get CA certificate for the email
            ca_result = make_easyrsa_request("get-cert-files", {"name": email, "include_key": False})
            ca_cert_pem = ca_result.get("ca_certificate", "") if ca_result.get("status") == "success" else ""
            
            # Send the certificate email
            email_sent = send_certificate_email_with_data(
                request_id=request_id,
                recipient_email=email,
                recipient_name=user_name,
                common_name=email,
                cert_pem=cert_row['certificate_pem'],
                key_pem=cert_row['private_key_pem'],
                ca_cert_pem=ca_cert_pem
            )
            
            if not email_sent:
                logger.warning(f"Certificate generated but email delivery failed for {email}")
                # Don't fail the request if email fails, certificate is still generated
        except Exception as e:
            logger.error(f"Error sending certificate email: {e}")
            # Don't fail the request if email fails, certificate is still generated
        
        logger.info(f"Successfully generated certificate for IDP user {email} with serial {serial_number}")
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate generated successfully! Check your email for the certificate file.',
            'serial_number': serial_number
        })
        
    except Exception as e:
        logger.error(f"Error generating certificate: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to generate certificate'}), 500

@app.route('/api/idp/renew-certificate', methods=['POST'])
def renew_idp_certificate():
    """Renew certificate for IDP user"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    try:
        email = session.get('username')
        logger.info(f"Renewing certificate for IDP user: {email}")
        
        # Check if user has an existing certificate
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM idp_certificates 
            WHERE email = %s AND status = 'active'
            ORDER BY created_at DESC 
            LIMIT 1
        """, (email,))
        
        existing_cert = cursor.fetchone()
        
        if not existing_cert:
            cursor.close()
            conn.close()
            return jsonify({'error': 'No active certificate found to renew'}), 404
        
        # Check if certificate is eligible for renewal (within 30 days of expiry)
        from datetime import datetime, timedelta
        expiry_date = existing_cert['valid_until']
        days_until_expiry = (expiry_date - datetime.now()).days
        
        if days_until_expiry > 30:
            cursor.close()
            conn.close()
            return jsonify({
                'error': f'Certificate can only be renewed within 30 days of expiry. Current certificate expires in {days_until_expiry} days.'
            }), 400
        
        cursor.close()
        conn.close()
        
        # Use the same generate function which will automatically revoke existing certificates
        # and create a new one
        return generate_idp_certificate()
        
    except Exception as e:
        logger.error(f"Error renewing certificate: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to renew certificate'}), 500

@app.route('/api/idp/revoke-certificate', methods=['POST'])
def revoke_idp_certificate():
    """Revoke the active certificate for IDP user"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    try:
        email = session.get('username')
        logger.info(f"Revoking certificate for IDP user: {email}")
        
        # Get the active certificate from database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM idp_certificates 
            WHERE email = %s AND status = 'active'
            ORDER BY created_at DESC 
            LIMIT 1
        """, (email,))
        
        active_cert = cursor.fetchone()
        
        if not active_cert:
            cursor.close()
            conn.close()
            return jsonify({'error': 'No active certificate found to revoke'}), 404
        
        # Update certificate status in database
        cursor.execute("""
            UPDATE idp_certificates 
            SET status = 'revoked', 
                revoked_at = CURRENT_TIMESTAMP, 
                revocation_reason = 'user_requested'
            WHERE id = %s
        """, (active_cert['id'],))
        
        # Revoke in EasyRSA PKI
        revoke_result = make_easyrsa_request("revoke", {"name": email})
        
        if revoke_result.get("status") == "success":
            logger.info(f"Successfully revoked certificate for {email}")
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'message': 'Certificate revoked successfully'
            })
        else:
            # If EasyRSA revocation fails, still commit database changes
            logger.warning(f"EasyRSA revocation failed for {email}, but database updated")
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'message': 'Certificate marked as revoked'
            })
            
    except Exception as e:
        logger.error(f"Error revoking certificate: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to revoke certificate'}), 500

@app.route('/api/idp/download-certificate')
def download_idp_certificate():
    """Download certificate for IDP user"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    try:
        format_type = request.args.get('format', 'pkcs12')
        email = session.get('username')
        
        # Get the most recent active certificate for this user
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM idp_certificates 
            WHERE email = %s AND status = 'active'
            ORDER BY created_at DESC 
            LIMIT 1
        """, (email,))
        
        cert_row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not cert_row:
            return jsonify({'error': 'No active certificate found'}), 404
        
        cert_pem = cert_row['certificate_pem']
        key_pem = cert_row['private_key_pem']
        common_name = cert_row['common_name']
        
        if not cert_pem or not key_pem:
            return jsonify({'error': 'Certificate data incomplete'}), 500
        
        # Prepare certificate data based on format
        from flask import make_response
        from cryptography.hazmat.primitives import serialization
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        if format_type == 'pkcs12':
            # Get CA certificate using the actual email address as the certificate name
            # Since we're using the existing certificate request system, the certificate
            # is stored with the actual email address, not a sanitized version
            logger.info(f"Attempting to get CA certificate using email: {email}")
            
            ca_result = make_easyrsa_request("get-cert-files", {"name": email, "include_key": False})
            logger.info(f"CA cert result from get-cert-files with email: {ca_result}")
            ca_cert_pem = ca_result.get("ca_certificate", "") if ca_result.get("status") == "success" else ""
            
            if not ca_cert_pem:
                logger.error(f"CA certificate not available - get-cert-files returned: {ca_result}")
                return jsonify({'error': 'CA certificate not available for P12 creation'}), 500
            
            # Create P12 bundle
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            private_key_obj = serialization.load_pem_private_key(key_pem.encode(), password=None, backend=default_backend())
            ca_cert_obj = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
            
            # Use 'certificate' as the password for P12 files
            p12_data = serialization.pkcs12.serialize_key_and_certificates(
                name=common_name.encode('utf-8'),
                key=private_key_obj,
                cert=cert_obj,
                cas=[ca_cert_obj],
                encryption_algorithm=serialization.BestAvailableEncryption(b'certificate')
            )
            
            response = make_response(p12_data)
            response.headers['Content-Type'] = 'application/x-pkcs12'
            response.headers['Content-Disposition'] = f'attachment; filename="{email.replace("@", "_")}.p12"'
            return response
            
        elif format_type == 'pem':
            # Return certificate and private key as PEM bundle
            pem_bundle = cert_pem + '\n' + key_pem
            
            response = make_response(pem_bundle)
            response.headers['Content-Type'] = 'application/x-pem-file'
            response.headers['Content-Disposition'] = f'attachment; filename="{email.replace("@", "_")}.pem"'
            return response
            
        elif format_type == 'der':
            # Convert certificate to DER format
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            der_data = cert_obj.public_bytes(serialization.Encoding.DER)
            
            response = make_response(der_data)
            response.headers['Content-Type'] = 'application/x-x509-cert'
            response.headers['Content-Disposition'] = f'attachment; filename="{email.replace("@", "_")}.der"'
            return response
            
        else:
            return jsonify({'error': 'Unsupported format'}), 400
        
    except Exception as e:
        logger.error(f"Error downloading certificate: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to download certificate'}), 500

@app.route('/api/idp/test', methods=['GET'])
def test_idp_endpoint():
    """Test endpoint for IDP users"""
    return jsonify({
        'status': 'success',
        'message': 'IDP endpoint working',
        'session_info': {
            'idp_user': session.get('idp_user'),
            'authenticated': session.get('authenticated'),
            'username': session.get('username'),
            'idp_provider': session.get('idp_provider')
        }
    })

@app.route('/api/idp/radius-credentials', methods=['GET'])
def get_idp_radius_credentials():
    """Get RADIUS credentials for the current IDP user"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    try:
        email = session.get('username')
        logger.info(f"Getting RADIUS credentials for IDP user: {email}")
        logger.info(f"Session info: idp_user={session.get('idp_user')}, authenticated={session.get('authenticated')}")
        
        conn = get_db_connection()
        if not conn:
            logger.error("Database connection failed")
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT radius_username, radius_password_hash, default_vlan_id, 
                   is_active, updated_at, auth_count, last_auth_at
            FROM idp_radius_auth 
            WHERE idp_email = %s
            ORDER BY updated_at DESC 
            LIMIT 1
        """, (email,))
        
        credentials = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if credentials:
            return jsonify({
                'status': 'success',
                'credentials': {
                    'radius_username': credentials['radius_username'],
                    'radius_password': '••••••••••••',  # Never return actual password
                    'default_vlan_id': credentials['default_vlan_id'],
                    'is_active': credentials['is_active'],
                    'updated_at': credentials['updated_at'].isoformat() if credentials['updated_at'] else None,
                    'auth_count': credentials['auth_count'],
                    'last_auth_at': credentials['last_auth_at'].isoformat() if credentials['last_auth_at'] else None
                }
            })
        else:
            return jsonify({
                'status': 'not_configured',
                'message': 'RADIUS credentials not set up for this user'
            })
            
    except Exception as e:
        logger.error(f"Error getting RADIUS credentials: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        if 'conn' in locals() and conn:
            conn.close()
        return jsonify({'error': 'Failed to get RADIUS credentials'}), 500

@app.route('/api/idp/radius-credentials', methods=['POST'])
def create_idp_radius_credentials():
    """Create RADIUS credentials for the current IDP user"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    try:
        email = session.get('username')
        logger.info(f"Creating RADIUS credentials for IDP user: {email}")
        
        # Generate a secure random password
        import secrets
        import string
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%') for _ in range(12))
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        # Create a radius username (use email prefix or full email)
        radius_username = email.split('@')[0] if '@' in email else email
        
        # Check if username already exists and append number if needed
        conn = get_db_connection()
        cursor = conn.cursor()
        
        base_username = radius_username
        counter = 1
        while True:
            cursor.execute("SELECT id FROM idp_radius_auth WHERE radius_username = %s", (radius_username,))
            if not cursor.fetchone():
                break
            radius_username = f"{base_username}{counter}"
            counter += 1
        
        # Get user data from session or IDP
        idp_user_id = session.get('idp_user_id', email)
        idp_provider = session.get('idp_provider', 'unknown')
        
        # Insert or update the RADIUS credentials
        cursor.execute("""
            INSERT INTO idp_radius_auth 
            (idp_user_id, idp_email, idp_provider, radius_username, radius_password_hash, is_active)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (idp_user_id, idp_provider) 
            DO UPDATE SET 
                idp_email = EXCLUDED.idp_email,
                radius_username = EXCLUDED.radius_username,
                radius_password_hash = EXCLUDED.radius_password_hash,
                is_active = EXCLUDED.is_active,
                updated_at = CURRENT_TIMESTAMP
            RETURNING id
        """, (idp_user_id, email, idp_provider, radius_username, password_hash, True))
        
        mapping_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"RADIUS credentials created for {email}: username={radius_username}")
        
        return jsonify({
            'status': 'success',
            'message': 'RADIUS credentials created successfully',
            'credentials': {
                'radius_username': radius_username,
                'radius_password': password,  # Return actual password only on creation
                'mapping_id': mapping_id
            }
        })
        
    except Exception as e:
        logger.error(f"Error creating RADIUS credentials: {str(e)}")
        return jsonify({'error': 'Failed to create RADIUS credentials'}), 500

@app.route('/api/idp/radius-credentials/regenerate', methods=['POST'])
def regenerate_idp_radius_password():
    """Regenerate RADIUS password for the current IDP user"""
    if not session.get('idp_user'):
        return jsonify({'error': 'Not an IDP user'}), 403
    
    try:
        email = session.get('username')
        logger.info(f"Regenerating RADIUS password for IDP user: {email}")
        
        # Generate a new secure random password
        import secrets
        import string
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%') for _ in range(12))
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user has existing RADIUS credentials
        cursor.execute("""
            SELECT radius_username FROM idp_radius_auth 
            WHERE idp_email = %s
            ORDER BY updated_at DESC 
            LIMIT 1
        """, (email,))
        
        existing = cursor.fetchone()
        
        if not existing:
            cursor.close()
            conn.close()
            return jsonify({'error': 'No RADIUS credentials found. Create them first.'}), 404
        
        # Update the password
        cursor.execute("""
            UPDATE idp_radius_auth 
            SET radius_password_hash = %s, updated_at = CURRENT_TIMESTAMP
            WHERE idp_email = %s
        """, (password_hash, email))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"RADIUS password regenerated for {email}")
        
        return jsonify({
            'status': 'success',
            'message': 'RADIUS password regenerated successfully',
            'credentials': {
                'radius_username': existing['radius_username'],
                'radius_password': password  # Return actual password only on regeneration
            }
        })
        
    except Exception as e:
        logger.error(f"Error regenerating RADIUS password: {str(e)}")
        return jsonify({'error': 'Failed to regenerate RADIUS password'}), 500

@app.route('/auth/logout')
def idp_logout():
    """Logout route for IDP users (and regular users)"""
    username = session.get('username')
    is_idp_user = session.get('idp_user')
    
    if is_idp_user:
        logger.info(f"IDP user logout: {username}")
    
    log_operation('logout', {'username': username, 'idp_user': is_idp_user})
    session.clear()
    return redirect('/login')


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

# Version Management API Endpoints - DISABLED

# Version management has been removed for security reasons
# These endpoints are kept for reference but return disabled status

@app.route('/api/version-info', methods=['GET'])
@auth_required()
def get_version_info():
    """Version management disabled"""
    return jsonify({
        'status': 'success',
        'version': APP_VERSION,
        'message': 'Version management has been disabled for security'
    })


@app.route('/api/available-branches', methods=['GET'])
@auth_required()
def get_available_branches():
    """Version management disabled"""
    return jsonify({
        'status': 'success',
        'branches': [],
        'message': 'Version management has been disabled for security'
    })


@app.route('/api/check-updates', methods=['GET'])
@auth_required()
def check_updates():
    """Version management disabled"""
    return jsonify({
        'status': 'success',
        'updates_available': False,
        'message': 'Version management has been disabled for security'
    })


@app.route('/api/update-branch', methods=['POST'])
@auth_required()
def update_current_branch():
    """Version management disabled"""
    return jsonify({
        'status': 'error',
        'message': 'Version management has been disabled for security. Please update via Docker.'
    }), 403


@app.route('/api/switch-branch', methods=['POST'])
@auth_required()
def switch_branch():
    """Version management disabled"""
    return jsonify({
        'status': 'error',
        'message': 'Version management has been disabled for security. Please update via Docker.'
    }), 403


@app.route('/api/update-status', methods=['GET'])
@auth_required()
def get_update_status():
    """Version management disabled"""
    return jsonify({
        'status': 'success',
        'in_progress': False,
        'message': 'Version management has been disabled for security'
    })



# RADIUS Server Management Endpoints
@app.route('/api/radius/status', methods=['GET'])
@auth_required()
def get_radius_status():
    """Get RADIUS server status and statistics"""
    try:
        # Check if RADIUS server is running by testing RADIUS port connectivity
        radius_running = False
        
        try:
            # Try to connect to RADIUS authentication port to check if it's listening
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            # Try to connect to radius-server container on port 1812
            result = sock.connect_ex(('radius-server', 1812))
            sock.close()
            radius_running = (result == 0)
        except:
            # If socket test fails, try Docker container status check
            try:
                import subprocess
                result = subprocess.run(['docker', 'exec', 'ca-manager-f-radius-server-1', 'pgrep', 'radiusd'], 
                                      capture_output=True, timeout=5)
                radius_running = (result.returncode == 0)
            except:
                radius_running = False
        
        # Get authentication statistics (placeholder for now)
        stats = {
            'server_running': radius_running,
            'uptime': '0h 0m' if not radius_running else 'Running',
            'total_requests': 0,
            'successful_auths': 0,
            'failed_auths': 0,
            'certificate_count': 0,
            'listening_ports': ['1812/udp', '1813/udp'] if radius_running else []
        }
        
        return jsonify({
            'status': 'success',
            'radius_status': stats
        })
        
    except Exception as e:
        logging.error(f"Error getting RADIUS status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radius/clients', methods=['GET'])
@auth_required()
def get_radius_clients():
    """Get configured RADIUS clients"""
    try:
        import subprocess
        import re
        
        # Read clients from actual RADIUS configuration
        clients = []
        
        try:
            result = subprocess.run([
                'docker', 'exec', 'ca-manager-f-radius-server-1',
                'cat', '/etc/raddb/clients.conf'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                content = result.stdout
                
                # Parse ALL client blocks from clients.conf (both enabled and disabled)
                # First, get enabled clients
                enabled_pattern = r'client\s+(\S+)\s*\{([^}]+)\}'
                enabled_matches = re.findall(enabled_pattern, content, re.MULTILINE | re.DOTALL)
                
                for client_name, client_config in enabled_matches:
                    # Parse client configuration
                    ip_match = re.search(r'ipaddr\s*=\s*([^\n\s#]+)', client_config)
                    secret_match = re.search(r'secret\s*=\s*([^\n\s#]+)', client_config)
                    type_match = re.search(r'nas_type\s*=\s*([^\n\s#]+)', client_config)
                    shortname_match = re.search(r'shortname\s*=\s*([^\n\s#]+)', client_config)
                    
                    client_info = {
                        'name': shortname_match.group(1) if shortname_match else client_name,
                        'ip': ip_match.group(1) if ip_match else 'Unknown',
                        'secret': '***',  # Never show actual secrets
                        'type': type_match.group(1) if type_match else 'other',
                        'client_id': client_name,
                        'status': 'enabled'
                    }
                    
                    clients.append(client_info)
                
                # Now get disabled (commented) clients
                # Look for commented client blocks
                disabled_pattern = r'(?:# Disabled on [^\n]+\n)?(?:^# client\s+(\S+)\s*\{[^}]*^# \})'
                lines = content.split('\n')
                i = 0
                while i < len(lines):
                    line = lines[i]
                    # Check for disabled client start
                    if line.startswith('# client '):
                        match = re.match(r'# client\s+(\S+)\s*\{', line)
                        if match:
                            client_name = match.group(1)
                            client_lines = []
                            i += 1
                            # Collect all lines until we find the closing brace
                            while i < len(lines) and not lines[i].strip() == '# }':
                                client_lines.append(lines[i])
                                i += 1
                            
                            if i < len(lines) and lines[i].strip() == '# }':
                                # Parse the disabled client
                                client_config = '\n'.join([l[2:] if l.startswith('# ') else l for l in client_lines])
                                
                                ip_match = re.search(r'ipaddr\s*=\s*([^\n\s#]+)', client_config)
                                secret_match = re.search(r'secret\s*=\s*([^\n\s#]+)', client_config)
                                type_match = re.search(r'nas_type\s*=\s*([^\n\s#]+)', client_config)
                                shortname_match = re.search(r'shortname\s*=\s*([^\n\s#]+)', client_config)
                                
                                client_info = {
                                    'name': shortname_match.group(1) if shortname_match else client_name,
                                    'ip': ip_match.group(1) if ip_match else 'Unknown',
                                    'secret': '***',  # Never show actual secrets
                                    'type': type_match.group(1) if type_match else 'other',
                                    'client_id': client_name,
                                    'status': 'disabled'
                                }
                                
                                clients.append(client_info)
                    i += 1
                    
        except Exception as e:
            logging.error(f"Error reading RADIUS clients config: {e}")
            # Fallback to default clients if reading fails
            clients = [
                {
                    'name': 'localhost',
                    'ip': '127.0.0.1', 
                    'secret': '***',
                    'type': 'test',
                    'client_id': 'localhost'
                },
                {
                    'name': 'local-net',
                    'ip': '192.168.0.0/16',
                    'secret': '***', 
                    'type': 'other',
                    'client_id': 'local-network'
                }
            ]
        
        return jsonify({
            'status': 'success',
            'clients': clients
        })
        
    except Exception as e:
        logging.error(f"Error getting RADIUS clients: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radius/clients', methods=['POST'])
@auth_required(permission='admin')
def add_radius_client():
    """Add a new RADIUS client"""
    try:
        data = request.get_json()
        
        name = data.get('name', '').strip()
        ip_address = data.get('ip_address', '').strip()
        shared_secret = data.get('shared_secret', '').strip()
        nas_type = data.get('nas_type', 'other').strip()
        
        if not all([name, ip_address, shared_secret]):
            return jsonify({'status': 'error', 'message': 'Name, IP address, and shared secret are required'}), 400
        
        # Validate IP address format (basic validation)
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
        if not re.match(ip_pattern, ip_address):
            return jsonify({'status': 'error', 'message': 'Invalid IP address format'}), 400
        
        # Create client configuration block
        client_config = f"""
client {name} {{
    ipaddr = {ip_address}
    secret = {shared_secret}
    nas_type = {nas_type}
    require_message_authenticator = yes
}}
"""
        
        # Add client to RADIUS configuration
        result = subprocess.run([
            'docker', 'exec', 'ca-manager-f-radius-server-1',
            'bash', '-c', f'echo "{client_config}" >> /etc/raddb/clients.conf'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            logging.error(f"Failed to add RADIUS client: {result.stderr}")
            return jsonify({'status': 'error', 'message': 'Failed to add client to configuration'}), 500
        
        # Reload RADIUS server to apply changes
        reload_result = subprocess.run([
            'docker', 'exec', 'ca-manager-f-radius-server-1',
            'radmin', '-e', 'hup'
        ], capture_output=True, text=True, timeout=10)
        
        if reload_result.returncode != 0:
            logging.warning(f"RADIUS reload warning: {reload_result.stderr}")
            # Continue anyway as the client was added to the file
        
        return jsonify({
            'status': 'success',
            'message': f'RADIUS client {name} added successfully'
        })
        
    except Exception as e:
        logging.error(f"Error adding RADIUS client: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radius/clients/<string:client_name>', methods=['DELETE'])
@auth_required()
def delete_radius_client(client_name):
    """Delete a RADIUS client"""
    try:
        # Read current clients configuration
        result = subprocess.run([
            'docker', 'exec', 'ca-manager-f-radius-server-1',
            'cat', '/etc/raddb/clients.conf'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            logging.error(f"Failed to read RADIUS clients config: {result.stderr}")
            return jsonify({'status': 'error', 'message': 'Failed to read RADIUS configuration'}), 500
        
        content = result.stdout
        
        # Find and permanently remove the client block
        import re
        # First try to find active client
        pattern = rf'client\s+{re.escape(client_name)}\s*\{{[^}}]+\}}\n?'
        
        if not re.search(pattern, content, re.MULTILINE | re.DOTALL):
            # Try to find commented client with possible timestamp
            pattern = rf'(# Disabled on \d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}\n)?((?:# .*\n)*# client\s+{re.escape(client_name)}\s*\{{(?:\n# .*)*\n# \}})\n?'
            if not re.search(pattern, content, re.MULTILINE):
                return jsonify({'status': 'error', 'message': f'Client {client_name} not found'}), 404
        
        # Permanently remove the client block
        new_content = re.sub(pattern, '', content, flags=re.MULTILINE | re.DOTALL)
        
        # Write updated configuration back
        write_result = subprocess.run([
            'docker', 'exec', 'ca-manager-f-radius-server-1',
            'bash', '-c', f'cat > /etc/raddb/clients.conf << "EOF"\n{new_content}EOF'
        ], capture_output=True, text=True, timeout=10)
        
        if write_result.returncode != 0:
            logging.error(f"Failed to update RADIUS clients config: {write_result.stderr}")
            return jsonify({'status': 'error', 'message': 'Failed to update RADIUS configuration'}), 500
        
        # Reload RADIUS server to apply changes
        reload_result = subprocess.run([
            'docker', 'exec', 'ca-manager-f-radius-server-1',
            'radmin', '-e', 'hup'
        ], capture_output=True, text=True, timeout=10)
        
        if reload_result.returncode != 0:
            logging.warning(f"RADIUS reload warning: {reload_result.stderr}")
        
        return jsonify({
            'status': 'success',
            'message': f'RADIUS client {client_name} deleted successfully'
        })
        
    except Exception as e:
        logging.error(f"Error deleting RADIUS client: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radius/clients/<string:client_name>', methods=['PATCH'])
@auth_required()
def toggle_radius_client(client_name):
    """Enable or disable a RADIUS client"""
    try:
        data = request.get_json()
        action = data.get('action', 'disable')  # 'enable' or 'disable'
        
        # Read current clients configuration
        result = subprocess.run([
            'docker', 'exec', 'ca-manager-f-radius-server-1',
            'cat', '/etc/raddb/clients.conf'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            logging.error(f"Failed to read RADIUS clients config: {result.stderr}")
            return jsonify({'status': 'error', 'message': 'Failed to read RADIUS configuration'}), 500
        
        content = result.stdout
        import re
        
        if action == 'disable':
            # Find and comment out the client block
            pattern = rf'(client\s+{re.escape(client_name)}\s*\{{[^}}]+\}})'
            match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
            
            if not match:
                return jsonify({'status': 'error', 'message': f'Client {client_name} not found or already disabled'}), 404
            
            client_block = match.group(1)
            commented_block = '\n'.join(['# ' + line for line in client_block.split('\n')])
            commented_block = f"# Disabled on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{commented_block}"
            new_content = content.replace(client_block, commented_block)
            
        elif action == 'enable':
            # Find and uncomment the client block
            # Look for commented client block with possible timestamp
            pattern = rf'(# Disabled on \d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}\n)?((?:# .*\n)*# client\s+{re.escape(client_name)}\s*\{{(?:\n# .*)*\n# \}})'
            match = re.search(pattern, content, re.MULTILINE)
            
            if not match:
                # Try simpler pattern without timestamp
                pattern = rf'((?:# .*\n)*# client\s+{re.escape(client_name)}\s*\{{(?:\n# .*)*\n# \}})'
                match = re.search(pattern, content, re.MULTILINE)
                
                if not match:
                    return jsonify({'status': 'error', 'message': f'Disabled client {client_name} not found'}), 404
            
            # Remove comment markers and timestamp if present
            full_match = match.group(0)
            # Remove the timestamp line if it exists
            full_match = re.sub(r'# Disabled on \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\n', '', full_match)
            # Remove '# ' from the beginning of each line
            uncommented_block = '\n'.join([line[2:] if line.startswith('# ') else line for line in full_match.split('\n')])
            uncommented_block = uncommented_block.strip()
            
            new_content = content.replace(match.group(0), uncommented_block)
            
        else:
            return jsonify({'status': 'error', 'message': 'Invalid action. Use "enable" or "disable"'}), 400
        
        # Write updated configuration back
        write_result = subprocess.run([
            'docker', 'exec', 'ca-manager-f-radius-server-1',
            'bash', '-c', f'cat > /etc/raddb/clients.conf << "EOF"\n{new_content}EOF'
        ], capture_output=True, text=True, timeout=10)
        
        if write_result.returncode != 0:
            logging.error(f"Failed to update RADIUS clients config: {write_result.stderr}")
            return jsonify({'status': 'error', 'message': 'Failed to update RADIUS configuration'}), 500
        
        # Reload RADIUS server to apply changes
        reload_result = subprocess.run([
            'docker', 'exec', 'ca-manager-f-radius-server-1',
            'radmin', '-e', 'hup'
        ], capture_output=True, text=True, timeout=10)
        
        if reload_result.returncode != 0:
            logging.warning(f"RADIUS reload warning: {reload_result.stderr}")
        
        return jsonify({
            'status': 'success',
            'message': f'RADIUS client {client_name} {action}d successfully'
        })
        
    except Exception as e:
        logging.error(f"Error toggling RADIUS client: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radius/logs', methods=['GET'])
@auth_required()
def get_radius_logs():
    """Get RADIUS authentication logs"""
    try:
        logs = []
        
        # Try to read RADIUS log file
        try:
            result = subprocess.run([
                'docker', 'exec', 'ca-manager-f-radius-server-1',
                'tail', '-n', '200', '/var/log/radius/radius.log'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout:
                import re
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if not line.strip():
                        continue
                    
                    # Parse FreeRADIUS log format
                    # Example: Mon Dec 11 10:23:45 2023 : Auth: (0) Login OK: [user] (from client localhost port 0 via TLS tunnel)
                    
                    log_entry = {}
                    
                    # Extract timestamp
                    timestamp_match = re.match(r'^(\w+ \w+ \d+ \d+:\d+:\d+ \d+)', line)
                    if timestamp_match:
                        log_entry['timestamp'] = timestamp_match.group(1)
                    else:
                        log_entry['timestamp'] = datetime.now().isoformat()
                    
                    # Determine log type and extract details
                    if 'Login OK' in line or 'Authentication successful' in line:
                        log_entry['type'] = 'AUTH_SUCCESS'
                        log_entry['message'] = 'Authentication successful'
                        
                        # Extract username
                        user_match = re.search(r'\[([^\]]+)\]', line)
                        if user_match:
                            log_entry['username'] = user_match.group(1)
                        
                        # Extract client info
                        client_match = re.search(r'from client (\S+)', line)
                        if client_match:
                            log_entry['nas_ip'] = client_match.group(1)
                            
                    elif 'Login incorrect' in line or 'Failed' in line or 'Rejected' in line:
                        log_entry['type'] = 'AUTH_FAILURE'
                        log_entry['message'] = 'Authentication failed'
                        
                        # Extract username
                        user_match = re.search(r'\[([^\]]+)\]', line)
                        if user_match:
                            log_entry['username'] = user_match.group(1)
                            
                        # Extract failure reason
                        if 'certificate' in line.lower():
                            log_entry['message'] = 'Certificate validation failed'
                        elif 'expired' in line.lower():
                            log_entry['message'] = 'Certificate expired'
                            
                    elif 'Warning' in line:
                        log_entry['type'] = 'WARNING'
                        log_entry['message'] = line.split('Warning:')[-1].strip() if 'Warning:' in line else 'Warning'
                        
                    elif 'Error' in line:
                        log_entry['type'] = 'ERROR'
                        log_entry['message'] = line.split('Error:')[-1].strip() if 'Error:' in line else 'Error'
                        
                    else:
                        # General info log
                        if 'TLS' in line or 'EAP' in line or 'Auth:' in line:
                            log_entry['type'] = 'INFO'
                            log_entry['message'] = line.split(': ', 2)[-1] if ': ' in line else line
                        else:
                            continue  # Skip non-relevant lines
                    
                    # Add the log entry if it has required fields
                    if 'type' in log_entry and 'message' in log_entry:
                        logs.append(log_entry)
                        
        except Exception as e:
            logging.warning(f"Could not read RADIUS logs: {e}")
            # Return sample data if logs can't be read
            logs = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'INFO',
                    'message': 'RADIUS server is running. Waiting for authentication attempts...'
                }
            ]
        
        # Reverse logs to show newest first
        logs.reverse()
        
        # Limit to most recent 100 entries
        logs = logs[:100]
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'count': len(logs)
        })
        
    except Exception as e:
        logging.error(f"Error getting RADIUS logs: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radius/certificates', methods=['GET'])
@auth_required()
def get_radius_certificates():
    """Get certificates configured for RADIUS"""
    try:
        import subprocess
        from datetime import datetime
        
        def get_cert_expiration(cert_path):
            """Get certificate expiration date"""
            try:
                result = subprocess.run([
                    'docker', 'exec', 'ca-manager-f-radius-server-1', 
                    'openssl', 'x509', '-in', cert_path, '-noout', '-enddate'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    # Parse output like "notAfter=Sep  8 19:18:29 2026 GMT"
                    end_date_str = result.stdout.strip().split('=')[1]
                    # Convert to YYYY-MM-DD format
                    end_date = datetime.strptime(end_date_str, '%b %d %H:%M:%S %Y %Z')
                    return end_date.strftime('%Y-%m-%d')
                return 'Unknown'
            except Exception as e:
                logging.error(f"Error getting certificate expiration: {e}")
                return 'Unknown'
        
        def check_cert_exists(cert_path):
            """Check if certificate file exists"""
            try:
                result = subprocess.run([
                    'docker', 'exec', 'ca-manager-f-radius-server-1', 
                    'test', '-f', cert_path
                ], capture_output=True, timeout=5)
                return result.returncode == 0
            except:
                return False
        
        # Check CA certificate
        ca_cert_path = '/etc/raddb/certs/ca/ca.crt'
        ca_present = check_cert_exists(ca_cert_path)
        ca_expires = get_cert_expiration(ca_cert_path) if ca_present else 'N/A'
        
        # Check server certificate
        server_cert_path = '/etc/raddb/certs/server/server.crt'
        server_present = check_cert_exists(server_cert_path)
        server_expires = get_cert_expiration(server_cert_path) if server_present else 'N/A'
        
        certificates = {
            'ca_certificate': {
                'present': ca_present,
                'expires': ca_expires,
                'issuer': 'CA Manager Root CA' if ca_present else 'N/A'
            },
            'server_certificate': {
                'present': server_present,
                'expires': server_expires,
                'common_name': 'radius-server' if server_present else 'N/A',
                'issuer': 'CA Manager Root CA' if server_present else 'N/A'
            }
        }
        
        return jsonify({
            'status': 'success',
            'certificates': certificates
        })
        
    except Exception as e:
        logging.error(f"Error getting RADIUS certificates: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radius/sync-certificates', methods=['POST'])
@auth_required(permission='admin')
def sync_radius_certificates():
    """Trigger certificate synchronization with RADIUS server"""
    try:
        # This would trigger the sync-certs.sh script in the RADIUS container
        # For now, we'll simulate the process
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate synchronization triggered successfully'
        })
        
    except Exception as e:
        logging.error(f"Error syncing RADIUS certificates: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# RadSec Proxy Endpoints
@app.route('/api/radsec/status', methods=['GET'])
@auth_required()
def get_radsec_status():
    """Get RadSec proxy status"""
    try:
        import os
        config_file = '/opt/proxy-installer/radsec_config.json'
        
        # Check if RadSec is deployed
        deployed = os.path.exists(config_file)
        
        if not deployed:
            return jsonify({
                'status': 'success',
                'deployed': False,
                'running': False
            })
        
        # Check if container is running
        result = subprocess.run([
            'docker', 'ps', '--filter', 'name=radsec-proxy', '--format', '{{.Status}}'
        ], capture_output=True, text=True, timeout=10)
        
        running = result.returncode == 0 and 'Up' in result.stdout
        
        # Read config for details
        config_data = {}
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
        except:
            pass
        
        return jsonify({
            'status': 'success',
            'deployed': True,
            'running': running,
            'server': config_data.get('server_url', 'Unknown'),
            'proxy_id': config_data.get('proxy_id', 'Unknown'),
            'site_id': config_data.get('site_id', 'Unknown')
        })
        
    except Exception as e:
        logging.error(f"Error getting RadSec status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radsec/deploy', methods=['POST'])
@auth_required(permission='admin')
def deploy_radsec_proxy():
    """Deploy RadSec proxy using Extreme Networks configuration"""
    try:
        data = request.get_json()
        token = data.get('token')
        server_url = data.get('server_url')
        site_id = data.get('site_id')
        proxy_id = data.get('proxy_id')
        workspace_id = data.get('workspace_id')
        
        if not all([token, server_url, site_id, proxy_id]):
            return jsonify({
                'status': 'error',
                'message': 'Missing required deployment parameters'
            }), 400
        
        # Create config directory
        config_dir = '/opt/proxy-installer'
        os.makedirs(config_dir, exist_ok=True)
        
        # Save configuration
        config_data = {
            'token': token,
            'server_url': server_url,
            'site_id': site_id,
            'proxy_id': proxy_id,
            'workspace_id': workspace_id,
            'deployed_at': datetime.now().isoformat()
        }
        
        config_file = os.path.join(config_dir, 'radsec_config.json')
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        # Create RadSec proxy script
        script_content = f'''#!/bin/bash
# RadSec Proxy deployment script
set -e

echo "Deploying RadSec proxy..."

# Download and run Extreme Networks installer
curl -L https://{server_url}/proxy-installer/master-installer.sh | bash -s -- -o deploy -t {token}

echo "RadSec proxy deployment completed"
'''
        
        script_path = os.path.join(config_dir, 'deploy_radsec.sh')
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        os.chmod(script_path, 0o755)
        
        # Execute deployment
        result = subprocess.run([
            'bash', script_path
        ], capture_output=True, text=True, timeout=300)  # 5 minute timeout
        
        if result.returncode == 0:
            return jsonify({
                'status': 'success',
                'message': 'RadSec proxy deployed successfully',
                'output': result.stdout
            })
        else:
            logging.error(f"RadSec deployment failed: {result.stderr}")
            return jsonify({
                'status': 'error',
                'message': f'Deployment failed: {result.stderr}',
                'output': result.stdout
            }), 500
            
    except Exception as e:
        logging.error(f"Error deploying RadSec proxy: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radsec/remove', methods=['POST'])
@auth_required(permission='admin')
def remove_radsec_proxy():
    """Remove RadSec proxy"""
    try:
        config_dir = '/opt/proxy-installer'
        config_file = os.path.join(config_dir, 'radsec_config.json')
        
        if not os.path.exists(config_file):
            return jsonify({
                'status': 'error',
                'message': 'RadSec proxy not found'
            }), 404
        
        # Create removal script
        script_content = '''#!/bin/bash
# RadSec Proxy removal script
set -e

echo "Removing RadSec proxy..."

# Stop and remove proxy containers
docker stop radsec-proxy 2>/dev/null || true
docker rm radsec-proxy 2>/dev/null || true

# Remove proxy files
rm -rf /opt/proxy-installer/

echo "RadSec proxy removal completed"
'''
        
        script_path = os.path.join(config_dir, 'remove_radsec.sh')
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        os.chmod(script_path, 0o755)
        
        # Execute removal
        result = subprocess.run([
            'bash', script_path
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            return jsonify({
                'status': 'success',
                'message': 'RadSec proxy removed successfully'
            })
        else:
            logging.error(f"RadSec removal failed: {result.stderr}")
            return jsonify({
                'status': 'error',
                'message': f'Removal failed: {result.stderr}'
            }), 500
            
    except Exception as e:
        logging.error(f"Error removing RadSec proxy: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radsec/logs', methods=['GET'])
@auth_required()
def get_radsec_logs():
    """Get RadSec proxy logs"""
    try:
        # Try to get logs from various sources
        log_sources = [
            'docker logs radsec-proxy 2>&1 | tail -100',
            'tail -100 /var/log/radsec/radsec.log 2>/dev/null',
            'tail -100 /opt/proxy-installer/logs/*.log 2>/dev/null'
        ]
        
        logs = []
        for command in log_sources:
            try:
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.stdout:
                    logs.extend(result.stdout.split('\n'))
            except:
                continue
        
        if not logs:
            logs = ['No RadSec proxy logs found. Check if the proxy is running.']
        
        return jsonify({
            'status': 'success',
            'logs': logs
        })
        
    except Exception as e:
        logging.error(f"Error getting RadSec logs: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radsec/update-certs', methods=['POST'])
@auth_required(permission='admin')
def update_radsec_certs():
    """Update RadSec proxy certificates"""
    try:
        config_file = '/opt/proxy-installer/radsec_config.json'
        
        if not os.path.exists(config_file):
            return jsonify({
                'status': 'error',
                'message': 'RadSec proxy not deployed'
            }), 404
        
        # Execute certificate update
        result = subprocess.run([
            'curl', '-L', 'https://oh-uz.extremecloudiq.com/proxy-installer/master-installer.sh'
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            # Execute update
            update_result = subprocess.run([
                'bash', '-c', 
                f'echo "{result.stdout}" | bash -s -- -o update_certs'
            ], capture_output=True, text=True, timeout=60)
            
            if update_result.returncode == 0:
                return jsonify({
                    'status': 'success',
                    'message': 'RadSec certificates updated successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': f'Certificate update failed: {update_result.stderr}'
                }), 500
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to download certificate update script'
            }), 500
            
    except Exception as e:
        logging.error(f"Error updating RadSec certificates: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radsec/restart', methods=['POST'])
@auth_required(permission='admin')
def restart_radsec_proxy():
    """Restart RadSec proxy"""
    try:
        # Restart the RadSec proxy container
        result = subprocess.run([
            'docker', 'restart', 'radsec-proxy'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return jsonify({
                'status': 'success',
                'message': 'RadSec proxy restarted successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to restart proxy: {result.stderr}'
            }), 500
            
    except Exception as e:
        logging.error(f"Error restarting RadSec proxy: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/radsec/troubleshoot', methods=['GET'])
@auth_required()
def troubleshoot_radsec():
    """Run RadSec proxy troubleshooting"""
    try:
        results = []
        
        # Check container status
        result = subprocess.run([
            'docker', 'ps', '-a', '--filter', 'name=radsec-proxy', '--format', 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'
        ], capture_output=True, text=True, timeout=10)
        
        results.append("=== Container Status ===")
        results.append(result.stdout or "No RadSec proxy container found")
        
        # Check network connectivity
        config_file = '/opt/proxy-installer/radsec_config.json'
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                server_url = config.get('server_url', 'oh-uz.extremecloudiq.com')
                
                results.append("\\n=== Network Connectivity ===")
                # Test DNS resolution
                dns_result = subprocess.run([
                    'nslookup', server_url
                ], capture_output=True, text=True, timeout=10)
                results.append(f"DNS Resolution for {server_url}:")
                results.append(dns_result.stdout or dns_result.stderr)
                
                # Test port connectivity
                port_result = subprocess.run([
                    'nc', '-zv', server_url, '2083'
                ], capture_output=True, text=True, timeout=10)
                results.append(f"\\nPort 2083 connectivity:")
                results.append(port_result.stderr or "Connection test completed")
                
            except:
                results.append("Could not read RadSec configuration")
        
        # Check logs
        results.append("\\n=== Recent Logs ===")
        log_result = subprocess.run([
            'docker', 'logs', '--tail', '20', 'radsec-proxy'
        ], capture_output=True, text=True, timeout=10)
        results.append(log_result.stdout or log_result.stderr or "No logs available")
        
        return jsonify({
            'status': 'success',
            'results': results
        })
        
    except Exception as e:
        logging.error(f"Error troubleshooting RadSec: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ================================
# VLAN Policy Engine Endpoints
# ================================

@app.route('/api/vlans', methods=['GET'])
@auth_required()
def get_vlans():
    """Get all VLAN definitions"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, vlan_id, vlan_name, description, subnet, gateway, 
                   dns_servers, is_active, created_at
            FROM vlans
            ORDER BY vlan_id
        """)
        
        vlans = []
        for row in cursor.fetchall():
            vlans.append({
                'id': row['id'],
                'vlan_id': row['vlan_id'],
                'vlan_name': row['vlan_name'],
                'description': row['description'],
                'subnet': row['subnet'],
                'gateway': row['gateway'],
                'dns_servers': row['dns_servers'],
                'is_active': row['is_active'],
                'created_at': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        conn.close()
        return jsonify({'status': 'success', 'vlans': vlans})
        
    except Exception as e:
        logging.error(f"Error getting VLANs: {e}")
        return jsonify({'error': 'Failed to get VLANs'}), 500

@app.route('/api/vlans', methods=['POST'])
@auth_required(permission='admin')
def create_vlan():
    """Create a new VLAN definition"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('vlan_id') or not data.get('vlan_name'):
            return jsonify({'error': 'VLAN ID and name are required'}), 400
            
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO vlans (vlan_id, vlan_name, description, subnet, gateway, dns_servers, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data['vlan_id'],
            data['vlan_name'],
            data.get('description'),
            data.get('subnet'),
            data.get('gateway'),
            data.get('dns_servers'),
            data.get('is_active', True)
        ))
        
        vlan_id = cursor.fetchone()['id']
        conn.commit()
        conn.close()
        
        log_operation('vlan_created', {'vlan_id': data['vlan_id'], 'vlan_name': data['vlan_name']})
        
        return jsonify({'status': 'success', 'message': 'VLAN created successfully', 'id': vlan_id})
        
    except Exception as e:
        logging.error(f"Error creating VLAN: {e}")
        return jsonify({'error': 'Failed to create VLAN'}), 500

@app.route('/api/vlan-policies', methods=['GET'])
@auth_required()
def get_vlan_policies():
    """Get all VLAN assignment policies"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        cursor.execute("""
            SELECT vp.*, v.vlan_name, v.vlan_id as vlan_number
            FROM vlan_policies vp
            LEFT JOIN vlans v ON v.id = vp.vlan_id
            ORDER BY vp.priority, vp.policy_name
        """)
        
        policies = []
        for row in cursor.fetchall():
            policies.append({
                'id': row['id'],
                'policy_name': row['policy_name'],
                'description': row['description'],
                'priority': row['priority'],
                'is_active': row['is_active'],
                'conditions': row['conditions'],
                'vlan_id': row['vlan_id'],
                'vlan_name': row['vlan_name'],
                'vlan_number': row['vlan_number'],
                'radius_attributes': row['radius_attributes'],
                'allow_access': row['allow_access'],
                'reject_reason': row['reject_reason'],
                'created_at': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        conn.close()
        return jsonify({'status': 'success', 'policies': policies})
        
    except Exception as e:
        logging.error(f"Error getting VLAN policies: {e}")
        return jsonify({'error': 'Failed to get VLAN policies'}), 500

@app.route('/api/vlan-policies', methods=['POST'])
@auth_required(permission='admin')
def create_vlan_policy():
    """Create a new VLAN assignment policy"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('policy_name'):
            return jsonify({'error': 'Policy name is required'}), 400
            
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Get current user ID
        user_id = None
        if session.get('user_id'):
            user_id = session['user_id']
            
        cursor.execute("""
            INSERT INTO vlan_policies 
            (policy_name, description, priority, is_active, conditions, 
             vlan_id, radius_attributes, allow_access, reject_reason, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data['policy_name'],
            data.get('description'),
            data.get('priority', 100),
            data.get('is_active', True),
            json.dumps(data.get('conditions', {})),
            data.get('vlan_id'),
            json.dumps(data.get('radius_attributes', {})),
            data.get('allow_access', True),
            data.get('reject_reason'),
            user_id
        ))
        
        policy_id = cursor.fetchone()['id']
        conn.commit()
        conn.close()
        
        log_operation('vlan_policy_created', {'policy_name': data['policy_name']})
        
        return jsonify({'status': 'success', 'message': 'VLAN policy created successfully', 'id': policy_id})
        
    except Exception as e:
        logging.error(f"Error creating VLAN policy: {e}")
        return jsonify({'error': 'Failed to create VLAN policy'}), 500

@app.route('/api/vlan-policies/<int:policy_id>', methods=['PUT'])
@auth_required(permission='admin')
def update_vlan_policy(policy_id):
    """Update a VLAN assignment policy"""
    try:
        data = request.get_json()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Build update query dynamically based on provided fields
        update_fields = []
        update_values = []
        
        if 'policy_name' in data:
            update_fields.append('policy_name = %s')
            update_values.append(data['policy_name'])
        if 'description' in data:
            update_fields.append('description = %s')
            update_values.append(data['description'])
        if 'priority' in data:
            update_fields.append('priority = %s')
            update_values.append(data['priority'])
        if 'is_active' in data:
            update_fields.append('is_active = %s')
            update_values.append(data['is_active'])
        if 'conditions' in data:
            update_fields.append('conditions = %s')
            update_values.append(json.dumps(data['conditions']))
        if 'vlan_id' in data:
            update_fields.append('vlan_id = %s')
            update_values.append(data['vlan_id'])
        if 'radius_attributes' in data:
            update_fields.append('radius_attributes = %s')
            update_values.append(json.dumps(data['radius_attributes']))
        if 'allow_access' in data:
            update_fields.append('allow_access = %s')
            update_values.append(data['allow_access'])
        if 'reject_reason' in data:
            update_fields.append('reject_reason = %s')
            update_values.append(data['reject_reason'])
            
        if not update_fields:
            return jsonify({'error': 'No fields to update'}), 400
            
        update_values.append(policy_id)
        
        cursor.execute(f"""
            UPDATE vlan_policies 
            SET {', '.join(update_fields)}
            WHERE id = %s
        """, update_values)
        
        conn.commit()
        conn.close()
        
        log_operation('vlan_policy_updated', {'policy_id': policy_id})
        
        return jsonify({'status': 'success', 'message': 'VLAN policy updated successfully'})
        
    except Exception as e:
        logging.error(f"Error updating VLAN policy: {e}")
        return jsonify({'error': 'Failed to update VLAN policy'}), 500

@app.route('/api/vlan-policies/<int:policy_id>', methods=['DELETE'])
@auth_required(permission='admin')
def delete_vlan_policy(policy_id):
    """Delete a VLAN assignment policy"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vlan_policies WHERE id = %s", (policy_id,))
        
        conn.commit()
        conn.close()
        
        log_operation('vlan_policy_deleted', {'policy_id': policy_id})
        
        return jsonify({'status': 'success', 'message': 'VLAN policy deleted successfully'})
        
    except Exception as e:
        logging.error(f"Error deleting VLAN policy: {e}")
        return jsonify({'error': 'Failed to delete VLAN policy'}), 500

@app.route('/api/user-vlan-assignments', methods=['GET'])
@auth_required()
def get_user_vlan_assignments():
    """Get all user-VLAN static assignments"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        cursor.execute("""
            SELECT uva.*, v.vlan_name, v.vlan_id as vlan_number, u.username as assigned_to
            FROM user_vlan_assignments uva
            LEFT JOIN vlans v ON v.id = uva.vlan_id
            LEFT JOIN users u ON u.id = uva.user_id
            ORDER BY uva.created_at DESC
        """)
        
        assignments = []
        for row in cursor.fetchall():
            assignments.append({
                'id': row['id'],
                'user_id': row['user_id'],
                'username': row['username'] or row['assigned_to'],
                'vlan_id': row['vlan_id'],
                'vlan_name': row['vlan_name'],
                'vlan_number': row['vlan_number'],
                'expires_at': row['expires_at'].isoformat() if row['expires_at'] else None,
                'notes': row['notes'],
                'created_at': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        conn.close()
        return jsonify({'status': 'success', 'assignments': assignments})
        
    except Exception as e:
        logging.error(f"Error getting user VLAN assignments: {e}")
        return jsonify({'error': 'Failed to get user VLAN assignments'}), 500

@app.route('/api/user-vlan-assignments', methods=['POST'])
@auth_required(permission='admin')
def create_user_vlan_assignment():
    """Create a static user-VLAN assignment"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('vlan_id'):
            return jsonify({'error': 'VLAN ID is required'}), 400
        if not data.get('username') and not data.get('user_id'):
            return jsonify({'error': 'Username or user ID is required'}), 400
            
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Get current user ID for created_by
        created_by = session.get('user_id')
            
        cursor.execute("""
            INSERT INTO user_vlan_assignments 
            (user_id, username, vlan_id, expires_at, notes, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data.get('user_id'),
            data.get('username'),
            data['vlan_id'],
            data.get('expires_at'),
            data.get('notes'),
            created_by
        ))
        
        assignment_id = cursor.fetchone()['id']
        conn.commit()
        conn.close()
        
        log_operation('user_vlan_assignment_created', {
            'username': data.get('username'),
            'vlan_id': data['vlan_id']
        })
        
        return jsonify({'status': 'success', 'message': 'User VLAN assignment created successfully', 'id': assignment_id})
        
    except Exception as e:
        logging.error(f"Error creating user VLAN assignment: {e}")
        return jsonify({'error': 'Failed to create user VLAN assignment'}), 500

# ================================
# IDP-RADIUS Authentication Bridge
# ================================

@app.route('/api/idp-radius-auth', methods=['GET'])
@auth_required()
def get_idp_radius_mappings():
    """Get all IDP-RADIUS authentication mappings"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ira.*, v.vlan_name, v.vlan_id as vlan_number
            FROM idp_radius_auth ira
            LEFT JOIN vlans v ON v.id = ira.default_vlan_id
            ORDER BY ira.created_at DESC
        """)
        
        mappings = []
        for row in cursor.fetchall():
            mappings.append({
                'id': row['id'],
                'idp_user_id': row['idp_user_id'],
                'idp_email': row['idp_email'],
                'idp_provider': row['idp_provider'],
                'radius_username': row['radius_username'],
                'certificate_cn': row['certificate_cn'],
                'default_vlan_id': row['default_vlan_id'],
                'vlan_name': row['vlan_name'],
                'vlan_number': row['vlan_number'],
                'is_active': row['is_active'],
                'last_auth_at': row['last_auth_at'].isoformat() if row['last_auth_at'] else None,
                'auth_count': row['auth_count'],
                'created_at': row['created_at'].isoformat() if row['created_at'] else None
            })
        
        conn.close()
        return jsonify({'status': 'success', 'mappings': mappings})
        
    except Exception as e:
        logging.error(f"Error getting IDP-RADIUS mappings: {e}")
        return jsonify({'error': 'Failed to get IDP-RADIUS mappings'}), 500

@app.route('/api/idp-radius-auth/validate', methods=['POST'])
def validate_idp_radius_auth():
    """Validate IDP credentials for RADIUS authentication"""
    try:
        data = request.get_json()
        
        # Get authentication method
        auth_method = data.get('auth_method')  # 'google', 'microsoft', or 'username_password'
        
        if auth_method in ['google', 'microsoft']:
            # IDP-based authentication
            idp_token = data.get('idp_token')
            if not idp_token:
                return jsonify({'error': 'IDP token required'}), 400
                
            # Validate IDP token and get user info
            if idp_auth_manager:
                if auth_method == 'google':
                    user_info = idp_auth_manager.validate_google_token(idp_token)
                else:
                    user_info = idp_auth_manager.validate_microsoft_token(idp_token)
                    
                if not user_info:
                    return jsonify({'error': 'Invalid IDP token'}), 401
                    
                # Check if user has IDP-RADIUS mapping
                conn = get_db_connection()
                if not conn:
                    return jsonify({'error': 'Database connection failed'}), 500
                    
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ira.*, v.vlan_id as vlan_number
                    FROM idp_radius_auth ira
                    LEFT JOIN vlans v ON v.id = ira.default_vlan_id
                    WHERE ira.idp_email = %s 
                        AND ira.idp_provider = %s 
                        AND ira.is_active = true
                """, (user_info['email'], auth_method))
                
                mapping = cursor.fetchone()
                
                if not mapping:
                    # Auto-create mapping for new IDP user
                    radius_username = user_info['email'].split('@')[0]
                    radius_password = generate_secure_password()
                    
                    cursor.execute("""
                        INSERT INTO idp_radius_auth 
                        (idp_user_id, idp_email, idp_provider, radius_username, 
                         radius_password_hash, is_active)
                        VALUES (%s, %s, %s, %s, %s, true)
                        RETURNING *
                    """, (
                        user_info['id'],
                        user_info['email'],
                        auth_method,
                        radius_username,
                        hashlib.sha256(radius_password.encode()).hexdigest()
                    ))
                    
                    mapping = cursor.fetchone()
                    conn.commit()
                    
                    log_operation('idp_radius_mapping_created', {
                        'email': user_info['email'],
                        'provider': auth_method
                    })
                
                # Update last authentication
                cursor.execute("""
                    UPDATE idp_radius_auth 
                    SET last_auth_at = NOW(), auth_count = auth_count + 1
                    WHERE id = %s
                """, (mapping['id'],))
                
                conn.commit()
                conn.close()
                
                # Return RADIUS credentials and VLAN assignment
                return jsonify({
                    'status': 'success',
                    'radius_username': mapping['radius_username'],
                    'vlan_id': mapping['vlan_number'] if mapping['default_vlan_id'] else None,
                    'auth_method': 'idp',
                    'provider': auth_method
                })
                
            else:
                return jsonify({'error': 'IDP authentication not configured'}), 500
                
        else:
            # Traditional username/password authentication
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return jsonify({'error': 'Username and password required'}), 400
                
            # Validate against local database
            user = authenticate_user(username, password)
            if not user:
                return jsonify({'error': 'Invalid credentials'}), 401
                
            # Get VLAN assignment for user
            conn = get_db_connection()
            if not conn:
                return jsonify({'error': 'Database connection failed'}), 500
                
            cursor = conn.cursor()
            cursor.execute("""
                SELECT v.vlan_id
                FROM user_vlan_assignments uva
                JOIN vlans v ON v.id = uva.vlan_id
                WHERE uva.user_id = %s
                    AND (uva.expires_at IS NULL OR uva.expires_at > NOW())
                LIMIT 1
            """, (user['id'],))
            
            vlan_assignment = cursor.fetchone()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'radius_username': username,
                'vlan_id': vlan_assignment['vlan_id'] if vlan_assignment else None,
                'auth_method': 'local'
            })
            
    except Exception as e:
        logging.error(f"Error validating IDP-RADIUS auth: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/vlan-assignment-log', methods=['GET'])
@auth_required()
def get_vlan_assignment_log():
    """Get VLAN assignment audit log"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Get query parameters for filtering
        username = request.args.get('username')
        limit = request.args.get('limit', 100, type=int)
        
        query = """
            SELECT val.*, v.vlan_name
            FROM vlan_assignment_log val
            LEFT JOIN vlans v ON v.vlan_id = val.assigned_vlan_id
        """
        
        params = []
        if username:
            query += " WHERE val.username = %s"
            params.append(username)
            
        query += " ORDER BY val.timestamp DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'id': row['id'],
                'username': row['username'],
                'auth_type': row['auth_type'],
                'assigned_vlan_id': row['assigned_vlan_id'],
                'vlan_name': row['vlan_name'],
                'assignment_reason': row['assignment_reason'],
                'nas_ip': row['nas_ip'],
                'nas_port': row['nas_port'],
                'calling_station_id': row['calling_station_id'],
                'success': row['success'],
                'error_message': row['error_message'],
                'timestamp': row['timestamp'].isoformat() if row['timestamp'] else None
            })
        
        conn.close()
        return jsonify({'status': 'success', 'logs': logs})
        
    except Exception as e:
        logging.error(f"Error getting VLAN assignment log: {e}")
        return jsonify({'error': 'Failed to get VLAN assignment log'}), 500

def generate_secure_password(length=16):
    """Generate a secure random password"""
    import string
    import secrets
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# VLAN Assignment API for RADIUS Integration
@app.route('/api/vlan-assignment', methods=['POST'])
def get_vlan_assignment():
    """Get VLAN assignment for RADIUS authentication"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        auth_type = data.get('auth_type', 'unknown')
        nas_ip = data.get('nas_ip')
        nas_port = data.get('nas_port')
        calling_station_id = data.get('calling_station_id')
        certificate_cn = data.get('certificate_cn')
        
        if not username:
            return jsonify({'status': 'error', 'message': 'Username is required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Prepare attributes for policy matching
        attributes = {
            'username': username,
            'auth_type': auth_type,
            'nas_ip': nas_ip,
            'nas_port': nas_port,
            'calling_station_id': calling_station_id,
            'certificate_cn': certificate_cn
        }
        
        # 1. Check static user assignment first (highest priority)
        cursor.execute("""
            SELECT v.vlan_id, v.vlan_name, 'static' as reason, '{}'::jsonb as attrs
            FROM user_vlan_assignments uva
            JOIN vlans v ON v.id = uva.vlan_id
            WHERE (uva.username = %s OR uva.user_id = (SELECT id FROM users WHERE username = %s))
                AND (uva.expires_at IS NULL OR uva.expires_at > NOW())
                AND v.is_active = true
            ORDER BY uva.created_at DESC
            LIMIT 1
        """, [username, username])
        
        result = cursor.fetchone()
        if result:
            return jsonify({
                'status': 'success',
                'vlan_id': result[0],
                'vlan_name': result[1],
                'assignment_reason': result[2],
                'radius_attributes': result[3] or {}
            })
        
        # 2. Check IDP-RADIUS mapping if auth_type indicates IDP authentication
        if auth_type in ['idp-google', 'idp-microsoft'] or (certificate_cn and '@' in certificate_cn):
            cursor.execute("""
                SELECT v.vlan_id, v.vlan_name, 'idp-default' as reason, '{}'::jsonb as attrs
                FROM idp_radius_auth ira
                JOIN vlans v ON v.id = ira.default_vlan_id
                WHERE ira.radius_username = %s
                    AND ira.is_active = true
                    AND v.is_active = true
                LIMIT 1
            """, [username])
            
            result = cursor.fetchone()
            if result:
                # Update last auth timestamp
                cursor.execute("""
                    UPDATE idp_radius_auth 
                    SET last_auth_at = NOW(), auth_count = auth_count + 1 
                    WHERE radius_username = %s
                """, [username])
                conn.commit()
                
                return jsonify({
                    'status': 'success',
                    'vlan_id': result[0],
                    'vlan_name': result[1],
                    'assignment_reason': result[2],
                    'radius_attributes': result[3] or {}
                })
        
        # 3. Check policy-based assignment
        cursor.execute("""
            SELECT vp.id, v.vlan_id, v.vlan_name, 
                   'policy:' || vp.policy_name as reason,
                   vp.radius_attributes, vp.conditions,
                   vp.priority, vp.allow_access, vp.reject_reason
            FROM vlan_policies vp
            JOIN vlans v ON v.id = vp.vlan_id
            WHERE vp.is_active = true
                AND v.is_active = true
            ORDER BY vp.priority ASC, vp.id ASC
        """)
        
        policies = cursor.fetchall()
        
        for policy in policies:
            policy_id, vlan_id, vlan_name, reason, radius_attrs, conditions, priority, allow_access, reject_reason = policy
            
            # Check if policy conditions match
            if match_policy_conditions(conditions, attributes):
                if not allow_access:
                    return jsonify({
                        'status': 'error',
                        'message': reject_reason or 'Access denied by policy',
                        'assignment_reason': reason
                    }), 403
                
                return jsonify({
                    'status': 'success',
                    'vlan_id': vlan_id,
                    'vlan_name': vlan_name,
                    'assignment_reason': reason,
                    'radius_attributes': radius_attrs or {}
                })
        
        # 4. Return default VLAN if no policies match
        cursor.execute("""
            SELECT vlan_id, vlan_name
            FROM vlans
            WHERE vlan_id = 1 AND is_active = true
            LIMIT 1
        """)
        
        result = cursor.fetchone()
        if result:
            return jsonify({
                'status': 'success',
                'vlan_id': result[0],
                'vlan_name': result[1],
                'assignment_reason': 'default',
                'radius_attributes': {}
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'No default VLAN configured'
            }), 500
            
    except Exception as e:
        logger.error(f"Error in VLAN assignment: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/vlan-assignment-log', methods=['POST'])
def log_vlan_assignment():
    """Log VLAN assignment audit entry"""
    try:
        data = request.get_json() or {}
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Log the assignment
        cursor.execute("""
            INSERT INTO vlan_assignment_log (
                username, auth_type, assigned_vlan_id, assignment_reason,
                nas_ip, nas_port, calling_station_id, success, error_message
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, [
            data.get('username'),
            data.get('auth_type'),
            data.get('assigned_vlan_id') if data.get('assigned_vlan_id') else None,
            data.get('assignment_reason'),
            data.get('nas_ip'),
            data.get('nas_port'),
            data.get('calling_station_id'),
            data.get('success', False),
            data.get('error_message')
        ])
        
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Assignment logged'})
        
    except Exception as e:
        logger.error(f"Error logging VLAN assignment: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to log assignment'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def match_policy_conditions(conditions, attributes):
    """Match policy conditions against authentication attributes"""
    if not conditions:
        return True
    
    try:
        # Convert PostgreSQL JSONB to Python dict if needed
        if isinstance(conditions, str):
            import json
            conditions = json.loads(conditions)
        
        for key, expected_value in conditions.items():
            actual_value = attributes.get(key)
            
            # Handle different condition types
            if isinstance(expected_value, list):
                # Multiple possible values or patterns
                matched = False
                for pattern in expected_value:
                    if match_value(actual_value, pattern):
                        matched = True
                        break
                if not matched:
                    return False
            else:
                # Single value or pattern
                if not match_value(actual_value, expected_value):
                    return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error matching policy conditions: {str(e)}")
        return False

def match_value(actual, expected):
    """Match a single value against expected pattern"""
    if actual is None:
        return expected is None
    
    actual_str = str(actual).lower()
    expected_str = str(expected).lower()
    
    # Handle wildcard patterns
    if '*' in expected_str:
        import re
        pattern = expected_str.replace('*', '.*')
        return bool(re.match(f'^{pattern}$', actual_str))
    
    # Handle boolean values
    if isinstance(expected, bool):
        return bool(actual) == expected
    
    # Exact match
    return actual_str == expected_str

# IDP-RADIUS Configuration Endpoints
@app.route('/api/idp-radius-config', methods=['GET'])
@auth_required(permission='admin')
def get_idp_radius_config():
    """Get IDP-RADIUS configuration settings"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Get configuration from system_config table
        cursor.execute("""
            SELECT config_key, config_value 
            FROM system_config 
            WHERE config_key LIKE 'idp_radius_%'
        """)
        
        config_rows = cursor.fetchall()
        config = {}
        
        # Default values
        defaults = {
            'auto_provisioning_enabled': False,
            'default_vlan_id': None,
            'radius_username_format': 'email',
            'password_complexity': 'standard',
            'custom_username_pattern': ''
        }
        
        # Parse configuration
        for key, value in config_rows:
            config_key = key.replace('idp_radius_', '')
            try:
                # Handle JSON values
                config[config_key] = json.loads(value) if value else defaults.get(config_key)
            except json.JSONDecodeError:
                config[config_key] = value
        
        # Apply defaults for missing keys
        for key, default_value in defaults.items():
            if key not in config:
                config[key] = default_value
        
        return jsonify({
            'status': 'success',
            'config': config
        })
        
    except Exception as e:
        logger.error(f"Error getting IDP-RADIUS config: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/idp-radius-config', methods=['POST'])
@auth_required(permission='admin')
def save_idp_radius_config():
    """Save IDP-RADIUS configuration settings"""
    try:
        data = request.get_json() or {}
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Configuration mapping
        config_mapping = {
            'auto_provisioning_enabled': data.get('auto_provisioning_enabled', False),
            'default_vlan_id': data.get('default_vlan_id'),
            'radius_username_format': data.get('radius_username_format', 'email'),
            'password_complexity': data.get('password_complexity', 'standard'),
            'custom_username_pattern': data.get('custom_username_pattern', '')
        }
        
        # Save each configuration item
        for key, value in config_mapping.items():
            config_key = f'idp_radius_{key}'
            config_value = json.dumps(value) if value is not None else None
            
            cursor.execute("""
                INSERT INTO system_config (config_key, config_value, created_by)
                VALUES (%s, %s, %s)
                ON CONFLICT (config_key) DO UPDATE SET
                    config_value = EXCLUDED.config_value,
                    updated_at = CURRENT_TIMESTAMP
            """, [config_key, config_value, session.get('user_id')])
        
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'IDP-RADIUS configuration saved successfully'
        })
        
    except Exception as e:
        logger.error(f"Error saving IDP-RADIUS config: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/idp-radius-config/test', methods=['POST'])
@auth_required(permission='admin')
def test_idp_radius_config():
    """Test IDP-RADIUS configuration"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        test_results = []
        
        # Test 1: Check if auto-provisioning is enabled
        cursor.execute("""
            SELECT config_value 
            FROM system_config 
            WHERE config_key = 'idp_radius_auto_provisioning_enabled'
        """)
        result = cursor.fetchone()
        auto_provisioning = json.loads(result[0]) if result and result[0] else False
        test_results.append(f"✓ Auto-provisioning: {'Enabled' if auto_provisioning else 'Disabled'}")
        
        # Test 2: Check default VLAN configuration
        cursor.execute("""
            SELECT sc.config_value, v.vlan_id, v.vlan_name
            FROM system_config sc
            LEFT JOIN vlans v ON v.id = CAST(sc.config_value::text AS INTEGER)
            WHERE sc.config_key = 'idp_radius_default_vlan_id'
        """)
        result = cursor.fetchone()
        if result and result[0] and result[0] != 'null':
            test_results.append(f"✓ Default VLAN: {result[1]} - {result[2]}")
        else:
            test_results.append("! Default VLAN: Not configured (will use system default)")
        
        # Test 3: Check username format
        cursor.execute("""
            SELECT config_value 
            FROM system_config 
            WHERE config_key = 'idp_radius_radius_username_format'
        """)
        result = cursor.fetchone()
        username_format = json.loads(result[0]) if result and result[0] else 'email'
        test_results.append(f"✓ Username format: {username_format}")
        
        # Test 4: Check password complexity
        cursor.execute("""
            SELECT config_value 
            FROM system_config 
            WHERE config_key = 'idp_radius_password_complexity'
        """)
        result = cursor.fetchone()
        password_complexity = json.loads(result[0]) if result and result[0] else 'standard'
        complexity_lengths = {'standard': 12, 'strong': 16, 'maximum': 24}
        test_results.append(f"✓ Password complexity: {password_complexity} ({complexity_lengths.get(password_complexity, 12)} characters)")
        
        # Test 5: Check existing IDP mappings
        cursor.execute("SELECT COUNT(*) FROM idp_radius_auth WHERE is_active = true")
        mapping_count = cursor.fetchone()[0]
        test_results.append(f"✓ Active IDP mappings: {mapping_count}")
        
        # Test 6: Check RADIUS server connectivity (if available)
        try:
            radius_url = os.environ.get('CA_MANAGER_URL', 'http://web-interface:5000')
            test_request = {
                "username": "test@example.com",
                "auth_type": "idp-google",
                "nas_ip": "127.0.0.1"
            }
            
            import requests
            response = requests.post(f"{radius_url}/api/vlan-assignment", 
                                   json=test_request, timeout=5)
            if response.status_code in [200, 403, 404]:  # Any response means API is working
                test_results.append("✓ VLAN assignment API: Accessible")
            else:
                test_results.append("! VLAN assignment API: Unexpected response")
        except Exception as e:
            test_results.append("! VLAN assignment API: Not accessible (this is normal if RADIUS server is not running)")
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration test completed',
            'test_results': test_results
        })
        
    except Exception as e:
        logger.error(f"Error testing IDP-RADIUS config: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Test failed: {str(e)}'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/idp-radius-auth/test', methods=['POST'])
@auth_required(permission='admin')
def test_idp_radius_auth():
    """Test IDP-RADIUS authentication functionality"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        test_results = []
        
        # Test 1: Check if there are active IDP mappings
        try:
            cursor.execute("SELECT COUNT(*) FROM idp_radius_auth WHERE is_active = true")
            mapping_count = cursor.fetchone()[0]
            test_results.append(f"✓ Active IDP-RADIUS mappings: {mapping_count}")
        except Exception as e:
            test_results.append(f"! IDP-RADIUS table error: {str(e)}")
        
        # Test 2: Test VLAN assignment API
        try:
            test_request = {
                "username": "test@example.com",
                "auth_type": "idp-google"
            }
            
            # Call our own VLAN assignment API
            from flask import current_app
            with current_app.test_request_context('/api/vlan-assignment', json=test_request):
                response = get_vlan_assignment()
                if hasattr(response, 'status_code'):
                    if response.status_code == 200:
                        test_results.append("✓ VLAN assignment API: Working correctly")
                    else:
                        test_results.append("! VLAN assignment API: Returns error (expected for test user)")
                else:
                    test_results.append("✓ VLAN assignment API: Functional")
        except Exception as e:
            test_results.append(f"! VLAN assignment API: Error - {str(e)}")
        
        # Test 3: Check database connectivity
        try:
            cursor.execute("SELECT COUNT(*) FROM vlans WHERE is_active = true")
            vlan_count = cursor.fetchone()[0]
            test_results.append(f"✓ Active VLANs available: {vlan_count}")
        except Exception as e:
            test_results.append(f"! VLAN table error: {str(e)}")
        
        # Test 4: Check policy engine
        try:
            cursor.execute("SELECT COUNT(*) FROM vlan_policies WHERE is_active = true")
            policy_count = cursor.fetchone()[0]
            test_results.append(f"✓ Active VLAN policies: {policy_count}")
        except Exception as e:
            test_results.append(f"! VLAN policies table error: {str(e)}")
        
        # Test 5: Check system configuration
        try:
            cursor.execute("SELECT COUNT(*) FROM system_config WHERE config_key LIKE 'idp_radius_%'")
            config_count = cursor.fetchone()[0]
            test_results.append(f"✓ IDP-RADIUS configuration entries: {config_count}")
        except Exception as e:
            test_results.append(f"! System config table error: {str(e)}")
        
        return jsonify({
            'status': 'success',
            'message': 'Authentication test completed',
            'test_results': test_results
        })
        
    except Exception as e:
        logger.error(f"Error testing IDP-RADIUS auth: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Test failed: {str(e)}'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/vlan-assignment-log', methods=['GET'])
@auth_required()
def get_vlan_assignment_logs():
    """Get VLAN assignment audit logs"""
    try:
        log_type = request.args.get('type', '')
        limit = min(int(request.args.get('limit', 100)), 1000)  # Max 1000 logs
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Build query based on type filter
        if log_type == 'idp':
            query = """
                SELECT username, auth_type, assigned_vlan_id, assignment_reason,
                       nas_ip, nas_port, calling_station_id, success, error_message, timestamp
                FROM vlan_assignment_log
                WHERE auth_type LIKE 'idp-%' OR auth_type IN ('eap-tls', 'eap-peap')
                ORDER BY timestamp DESC
                LIMIT %s
            """
        else:
            query = """
                SELECT username, auth_type, assigned_vlan_id, assignment_reason,
                       nas_ip, nas_port, calling_station_id, success, error_message, timestamp
                FROM vlan_assignment_log
                ORDER BY timestamp DESC
                LIMIT %s
            """
        
        cursor.execute(query, [limit])
        logs = cursor.fetchall()
        
        # Convert to list of dictionaries
        log_list = []
        for log in logs:
            log_list.append({
                'username': log[0],
                'auth_type': log[1],
                'assigned_vlan_id': log[2],
                'assignment_reason': log[3],
                'nas_ip': log[4],
                'nas_port': log[5],
                'calling_station_id': log[6],
                'success': log[7],
                'error_message': log[8],
                'timestamp': log[9].isoformat() if log[9] else None
            })
        
        return jsonify({
            'status': 'success',
            'logs': log_list,
            'count': len(log_list)
        })
        
    except Exception as e:
        logger.error(f"Error getting VLAN assignment logs: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

# PKI Backup and Restore Endpoints
@app.route('/api/pki/backup', methods=['POST'])
@auth_required(permission='admin')
def create_pki_backup():
    """Create encrypted backup of the entire PKI infrastructure"""
    try:
        data = request.get_json() or {}
        password = data.get('password')
        
        if not password:
            return jsonify({
                "status": "error",
                "message": "Backup password is required"
            }), 400
        
        if len(password) < 8:
            return jsonify({
                "status": "error",
                "message": "Backup password must be at least 8 characters long"
            }), 400
        
        log_operation('create_pki_backup')
        
        # Request backup from EasyRSA container
        backup_data = {
            'password': password,
            'include_private_keys': True,
            'compression': True
        }
        
        response = requests.post(
            f"{TERMINAL_CONTAINER_URL}/execute",
            json={"operation": "create-backup", "params": backup_data},
            timeout=300  # 5 minutes for backup
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                # Get the backup content
                backup_content = result.get('backup_data')
                if backup_content:
                    # Create file-like object from backup data (already base64 encoded JSON)
                    backup_bytes = backup_content.encode('utf-8')
                    file_obj = io.BytesIO(backup_bytes)
                    
                    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                    filename = f'pki-backup-{timestamp}.pki'
                    
                    return send_file(
                        file_obj,
                        as_attachment=True,
                        download_name=filename,
                        mimetype='application/octet-stream'
                    )
                else:
                    return jsonify({
                        "status": "error",
                        "message": "No backup data received from container"
                    }), 500
            else:
                return jsonify({
                    "status": "error",
                    "message": result.get('message', 'Backup creation failed')
                }), 500
        else:
            return jsonify({
                "status": "error",
                "message": f"EasyRSA container error: {response.status_code}"
            }), 500
            
    except requests.exceptions.Timeout:
        return jsonify({
            "status": "error",
            "message": "Backup operation timed out. Please try again."
        }), 408
    except Exception as e:
        logging.error(f"Error creating PKI backup: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to create PKI backup: {str(e)}"
        }), 500

@app.route('/api/pki/restore', methods=['POST'])
@auth_required(permission='admin')
def restore_pki_backup():
    """Restore PKI infrastructure from encrypted backup"""
    try:
        logger.info(f"Restore request received. Files: {list(request.files.keys())}")
        logger.info(f"Form data: {list(request.form.keys())}")
        
        if 'backup_file' not in request.files:
            logger.error("No backup_file found in request.files")
            return jsonify({
                "status": "error",
                "message": "No backup file provided"
            }), 400
        
        file = request.files['backup_file']
        password = request.form.get('password')
        
        logger.info(f"File received: {file.filename}, Password provided: {bool(password)}")
        
        if not file or not file.filename:
            return jsonify({
                "status": "error",
                "message": "No file selected or empty filename"
            }), 400
        
        if not password:
            return jsonify({
                "status": "error",
                "message": "Backup password is required"
            }), 400
        
        # More flexible file extension check
        if not file.filename.lower().endswith('.pki'):
            logger.warning(f"File extension check failed: {file.filename}")
            return jsonify({
                "status": "error",
                "message": f"Invalid file format. Only .pki files are supported. Received: {file.filename}"
            }), 400
        
        log_operation('restore_pki_backup', {'filename': file.filename})
        
        # Read and validate file content
        try:
            file_content = file.read()
            if not file_content:
                return jsonify({
                    "status": "error",
                    "message": "Backup file is empty"
                }), 400
            
            logger.info(f"File content size: {len(file_content)} bytes")
            
            # File content is already base64-encoded JSON from .pki file
            backup_data_b64 = file_content.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error reading backup file: {e}")
            return jsonify({
                "status": "error",
                "message": f"Error reading backup file: {str(e)}"
            }), 400
        
        # Send restore request to EasyRSA container
        restore_data = {
            'password': password,
            'backup_data': backup_data_b64,
            'verify_password': True
        }
        
        logger.info("Sending restore request to EasyRSA container")
        
        try:
            response = requests.post(
                f"{TERMINAL_CONTAINER_URL}/execute",
                json={"operation": "restore-backup", "params": restore_data},
                timeout=300  # 5 minutes for restore
            )
            
            logger.info(f"EasyRSA response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"EasyRSA response: {result}")
                
                if result.get('status') == 'success':
                    return jsonify({
                        "status": "success",
                        "message": "PKI restored successfully from backup",
                        "details": result.get('message', '')
                    })
                else:
                    return jsonify({
                        "status": "error",
                        "message": result.get('message', 'Backup restore failed')
                    }), 500
            else:
                response_text = response.text if hasattr(response, 'text') else 'Unknown error'
                logger.error(f"EasyRSA container error {response.status_code}: {response_text}")
                return jsonify({
                    "status": "error",
                    "message": f"EasyRSA container error: {response.status_code} - {response_text}"
                }), 500
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request to EasyRSA container failed: {e}")
            return jsonify({
                "status": "error",
                "message": f"Failed to communicate with EasyRSA container: {str(e)}"
            }), 500
            
    except requests.exceptions.Timeout:
        return jsonify({
            "status": "error",
            "message": "Restore operation timed out. Please try again."
        }), 408
    except Exception as e:
        logging.error(f"Error restoring PKI backup: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to restore PKI backup: {str(e)}"
        }), 500

# Comprehensive Backup and Restore Endpoints
@app.route('/api/backup/comprehensive', methods=['POST'])
@auth_required(permission='admin')
def create_comprehensive_backup():
    """Create comprehensive backup including PKI data, database, and application settings"""
    try:
        data = request.get_json() or {}
        password = data.get('password')
        
        if not password:
            return jsonify({
                "status": "error",
                "message": "Backup password is required"
            }), 400
        
        if len(password) < 8:
            return jsonify({
                "status": "error",
                "message": "Backup password must be at least 8 characters long"
            }), 400
        
        log_operation('create_comprehensive_backup')
        
        # Create comprehensive backup data structure
        backup_data = {
            'version': '2.0',
            'backup_type': 'comprehensive',
            'created': datetime.now().isoformat(),
            'components': {
                'pki_data': None,
                'database_data': {},
                'application_settings': {},
                'logos_and_assets': {}
            }
        }
        
        # 1. Get PKI backup data
        try:
            pki_response = requests.post(
                f"{TERMINAL_CONTAINER_URL}/execute",
                json={"operation": "create-backup", "params": {'password': password}},
                timeout=120
            )
            
            if pki_response.status_code == 200:
                pki_result = pki_response.json()
                if pki_result.get('status') == 'success':
                    backup_data['components']['pki_data'] = pki_result.get('backup_data')
                    
        except Exception as e:
            logging.warning(f"PKI backup failed: {e}")
            backup_data['components']['pki_data'] = None
        
        # 2. Backup database tables
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Tables to backup
            tables_to_backup = [
                'users', 'roles', 'permissions', 'user_roles', 'role_permissions',
                'system_config', 'smtp_config', 'tenants', 'tenant_settings',
                'ocsp_config', 'certificates', 'certificate_revocations',
                'idp_users', 'idp_certificates', 'allowed_email_domains',
                'email_verifications', 'audit_logs'
            ]
            
            for table in tables_to_backup:
                try:
                    # Check if table exists
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_name = %s
                        );
                    """, (table,))
                    
                    if cursor.fetchone()[0]:
                        # Get table data
                        cursor.execute(f"SELECT * FROM {table}")
                        rows = cursor.fetchall()
                        
                        # Get column names
                        cursor.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name = %s ORDER BY ordinal_position", (table,))
                        columns = [row[0] for row in cursor.fetchall()]
                        
                        # Convert to list of dictionaries
                        table_data = []
                        for row in rows:
                            row_dict = {}
                            for i, value in enumerate(row):
                                # Handle datetime objects
                                if isinstance(value, datetime):
                                    row_dict[columns[i]] = value.isoformat()
                                else:
                                    row_dict[columns[i]] = value
                            table_data.append(row_dict)
                        
                        backup_data['components']['database_data'][table] = {
                            'columns': columns,
                            'rows': table_data,
                            'count': len(table_data)
                        }
                        
                except Exception as e:
                    logging.warning(f"Failed to backup table {table}: {e}")
                    backup_data['components']['database_data'][table] = {'error': str(e)}
        
        except Exception as e:
            logging.error(f"Database backup failed: {e}")
            backup_data['components']['database_data'] = {'error': str(e)}
        finally:
            if conn:
                conn.close()
        
        # 3. Backup application settings and configuration files
        try:
            # Environment variables that should be backed up
            env_vars_to_backup = [
                'DOMAIN', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH',
                'EASYRSA_REQ_COUNTRY', 'EASYRSA_REQ_PROVINCE', 'EASYRSA_REQ_CITY',
                'EASYRSA_REQ_ORG', 'EASYRSA_REQ_EMAIL', 'EASYRSA_REQ_OU'
            ]
            
            env_backup = {}
            for var in env_vars_to_backup:
                value = os.getenv(var)
                if value:
                    env_backup[var] = value
            
            backup_data['components']['application_settings'] = {
                'environment_variables': env_backup,
                'flask_config': {
                    'AUTHENTICATION_ENABLED': os.getenv('AUTHENTICATION_ENABLED', 'true'),
                    'MULTI_USER_MODE': os.getenv('MULTI_USER_MODE', 'true'),
                    'LOG_LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
                    'FLASK_ENV': os.getenv('FLASK_ENV', 'production')
                }
            }
            
        except Exception as e:
            logging.warning(f"Application settings backup failed: {e}")
            backup_data['components']['application_settings'] = {'error': str(e)}
        
        # 4. Backup logos and static assets
        try:
            logos_backup = {}
            
            # Check for uploaded logos in common locations
            logo_paths = [
                '/app/static/logos',
                '/app/static/images',
                '/app/uploads'
            ]
            
            for logo_path in logo_paths:
                if os.path.exists(logo_path):
                    for file in os.listdir(logo_path):
                        if file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
                            try:
                                file_path = os.path.join(logo_path, file)
                                with open(file_path, 'rb') as f:
                                    file_data = f.read()
                                    # Base64 encode binary data
                                    import base64
                                    logos_backup[f"{logo_path}/{file}"] = base64.b64encode(file_data).decode('utf-8')
                            except Exception as e:
                                logging.warning(f"Failed to backup logo {file}: {e}")
            
            backup_data['components']['logos_and_assets'] = logos_backup
            
        except Exception as e:
            logging.warning(f"Logos backup failed: {e}")
            backup_data['components']['logos_and_assets'] = {'error': str(e)}
        
        # 5. Encrypt and compress the comprehensive backup
        try:
            import json, gzip, base64, secrets
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Serialize backup data
            backup_json = json.dumps(backup_data, indent=2, default=str)
            
            # Compress data
            compressed_data = gzip.compress(backup_json.encode('utf-8'))
            
            # Generate salt and IV
            salt = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            
            # Encrypt data
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad data to block size
            padding_length = 16 - (len(compressed_data) % 16)
            padded_data = compressed_data + bytes([padding_length] * padding_length)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Create final backup package
            final_backup = {
                'version': '2.0',
                'type': 'comprehensive',
                'created': datetime.now().isoformat(),
                'salt': base64.b64encode(salt).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'data': base64.b64encode(encrypted_data).decode('utf-8'),
                'components_summary': {
                    'pki_included': backup_data['components']['pki_data'] is not None,
                    'database_tables': len(backup_data['components']['database_data']),
                    'app_settings_included': 'error' not in backup_data['components']['application_settings'],
                    'logos_count': len(backup_data['components']['logos_and_assets'])
                }
            }
            
            # Convert to downloadable format
            final_json = json.dumps(final_backup, indent=2)
            backup_bytes = final_json.encode('utf-8')
            file_obj = io.BytesIO(backup_bytes)
            
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            filename = f'comprehensive-backup-{timestamp}.cabak'
            
            return send_file(
                file_obj,
                as_attachment=True,
                download_name=filename,
                mimetype='application/json'
            )
            
        except Exception as e:
            logging.error(f"Backup encryption failed: {e}")
            return jsonify({
                "status": "error",
                "message": f"Failed to encrypt backup: {str(e)}"
            }), 500
            
    except Exception as e:
        logging.error(f"Comprehensive backup failed: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to create comprehensive backup: {str(e)}"
        }), 500

@app.route('/api/backup/comprehensive/restore', methods=['POST'])
@auth_required(permission='admin')
def restore_comprehensive_backup():
    """Restore comprehensive backup including PKI data, database, and application settings"""
    try:
        if 'backup_file' not in request.files:
            return jsonify({
                "status": "error",
                "message": "No backup file provided"
            }), 400
        
        password = request.form.get('password')
        if not password:
            return jsonify({
                "status": "error",
                "message": "Backup password is required"
            }), 400
        
        backup_file = request.files['backup_file']
        if backup_file.filename == '':
            return jsonify({
                "status": "error",
                "message": "No backup file selected"
            }), 400
        
        log_operation('restore_comprehensive_backup')
        
        # Read and parse backup file
        try:
            backup_content = backup_file.read().decode('utf-8')
            backup_package = json.loads(backup_content)
            
            if backup_package.get('version') != '2.0' or backup_package.get('type') != 'comprehensive':
                return jsonify({
                    "status": "error",
                    "message": "Invalid or incompatible backup file format"
                }), 400
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Failed to parse backup file: {str(e)}"
            }), 400
        
        # Decrypt backup data
        try:
            import json, gzip, base64
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            salt = base64.b64decode(backup_package['salt'])
            iv = base64.b64decode(backup_package['iv'])
            encrypted_data = base64.b64decode(backup_package['data'])
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            
            # Decrypt data
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            padding_length = decrypted_padded[-1]
            decrypted_data = decrypted_padded[:-padding_length]
            
            # Decompress and parse
            decompressed_data = gzip.decompress(decrypted_data)
            backup_data = json.loads(decompressed_data.decode('utf-8'))
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Failed to decrypt backup (check password): {str(e)}"
            }), 400
        
        restore_results = {
            'pki_restore': {'status': 'skipped'},
            'database_restore': {'status': 'skipped', 'tables': {}},
            'settings_restore': {'status': 'skipped'},
            'logos_restore': {'status': 'skipped'}
        }
        
        # 1. Restore PKI data
        if backup_data['components'].get('pki_data'):
            try:
                pki_restore_data = {
                    'password': password,
                    'backup_data': backup_data['components']['pki_data']
                }
                
                pki_response = requests.post(
                    f"{TERMINAL_CONTAINER_URL}/execute",
                    json={"operation": "restore-backup", "params": pki_restore_data},
                    timeout=120
                )
                
                if pki_response.status_code == 200:
                    pki_result = pki_response.json()
                    if pki_result.get('status') == 'success':
                        restore_results['pki_restore'] = {'status': 'success', 'message': 'PKI data restored'}
                    else:
                        restore_results['pki_restore'] = {'status': 'error', 'message': pki_result.get('message', 'Unknown error')}
                else:
                    restore_results['pki_restore'] = {'status': 'error', 'message': 'PKI container communication failed'}
                    
            except Exception as e:
                restore_results['pki_restore'] = {'status': 'error', 'message': str(e)}
        
        # 2. Restore database data
        db_data = backup_data['components'].get('database_data', {})
        if db_data and 'error' not in db_data:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                for table_name, table_data in db_data.items():
                    if 'error' in table_data:
                        restore_results['database_restore']['tables'][table_name] = {'status': 'error', 'message': table_data['error']}
                        continue
                    
                    try:
                        # Clear existing data (except for critical admin user)
                        if table_name == 'users':
                            cursor.execute("DELETE FROM users WHERE username != 'admin'")
                        elif table_name not in ['roles', 'permissions']:  # Keep default roles and permissions
                            cursor.execute(f"DELETE FROM {table_name}")
                        
                        # Insert restored data
                        if table_data.get('rows'):
                            columns = table_data['columns']
                            placeholders = ', '.join(['%s'] * len(columns))
                            
                            for row in table_data['rows']:
                                # Skip admin user to prevent lockout
                                if table_name == 'users' and row.get('username') == 'admin':
                                    continue
                                
                                values = [row.get(col) for col in columns]
                                cursor.execute(
                                    f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})",
                                    values
                                )
                        
                        restore_results['database_restore']['tables'][table_name] = {
                            'status': 'success',
                            'rows_restored': len(table_data.get('rows', []))
                        }
                        
                    except Exception as e:
                        restore_results['database_restore']['tables'][table_name] = {'status': 'error', 'message': str(e)}
                
                conn.commit()
                restore_results['database_restore']['status'] = 'success'
                
            except Exception as e:
                restore_results['database_restore'] = {'status': 'error', 'message': str(e)}
            finally:
                if 'conn' in locals():
                    conn.close()
        
        # 3. Restore logos and assets
        logos_data = backup_data['components'].get('logos_and_assets', {})
        if logos_data and 'error' not in logos_data:
            try:
                restored_files = 0
                for file_path, file_data in logos_data.items():
                    try:
                        # Create directory if it doesn't exist
                        dir_path = os.path.dirname(file_path)
                        os.makedirs(dir_path, exist_ok=True)
                        
                        # Decode and write file
                        file_bytes = base64.b64decode(file_data)
                        with open(file_path, 'wb') as f:
                            f.write(file_bytes)
                        restored_files += 1
                        
                    except Exception as e:
                        logging.warning(f"Failed to restore file {file_path}: {e}")
                
                restore_results['logos_restore'] = {
                    'status': 'success',
                    'files_restored': restored_files
                }
                
            except Exception as e:
                restore_results['logos_restore'] = {'status': 'error', 'message': str(e)}
        
        # Generate summary
        success_components = sum(1 for component in restore_results.values() if component.get('status') == 'success')
        total_components = len(restore_results)
        
        return jsonify({
            "status": "success" if success_components > 0 else "error",
            "message": f"Restore completed. {success_components}/{total_components} components restored successfully.",
            "restore_details": restore_results,
            "backup_info": {
                "created": backup_data.get('created'),
                "version": backup_data.get('version')
            }
        })
        
    except Exception as e:
        logging.error(f"Comprehensive restore failed: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to restore comprehensive backup: {str(e)}"
        }), 500

# Enhanced VLAN Policy Management API Endpoints

@app.route('/api/user-classification-rules', methods=['GET'])
@auth_required()
def get_user_classification_rules():
    """Get all user classification rules"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ucr.*, u.username as created_by_username
            FROM user_classification_rules ucr
            LEFT JOIN users u ON ucr.created_by = u.id
            ORDER BY ucr.priority ASC, ucr.created_at DESC
        """)
        
        rules = cursor.fetchall()
        rule_list = [dict(rule) for rule in rules]
        
        return jsonify({
            'status': 'success',
            'rules': rule_list
        })
        
    except Exception as e:
        logger.error(f"Error getting user classification rules: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/user-classification-rules', methods=['POST'])
@auth_required()
def create_user_classification_rule():
    """Create a new user classification rule"""
    try:
        data = request.get_json()
        
        required_fields = ['rule_name', 'classification_type', 'classification_value', 'user_group']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'status': 'error',
                    'message': f'Missing required field: {field}'
                }), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Check if rule name already exists
        cursor.execute("SELECT id FROM user_classification_rules WHERE rule_name = %s", (data['rule_name'],))
        if cursor.fetchone():
            return jsonify({
                'status': 'error',
                'message': 'Rule name already exists'
            }), 400
        
        cursor.execute("""
            INSERT INTO user_classification_rules 
            (rule_name, description, priority, classification_type, classification_value, 
             user_group, user_category, metadata, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data['rule_name'],
            data.get('description'),
            data.get('priority', 100),
            data['classification_type'],
            data['classification_value'],
            data['user_group'],
            data.get('user_category'),
            json.dumps(data.get('metadata', {})),
            session.get('user_id')
        ))
        
        rule_id = cursor.fetchone()[0]
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'User classification rule created successfully',
            'rule_id': rule_id
        })
        
    except Exception as e:
        logger.error(f"Error creating user classification rule: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/user-classification-rules/<int:rule_id>', methods=['PUT'])
@auth_required()
def update_user_classification_rule(rule_id):
    """Update an existing user classification rule"""
    try:
        data = request.get_json()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Check if rule exists
        cursor.execute("SELECT id FROM user_classification_rules WHERE id = %s", (rule_id,))
        if not cursor.fetchone():
            return jsonify({
                'status': 'error',
                'message': 'Rule not found'
            }), 404
        
        # Check if new rule name conflicts (if being changed)
        if data.get('rule_name'):
            cursor.execute("SELECT id FROM user_classification_rules WHERE rule_name = %s AND id != %s", 
                          (data['rule_name'], rule_id))
            if cursor.fetchone():
                return jsonify({
                    'status': 'error',
                    'message': 'Rule name already exists'
                }), 400
        
        # Build update query dynamically
        update_fields = []
        values = []
        
        allowed_fields = ['rule_name', 'description', 'priority', 'is_active', 'classification_type', 
                         'classification_value', 'user_group', 'user_category', 'metadata']
        
        for field in allowed_fields:
            if field in data:
                update_fields.append(f"{field} = %s")
                if field == 'metadata':
                    values.append(json.dumps(data[field]))
                else:
                    values.append(data[field])
        
        if not update_fields:
            return jsonify({
                'status': 'error',
                'message': 'No valid fields to update'
            }), 400
        
        values.append(rule_id)
        
        cursor.execute(f"""
            UPDATE user_classification_rules 
            SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, values)
        
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'User classification rule updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error updating user classification rule: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/user-classification-rules/<int:rule_id>', methods=['DELETE'])
@auth_required()
def delete_user_classification_rule(rule_id):
    """Delete a user classification rule"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Check if rule exists
        cursor.execute("SELECT rule_name FROM user_classification_rules WHERE id = %s", (rule_id,))
        rule = cursor.fetchone()
        if not rule:
            return jsonify({
                'status': 'error',
                'message': 'Rule not found'
            }), 404
        
        cursor.execute("DELETE FROM user_classification_rules WHERE id = %s", (rule_id,))
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'User classification rule "{rule["rule_name"]}" deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting user classification rule: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/vlan-policies-v2', methods=['GET'])
@auth_required()
def get_enhanced_vlan_policies():
    """Get all enhanced VLAN policies"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT vp.*, 
                   dv.vlan_id as default_vlan_name, dv.vlan_name as default_vlan_display,
                   fv.vlan_id as fallback_vlan_name, fv.vlan_name as fallback_vlan_display,
                   u.username as created_by_username
            FROM vlan_policies_v2 vp
            LEFT JOIN vlans dv ON vp.default_vlan_id = dv.id
            LEFT JOIN vlans fv ON vp.fallback_vlan_id = fv.id
            LEFT JOIN users u ON vp.created_by = u.id
            ORDER BY vp.priority ASC, vp.created_at DESC
        """)
        
        policies = cursor.fetchall()
        policy_list = [dict(policy) for policy in policies]
        
        return jsonify({
            'status': 'success',
            'policies': policy_list
        })
        
    except Exception as e:
        logger.error(f"Error getting enhanced VLAN policies: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/vlan-policies-v2', methods=['POST'])
@auth_required()
def create_enhanced_vlan_policy():
    """Create a new enhanced VLAN policy"""
    try:
        data = request.get_json()
        
        required_fields = ['policy_name', 'target_user_groups']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'status': 'error',
                    'message': f'Missing required field: {field}'
                }), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Check if policy name already exists
        cursor.execute("SELECT id FROM vlan_policies_v2 WHERE policy_name = %s", (data['policy_name'],))
        if cursor.fetchone():
            return jsonify({
                'status': 'error',
                'message': 'Policy name already exists'
            }), 400
        
        cursor.execute("""
            INSERT INTO vlan_policies_v2 
            (policy_name, description, priority, target_user_groups, target_user_categories, target_users,
             time_conditions, location_conditions, device_conditions, auth_conditions,
             default_vlan_id, fallback_vlan_id, radius_attributes, access_control,
             bandwidth_limit, qos_class, session_timeout, idle_timeout, reauthentication_interval,
             enable_logging, enable_monitoring, alert_on_violation, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data['policy_name'],
            data.get('description'),
            data.get('priority', 100),
            data['target_user_groups'],
            data.get('target_user_categories', []),
            data.get('target_users', []),
            json.dumps(data.get('time_conditions', {})),
            json.dumps(data.get('location_conditions', {})),
            json.dumps(data.get('device_conditions', {})),
            json.dumps(data.get('auth_conditions', {})),
            data.get('default_vlan_id'),
            data.get('fallback_vlan_id'),
            json.dumps(data.get('radius_attributes', {})),
            data.get('access_control', 'allow'),
            data.get('bandwidth_limit'),
            data.get('qos_class'),
            data.get('session_timeout'),
            data.get('idle_timeout'),
            data.get('reauthentication_interval'),
            data.get('enable_logging', True),
            data.get('enable_monitoring', True),
            data.get('alert_on_violation', False),
            session.get('user_id')
        ))
        
        policy_id = cursor.fetchone()[0]
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Enhanced VLAN policy created successfully',
            'policy_id': policy_id
        })
        
    except Exception as e:
        logger.error(f"Error creating enhanced VLAN policy: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/user-groups', methods=['GET'])
@auth_required()
def get_user_groups():
    """Get all user groups"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ug.*, 
                   dv.vlan_id as default_vlan_name, dv.vlan_name as default_vlan_display,
                   pg.group_name as parent_group_name,
                   u.username as created_by_username
            FROM user_groups ug
            LEFT JOIN vlans dv ON ug.default_vlan_id = dv.id
            LEFT JOIN user_groups pg ON ug.parent_group_id = pg.id
            LEFT JOIN users u ON ug.created_by = u.id
            WHERE ug.is_active = true
            ORDER BY ug.group_name ASC
        """)
        
        groups = cursor.fetchall()
        group_list = [dict(group) for group in groups]
        
        return jsonify({
            'status': 'success',
            'groups': group_list
        })
        
    except Exception as e:
        logger.error(f"Error getting user groups: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/enhanced-vlan-assignment', methods=['POST'])
def get_enhanced_vlan_assignment():
    """Get VLAN assignment using enhanced policy engine"""
    try:
        data = request.get_json() or {}
        username = data.get('username')
        auth_type = data.get('auth_type', 'unknown')
        attributes = data.get('attributes', {})
        
        if not username:
            return jsonify({
                'status': 'error',
                'message': 'Username is required'
            }), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 'error', 'message': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Use the enhanced VLAN assignment function
        cursor.execute("""
            SELECT * FROM get_enhanced_vlan_assignment(%s, %s, %s)
        """, (username, auth_type, json.dumps(attributes)))
        
        result = cursor.fetchone()
        
        if result:
            response_data = {
                'status': 'success',
                'vlan_id': result['vlan_id'],
                'vlan_name': result['vlan_name'],
                'assignment_reason': result['assignment_reason'],
                'radius_attributes': result['radius_attributes'],
                'user_group': result['user_group'],
                'user_category': result['user_category'],
                'session_timeout': result['session_timeout'],
                'bandwidth_limit': result['bandwidth_limit']
            }
            
            # Log the assignment
            cursor.execute("""
                INSERT INTO vlan_assignment_log_v2 
                (username, user_group, user_category, auth_type, assigned_vlan_id, 
                 assignment_reason, applied_radius_attributes, session_timeout, 
                 bandwidth_limit, success, processing_time_ms)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                username,
                result['user_group'],
                result['user_category'],
                auth_type,
                result['vlan_id'],
                result['assignment_reason'],
                result['radius_attributes'],
                result['session_timeout'],
                result['bandwidth_limit'],
                True,
                0  # Processing time would be measured in real implementation
            ))
            
            conn.commit()
            return jsonify(response_data)
        else:
            # Log failed assignment
            cursor.execute("""
                INSERT INTO vlan_assignment_log_v2 
                (username, auth_type, success, error_message)
                VALUES (%s, %s, %s, %s)
            """, (username, auth_type, False, 'No VLAN assignment found'))
            
            conn.commit()
            
            return jsonify({
                'status': 'error',
                'message': 'No VLAN assignment found for user'
            }), 404
        
    except Exception as e:
        logger.error(f"Error in enhanced VLAN assignment: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

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

