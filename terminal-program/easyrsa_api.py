# easyrsa_api.py - Enhanced EasyRSA API with full CA configuration support
# API wrapper for EasyRSA certificate management

from flask import Flask, request, jsonify, send_file, Response
import subprocess
import os
import json
import glob
import base64
import tarfile
import shutil
import re
import logging
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# EasyRSA configuration
EASYRSA_PATH = "/usr/share/easy-rsa"
PKI_PATH = "/app/pki"
EASYRSA_CMD = f"{EASYRSA_PATH}/easyrsa"

# Ensure PKI directory exists and is writable
os.makedirs(PKI_PATH, exist_ok=True)
os.environ['EASYRSA_PKI'] = PKI_PATH

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy", 
        "easyrsa_path": EASYRSA_PATH,
        "pki_path": PKI_PATH,
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/debug')
def debug_pki():
    """Debug endpoint to see PKI directory contents"""
    try:
        debug_info = {
            "pki_path": PKI_PATH,
            "pki_exists": os.path.exists(PKI_PATH),
            "pki_contents": [],
            "ca_file_path": os.path.join(PKI_PATH, "ca.crt"),
            "ca_file_exists": False,
            "ca_file_size": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        # List PKI directory contents
        if os.path.exists(PKI_PATH):
            try:
                for item in os.listdir(PKI_PATH):
                    item_path = os.path.join(PKI_PATH, item)
                    debug_info["pki_contents"].append({
                        "name": item,
                        "is_file": os.path.isfile(item_path),
                        "is_dir": os.path.isdir(item_path),
                        "size": os.path.getsize(item_path) if os.path.isfile(item_path) else 0
                    })
            except Exception as e:
                debug_info["pki_list_error"] = str(e)
        
        # Check CA file specifically
        ca_file_path = os.path.join(PKI_PATH, "ca.crt")
        debug_info["ca_file_exists"] = os.path.exists(ca_file_path)
        if debug_info["ca_file_exists"]:
            debug_info["ca_file_size"] = os.path.getsize(ca_file_path)
            debug_info["ca_file_readable"] = os.access(ca_file_path, os.R_OK)
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download-ca')
def download_ca():
    """Download CA certificate file"""
    try:
        ca_file_path = os.path.join(PKI_PATH, "ca.crt")
        
        if os.path.exists(ca_file_path):
            file_size = os.path.getsize(ca_file_path)
            
            if file_size == 0:
                return jsonify({
                    "status": "error",
                    "message": "CA certificate file is empty"
                }), 404
            
            return send_file(
                ca_file_path,
                as_attachment=True,
                download_name='ca.pem',
                mimetype='application/x-pem-file'
            )
        else:
            return jsonify({
                "status": "error",
                "message": f"CA certificate not found at {ca_file_path}"
            }), 404
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to serve CA certificate: {str(e)}"
        }), 500

@app.route('/execute', methods=['POST'])
def execute_easyrsa():
    """Execute EasyRSA commands"""
    try:
        data = request.get_json() or {}
        operation = data.get('operation', '')
        params = data.get('params', {})
        
        if not operation:
            return jsonify({
                "status": "error",
                "message": "No operation specified"
            }), 400
        
        # Route to specific operation handlers
        if operation == 'init-pki':
            return init_pki()
        elif operation == 'build-ca':
            return build_ca(params)
        elif operation == 'gen-req':
            return gen_req(params)
        elif operation == 'sign-req':
            return sign_req(params)
        elif operation == 'build-client-full':
            return build_client_full(params)
        elif operation == 'build-server-full':
            return build_server_full(params)
        elif operation == 'revoke':
            return revoke_cert(params)
        elif operation == 'gen-crl':
            return gen_crl()
        elif operation == 'show-ca':
            return show_ca()
        elif operation == 'show-cert':
            return show_cert(params)
        elif operation == 'validate-cert':
            return validate_cert(params)
        elif operation == 'get-cert-files':
            return get_cert_files(params)
        elif operation == 'list-certs':
            return list_certificates()
        elif operation == 'check-expiring':
            return check_expiring_certificates(params)
        elif operation == 'status':
            return pki_status()
        elif operation == 'get-metrics':
            return get_metrics()
        elif operation == 'create-backup':
            return create_backup()
        elif operation == 'get-ca-key':
            return get_ca_private_key()
        elif operation == 'import-req':
            return import_req(params)
        elif operation == 'get-index':
            return get_index_content()
        elif operation == 'import-ca':
            return import_ca(params)
        else:
            return jsonify({
                "status": "error",
                "message": f"Unknown operation: {operation}"
            }), 400
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def create_vars_file(ca_config):
    """Create custom vars file with CA configuration"""
    try:
        vars_content = f"""# Generated vars file for CA configuration
# Generated on {datetime.now().isoformat()}

# Certificate validity periods
set_var EASYRSA_CA_EXPIRE   {ca_config.get('ca_validity_days', 3650)}
set_var EASYRSA_CERT_EXPIRE {ca_config.get('cert_validity_days', 365)}
set_var EASYRSA_CRL_DAYS    30

# Cryptographic settings
set_var EASYRSA_ALGO        rsa
set_var EASYRSA_KEY_SIZE    {ca_config.get('key_size', 2048)}
set_var EASYRSA_DIGEST      "{ca_config.get('digest_algorithm', 'sha256')}"

# Certificate fields
set_var EASYRSA_REQ_COUNTRY "{ca_config.get('country', 'US')}"
set_var EASYRSA_REQ_PROVINCE    "{ca_config.get('state', 'CA')}"
set_var EASYRSA_REQ_CITY    "{ca_config.get('city', 'San Francisco')}"
set_var EASYRSA_REQ_ORG     "{ca_config.get('organization', 'My Organization')}"
set_var EASYRSA_REQ_EMAIL   "{ca_config.get('email', 'admin@myorg.com')}"
set_var EASYRSA_REQ_OU      "{ca_config.get('organizational_unit', 'IT Department')}"
set_var EASYRSA_REQ_CN      "{ca_config.get('common_name', 'Easy-RSA CA')}"

# Batch mode settings
set_var EASYRSA_BATCH       1
set_var EASYRSA_NO_PASS     1
"""
        
        vars_file_path = os.path.join(PKI_PATH, "vars")
        with open(vars_file_path, 'w') as f:
            f.write(vars_content)
        
        print(f"Created vars file at: {vars_file_path}")
        print(f"Vars content:\n{vars_content}")
        
        return vars_file_path
        
    except Exception as e:
        print(f"Error creating vars file: {e}")
        raise

def run_easyrsa_command(args, input_text=None, custom_env=None):
    """Helper function to run EasyRSA commands"""
    cmd = [EASYRSA_CMD] + args
    
    print(f"Running command: {' '.join(cmd)}")
    print(f"Working directory: {EASYRSA_PATH}")
    print(f"PKI directory: {PKI_PATH}")
    if input_text:
        print(f"Input text: {repr(input_text)}")
    
    # Set up environment
    env = custom_env or {**os.environ, 'EASYRSA_PKI': PKI_PATH, 'EASYRSA_BATCH': '1'}
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=120,
        cwd=EASYRSA_PATH,
        env=env
    )
    
    print(f"Command result - Return code: {result.returncode}")
    print(f"STDOUT: {result.stdout}")
    print(f"STDERR: {result.stderr}")
    
    return result

def init_pki():
    """Initialize PKI"""
    result = run_easyrsa_command(['init-pki'])
    
    return jsonify({
        "status": "success" if result.returncode == 0 else "error",
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "message": "PKI initialized successfully" if result.returncode == 0 else "Failed to initialize PKI"
    })

def import_ca(params):
    """Import existing CA certificate and private key"""
    try:
        ca_cert_pem = params.get('ca_certificate', '')
        ca_key_pem = params.get('ca_key', '')
        cert_validity_days = params.get('cert_validity_days', 365)
        ca_info = params.get('ca_info', {})
        
        if not ca_cert_pem or not ca_key_pem:
            return jsonify({
                "status": "error",
                "message": "Both CA certificate and private key are required"
            }), 400
        
        # Ensure PKI is initialized
        if not os.path.exists(PKI_PATH):
            os.makedirs(PKI_PATH, exist_ok=True)
        if not os.path.exists(os.path.join(PKI_PATH, 'private')):
            os.makedirs(os.path.join(PKI_PATH, 'private'), exist_ok=True)
        if not os.path.exists(os.path.join(PKI_PATH, 'issued')):
            os.makedirs(os.path.join(PKI_PATH, 'issued'), exist_ok=True)
        
        # Write CA certificate
        ca_cert_path = os.path.join(PKI_PATH, 'ca.crt')
        with open(ca_cert_path, 'w') as f:
            f.write(ca_cert_pem)
        
        # Write CA private key
        ca_key_path = os.path.join(PKI_PATH, 'private', 'ca.key')
        with open(ca_key_path, 'w') as f:
            f.write(ca_key_pem)
        
        # Set proper permissions on private key
        os.chmod(ca_key_path, 0o600)
        
        # Create serial file
        serial_path = os.path.join(PKI_PATH, 'serial')
        if not os.path.exists(serial_path):
            with open(serial_path, 'w') as f:
                f.write('01\n')
        
        # Create index.txt file
        index_path = os.path.join(PKI_PATH, 'index.txt')
        if not os.path.exists(index_path):
            with open(index_path, 'w') as f:
                f.write('')
        
        # Create index.txt.attr file with unique_subject = no
        index_attr_path = os.path.join(PKI_PATH, 'index.txt.attr')
        with open(index_attr_path, 'w') as f:
            f.write('unique_subject = no\n')
        
        # Update vars file with cert validity days
        vars_path = os.path.join(PKI_PATH, 'vars')
        if os.path.exists('/usr/share/easy-rsa/vars.example'):
            # Copy example vars if it exists
            with open('/usr/share/easy-rsa/vars.example', 'r') as f:
                vars_content = f.read()
            with open(vars_path, 'w') as f:
                f.write(vars_content)
                f.write(f'\nset_var EASYRSA_CERT_EXPIRE {cert_validity_days}\n')
        else:
            # Create minimal vars file
            with open(vars_path, 'w') as f:
                f.write(f'set_var EASYRSA_CERT_EXPIRE {cert_validity_days}\n')
                f.write('set_var EASYRSA_BATCH "1"\n')
        
        return jsonify({
            "status": "success",
            "message": f"Successfully imported CA: {ca_info.get('common_name', 'Unknown')}",
            "ca_info": ca_info,
            "stdout": f"CA certificate and key imported successfully\nCA Path: {ca_cert_path}\nKey Path: {ca_key_path}",
            "stderr": ""
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to import CA: {str(e)}",
            "stdout": "",
            "stderr": str(e)
        }), 500

def build_ca(params):
    """Build Certificate Authority with full configuration"""
    print(f"Received CA build params: {params}")
    
    # Extract CA configuration from params
    ca_config = {
        'common_name': params.get('common_name', 'Easy-RSA CA'),
        'country': params.get('country', 'US'),
        'state': params.get('state', 'CA'),
        'city': params.get('city', 'San Francisco'),
        'organization': params.get('organization', 'My Organization'),
        'organizational_unit': params.get('organizational_unit', 'IT Department'),
        'email': params.get('email', 'admin@myorg.com'),
        'ca_validity_days': params.get('ca_validity_days', 3650),
        'cert_validity_days': params.get('cert_validity_days', 365),
        'key_size': params.get('key_size', 2048),
        'digest_algorithm': params.get('digest_algorithm', 'sha256')
    }
    
    print(f"Building CA with configuration: {ca_config}")
    
    try:
        # Create vars file with custom configuration
        vars_file_path = create_vars_file(ca_config)
        
        # Set up environment with vars file
        custom_env = {
            **os.environ,
            'EASYRSA_PKI': PKI_PATH,
            'EASYRSA_BATCH': '1',
            'EASYRSA_VARS_FILE': vars_file_path,
            # Also set individual environment variables as backup
            'EASYRSA_REQ_CN': ca_config['common_name'],
            'EASYRSA_REQ_COUNTRY': ca_config['country'],
            'EASYRSA_REQ_PROVINCE': ca_config['state'],
            'EASYRSA_REQ_CITY': ca_config['city'],
            'EASYRSA_REQ_ORG': ca_config['organization'],
            'EASYRSA_REQ_OU': ca_config['organizational_unit'],
            'EASYRSA_REQ_EMAIL': ca_config['email'],
            'EASYRSA_CA_EXPIRE': str(ca_config['ca_validity_days']),
            'EASYRSA_CERT_EXPIRE': str(ca_config['cert_validity_days']),
            'EASYRSA_KEY_SIZE': str(ca_config['key_size']),
            'EASYRSA_DIGEST': ca_config['digest_algorithm']
        }
        
        print(f"Environment variables set: {[k for k in custom_env.keys() if k.startswith('EASYRSA')]}")
        
        # The input for build-ca should be the common name
        ca_input = f"{ca_config['common_name']}\n"
        
        # Run build-ca command
        result = run_easyrsa_command(['build-ca', 'nopass'], ca_input, custom_env)
        
        # Check if CA was created successfully
        ca_file_path = os.path.join(PKI_PATH, "ca.crt")
        ca_exists = os.path.exists(ca_file_path)
        print(f"CA file exists after build: {ca_exists}")
        
        if ca_exists and result.returncode == 0:
            # Verify the CA certificate content
            try:
                verify_result = run_easyrsa_command(['show-ca'])
                if verify_result.returncode == 0:
                    print(f"CA certificate verification:\n{verify_result.stdout}")
            except Exception as e:
                print(f"Error verifying CA: {e}")
        
        return jsonify({
            "status": "success" if result.returncode == 0 else "error",
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "message": f"CA '{ca_config['common_name']}' built successfully with custom configuration" if result.returncode == 0 else "Failed to build CA"
        })
        
    except Exception as e:
        print(f"Error in build_ca: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to build CA: {str(e)}"
        }), 500

def gen_req(params):
    """Generate certificate request"""
    name = params.get('name')
    if not name:
        return jsonify({"status": "error", "message": "Name parameter required"}), 400
    
    result = run_easyrsa_command(['gen-req', name, 'nopass'])
    
    return jsonify({
        "status": "success" if result.returncode == 0 else "error",
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "message": f"Certificate request for {name} generated successfully" if result.returncode == 0 else f"Failed to generate request for {name}"
    })

def sign_req(params):
    """Sign certificate request"""
    name = params.get('name')
    cert_type = params.get('type', 'client')  # client or server
    
    if not name:
        return jsonify({"status": "error", "message": "Name parameter required"}), 400
    
    result = run_easyrsa_command(['sign-req', cert_type, name], input_text="yes\n")
    
    return jsonify({
        "status": "success" if result.returncode == 0 else "error",
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "message": f"Certificate for {name} signed successfully" if result.returncode == 0 else f"Failed to sign certificate for {name}"
    })

def build_client_full(params):
    """Build client certificate with correct CN from frontend input using two-step process"""
    name = params.get('name')
    if not name:
        return jsonify({"status": "error", "message": "Name parameter required"}), 400
    
    try:
        # Step 1: Generate request with correct CN from frontend
        # Set up environment with the correct CN for the certificate request
        req_env = {
            **os.environ,
            'EASYRSA_PKI': PKI_PATH,
            'EASYRSA_BATCH': '1',
            'EASYRSA_REQ_CN': name  # Use the name from frontend as CN
        }
        
        # Generate the certificate request
        req_result = run_easyrsa_command(['gen-req', name, 'nopass'], custom_env=req_env)
        if req_result.returncode != 0:
            return jsonify({
                "status": "error",
                "return_code": req_result.returncode,
                "stdout": req_result.stdout,
                "stderr": req_result.stderr,
                "message": f"Failed to generate request for {name}"
            })
        
        # Step 2: Sign as client certificate
        # Clean environment for signing to avoid conflicts
        sign_env = {
            **os.environ,
            'EASYRSA_PKI': PKI_PATH,
            'EASYRSA_BATCH': '1'
        }
        # Remove CN for signing step to avoid conflicts
        sign_env.pop('EASYRSA_REQ_CN', None)
        
        sign_result = run_easyrsa_command(['sign-req', 'client', name], 
                                        input_text="yes\n", custom_env=sign_env)
        
        # Clean up the certificate request file after successful certificate creation
        if sign_result.returncode == 0:
            try:
                req_file = os.path.join(PKI_PATH, 'reqs', f'{name}.req')
                if os.path.exists(req_file):
                    os.remove(req_file)
                    print(f"Cleaned up certificate request file: {req_file}")
            except Exception as cleanup_error:
                print(f"Warning: Failed to clean up request file: {cleanup_error}")
        
        return jsonify({
            "status": "success" if sign_result.returncode == 0 else "error",
            "return_code": sign_result.returncode,
            "stdout": sign_result.stdout,
            "stderr": sign_result.stderr,
            "message": f"Client certificate for {name} created successfully with CN={name}" if sign_result.returncode == 0 else f"Failed to create client certificate for {name}"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to create client certificate for {name}: {str(e)}"
        }), 500

def build_server_full(params):
    """Build server certificate with correct CN and DNS SAN from frontend input"""
    name = params.get('name')
    if not name:
        return jsonify({"status": "error", "message": "Name parameter required"}), 400
    
    try:
        import tempfile
        
        # Create temporary extension file for SAN
        ext_fd, ext_file = tempfile.mkstemp(suffix='.conf')
        
        try:
            # Write SAN extension configuration
            san_config = f"""# Server certificate extensions for {name}
[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:{name}

[ req_ext ]
subjectAltName = DNS:{name}
"""
            with open(ext_file, 'w') as f:
                f.write(san_config)
            
            # Set up environment with correct CN and extension file
            cert_env = {
                **os.environ, 
                'EASYRSA_PKI': PKI_PATH, 
                'EASYRSA_BATCH': '1',
                'EASYRSA_REQ_CN': name,  # Use name from frontend as CN
                'EASYRSA_EXT_DIR': os.path.dirname(ext_file)
            }
            
            # Step 1: Generate request with correct CN
            req_result = run_easyrsa_command(['gen-req', name, 'nopass'], custom_env=cert_env)
            if req_result.returncode != 0:
                return jsonify({
                    "status": "error",
                    "return_code": req_result.returncode,
                    "stdout": req_result.stdout,
                    "stderr": req_result.stderr,
                    "message": f"Failed to generate request for {name}"
                })
            
            # Step 2: Sign as server certificate with SAN
            # Clean environment for signing to avoid conflicts, but keep extension file
            sign_env = {
                **os.environ, 
                'EASYRSA_PKI': PKI_PATH, 
                'EASYRSA_BATCH': '1'
            }
            sign_env.pop('EASYRSA_REQ_CN', None)  # Remove CN for signing step
            
            sign_result = run_easyrsa_command(['sign-req', 'server', name], 
                                            input_text="yes\n", custom_env=sign_env)
            
            # Clean up the certificate request file after successful certificate creation
            if sign_result.returncode == 0:
                try:
                    req_file = os.path.join(PKI_PATH, 'reqs', f'{name}.req')
                    if os.path.exists(req_file):
                        os.remove(req_file)
                        print(f"Cleaned up certificate request file: {req_file}")
                except Exception as cleanup_error:
                    print(f"Warning: Failed to clean up request file: {cleanup_error}")
            
            return jsonify({
                "status": "success" if sign_result.returncode == 0 else "error",
                "return_code": sign_result.returncode,
                "stdout": sign_result.stdout,
                "stderr": sign_result.stderr,
                "message": f"Server certificate for {name} created successfully with CN={name} and DNS SAN={name}" if sign_result.returncode == 0 else f"Failed to create server certificate for {name}"
            })
            
        finally:
            # Clean up temporary extension file
            os.close(ext_fd)
            os.unlink(ext_file)
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to create server certificate for {name}: {str(e)}"
        }), 500

def revoke_cert(params):
    """Revoke a certificate"""
    name = params.get('name')
    if not name:
        return jsonify({"status": "error", "message": "Name parameter required"}), 400
    
    result = run_easyrsa_command(['revoke', name], input_text="yes\n")
    
    return jsonify({
        "status": "success" if result.returncode == 0 else "error",
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "message": f"Certificate for {name} revoked successfully" if result.returncode == 0 else f"Failed to revoke certificate for {name}"
    })

def gen_crl():
    """Generate Certificate Revocation List"""
    result = run_easyrsa_command(['gen-crl'])
    
    return jsonify({
        "status": "success" if result.returncode == 0 else "error",
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "message": "CRL generated successfully" if result.returncode == 0 else "Failed to generate CRL"
    })

def show_ca():
    """Show CA certificate details"""
    result = run_easyrsa_command(['show-ca'])
    
    return jsonify({
        "status": "success" if result.returncode == 0 else "error",
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "message": "CA details retrieved successfully" if result.returncode == 0 else "Failed to show CA details"
    })

def get_ca_private_key():
    """Get CA private key for OCSP responder"""
    try:
        ca_key_path = os.path.join(PKI_PATH, "private", "ca.key")
        
        if not os.path.exists(ca_key_path):
            return jsonify({
                "status": "error",
                "message": "CA private key not found"
            }), 404
        
        with open(ca_key_path, 'r') as f:
            ca_key_pem = f.read()
        
        logger.info("CA private key retrieved for OCSP responder")
        return jsonify({
            "status": "success",
            "private_key": ca_key_pem,
            "message": "CA private key retrieved successfully"
        })
        
    except Exception as e:
        logger.error(f"Error retrieving CA private key: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve CA private key: {str(e)}"
        }), 500

def get_index_content():
    """Get index.txt content for OCSP certificate status checking"""
    try:
        index_path = os.path.join(PKI_PATH, "index.txt")
        
        if not os.path.exists(index_path):
            return jsonify({
                "status": "error",
                "message": "Certificate index file not found"
            }), 404
        
        with open(index_path, 'r') as f:
            index_content = f.read()
        
        logger.info("Certificate index retrieved for OCSP status checking")
        return jsonify({
            "status": "success",
            "index_content": index_content,
            "message": "Certificate index retrieved successfully"
        })
        
    except Exception as e:
        logger.error(f"Error retrieving certificate index: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve certificate index: {str(e)}"
        }), 500

def show_cert(params):
    """Show certificate details"""
    name = params.get('name')
    if not name:
        return jsonify({"status": "error", "message": "Name parameter required"}), 400
    
    result = run_easyrsa_command(['show-cert', name])
    
    return jsonify({
        "status": "success" if result.returncode == 0 else "error",
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "message": f"Certificate details for {name}" if result.returncode == 0 else f"Failed to show certificate for {name}"
    })

def validate_cert(params):
    """Validate certificate expiry, chain, etc."""
    name = params.get('name')
    if not name:
        return jsonify({"status": "error", "message": "Name parameter required"}), 400
    
    try:
        cert_file = os.path.join(PKI_PATH, "issued", f"{name}.crt")
        
        if not os.path.exists(cert_file):
            return jsonify({
                "status": "error",
                "message": f"Certificate file not found for {name}"
            }), 404
        
        # Read and parse certificate
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Calculate expiry information
        now = datetime.utcnow()
        expires_in = cert.not_valid_after - now
        expires_in_days = expires_in.days
        
        # Determine validation status
        is_valid = now < cert.not_valid_after and now > cert.not_valid_before
        is_expiring_soon = expires_in_days <= 30
        
        validation_result = {
            "valid": is_valid,
            "expires_in_days": expires_in_days,
            "expiry_date": cert.not_valid_after.isoformat(),
            "issue_date": cert.not_valid_before.isoformat(),
            "expiring_soon": is_expiring_soon,
            "subject": str(cert.subject),
            "issuer": str(cert.issuer),
            "serial_number": str(cert.serial_number)
        }
        
        return jsonify({
            "status": "success",
            "validation": validation_result,
            "message": f"Certificate {name} validation completed"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to validate certificate {name}: {str(e)}"
        }), 500

def get_cert_files(params):
    """Get certificate files for download"""
    name = params.get('name')
    include_key = params.get('include_key', True)
    
    if not name:
        return jsonify({"status": "error", "message": "Name parameter required"}), 400
    
    try:
        files = {}
        
        # Get certificate
        cert_file = os.path.join(PKI_PATH, "issued", f"{name}.crt")
        if os.path.exists(cert_file):
            with open(cert_file, 'r') as f:
                files['certificate'] = f.read()
        else:
            return jsonify({
                "status": "error",
                "message": f"Certificate file not found for {name}"
            }), 404
        
        # Get private key if requested
        if include_key:
            key_file = os.path.join(PKI_PATH, "private", f"{name}.key")
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    files['private_key'] = f.read()
        
        # Get CA certificate
        ca_file = os.path.join(PKI_PATH, "ca.crt")
        if os.path.exists(ca_file):
            with open(ca_file, 'r') as f:
                files['ca_certificate'] = f.read()
        
        return jsonify({
            "status": "success",
            **files,
            "message": f"Certificate files for {name} retrieved successfully"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to get certificate files for {name}: {str(e)}"
        }), 500

def check_expiring_certificates(params):
    """Check for certificates expiring within specified days"""
    days = params.get('days', 30)
    
    try:
        expiring_certs = []
        issued_path = os.path.join(PKI_PATH, "issued", "*.crt")
        
        for cert_file in glob.glob(issued_path):
            try:
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()
                
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                
                # Calculate expiry
                now = datetime.utcnow()
                expires_in = cert.not_valid_after - now
                expires_in_days = expires_in.days
                
                if 0 <= expires_in_days <= days:
                    name = os.path.basename(cert_file).replace('.crt', '')
                    expiring_certs.append({
                        "name": name,
                        "expires_in_days": expires_in_days,
                        "expiry_date": cert.not_valid_after.isoformat(),
                        "subject": str(cert.subject)
                    })
                    
            except Exception as e:
                print(f"Error processing certificate {cert_file}: {e}")
                continue
        
        return jsonify({
            "status": "success",
            "expiring_certificates": expiring_certs,
            "count": len(expiring_certs),
            "days_threshold": days,
            "message": f"Found {len(expiring_certs)} certificates expiring within {days} days"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to check expiring certificates: {str(e)}"
        }), 500

def list_certificates():
    """List all certificates and their status"""
    try:
        certs = []
        
        # List issued certificates
        issued_path = os.path.join(PKI_PATH, "issued", "*.crt")
        for cert_file in glob.glob(issued_path):
            name = os.path.basename(cert_file).replace('.crt', '')
            
            # Try to get expiry information
            try:
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                expires_in = cert.not_valid_after - datetime.utcnow()
                expires_in_days = expires_in.days
                
                certs.append({
                    "name": name,
                    "type": "issued",
                    "file": cert_file,
                    "expires_in_days": expires_in_days,
                    "expiry_date": cert.not_valid_after.isoformat(),
                    "subject": str(cert.subject)
                })
            except Exception as e:
                certs.append({
                    "name": name,
                    "type": "issued",
                    "file": cert_file,
                    "error": f"Could not parse certificate: {str(e)}"
                })
        
        # List certificate requests
        req_path = os.path.join(PKI_PATH, "reqs", "*.req")
        for req_file in glob.glob(req_path):
            name = os.path.basename(req_file).replace('.req', '')
            certs.append({
                "name": name,
                "type": "request",
                "file": req_file
            })
        
        # Check for revoked certificates
        revoked_path = os.path.join(PKI_PATH, "revoked")
        if os.path.exists(revoked_path):
            for cert_file in glob.glob(os.path.join(revoked_path, "certs_by_serial", "*.crt")):
                name = os.path.basename(cert_file).replace('.crt', '')
                certs.append({
                    "name": name,
                    "type": "revoked",
                    "file": cert_file
                })
        
        return jsonify({
            "status": "success",
            "certificates": certs,
            "count": len(certs),
            "message": f"Found {len(certs)} certificates"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def get_metrics():
    """Get system metrics and dashboard data"""
    try:
        # Count different types of certificates
        issued_count = len(glob.glob(os.path.join(PKI_PATH, "issued", "*.crt")))
        request_count = len(glob.glob(os.path.join(PKI_PATH, "reqs", "*.req")))
        
        # Count revoked certificates
        revoked_count = 0
        revoked_path = os.path.join(PKI_PATH, "revoked", "certs_by_serial")
        if os.path.exists(revoked_path):
            revoked_count = len(glob.glob(os.path.join(revoked_path, "*.crt")))
        
        # Check for expiring certificates (within 30 days)
        expiring_soon = 0
        for cert_file in glob.glob(os.path.join(PKI_PATH, "issued", "*.crt")):
            try:
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                expires_in = cert.not_valid_after - datetime.utcnow()
                if 0 <= expires_in.days <= 30:
                    expiring_soon += 1
            except:
                continue
        
        # Check CA status
        ca_exists = os.path.exists(os.path.join(PKI_PATH, "ca.crt"))
        pki_initialized = os.path.exists(os.path.join(PKI_PATH, "private"))
        
        metrics = {
            "total_certificates": issued_count,
            "pending_requests": request_count,
            "revoked_certificates": revoked_count,
            "expiring_soon": expiring_soon,
            "ca_exists": ca_exists,
            "pki_initialized": pki_initialized,
            "health_status": "healthy" if ca_exists and pki_initialized else "warning",
            "timestamp": datetime.now().isoformat()
        }
        
        return jsonify({
            "status": "success",
            "metrics": metrics,
            "message": "Metrics retrieved successfully"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to get metrics: {str(e)}"
        }), 500

def create_backup():
    """Create complete PKI backup"""
    try:
        import tempfile
        import tarfile
        
        # Create temporary file for backup
        backup_fd, backup_path = tempfile.mkstemp(suffix='.tar.gz')
        
        with tarfile.open(backup_path, 'w:gz') as tar:
            # Add entire PKI directory to backup
            tar.add(PKI_PATH, arcname='pki')
        
        # Read backup file
        with open(backup_path, 'rb') as f:
            backup_data = f.read()
        
        # Clean up temporary file
        os.unlink(backup_path)
        os.close(backup_fd)
        
        return jsonify({
            "status": "success",
            "backup_data": base64.b64encode(backup_data).decode(),
            "backup_size": len(backup_data),
            "timestamp": datetime.now().isoformat(),
            "message": "Backup created successfully"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to create backup: {str(e)}"
        }), 500

def pki_status():
    """Get PKI status and information"""
    try:
        ca_file_path = os.path.join(PKI_PATH, "ca.crt")
        
        status = {
            "pki_initialized": os.path.exists(os.path.join(PKI_PATH, "private")),
            "ca_exists": os.path.exists(ca_file_path),
            "pki_path": PKI_PATH,
            "easyrsa_version": "3.x",
            "timestamp": datetime.now().isoformat()
        }
        
        # Get CA info if it exists
        if status["ca_exists"]:
            try:
                ca_result = run_easyrsa_command(['show-ca'])
                if ca_result.returncode == 0:
                    status["ca_info"] = ca_result.stdout
                
                # Parse CA certificate for more details
                with open(ca_file_path, 'rb') as f:
                    ca_cert_data = f.read()
                ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
                
                status["ca_details"] = {
                    "subject": str(ca_cert.subject),
                    "issuer": str(ca_cert.issuer),
                    "valid_from": ca_cert.not_valid_before.isoformat(),
                    "valid_until": ca_cert.not_valid_after.isoformat(),
                    "serial_number": str(ca_cert.serial_number)
                }
                
                # Calculate CA expiry
                ca_expires_in = ca_cert.not_valid_after - datetime.utcnow()
                status["ca_expires_in_days"] = ca_expires_in.days
                
            except Exception as e:
                status["ca_error"] = str(e)
        
        # Count certificates
        issued_count = len(glob.glob(os.path.join(PKI_PATH, "issued", "*.crt")))
        req_count = len(glob.glob(os.path.join(PKI_PATH, "reqs", "*.req")))
        
        # Count revoked certificates
        revoked_count = 0
        revoked_path = os.path.join(PKI_PATH, "revoked", "certs_by_serial")
        if os.path.exists(revoked_path):
            revoked_count = len(glob.glob(os.path.join(revoked_path, "*.crt")))
        
        status.update({
            "issued_certificates": issued_count,
            "pending_requests": req_count,
            "revoked_certificates": revoked_count
        })
        
        return jsonify({
            "status": "success",
            "pki_status": status,
            "message": "PKI status retrieved successfully"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def import_req(params):
    """Import CSR data for SCEP enrollment"""
    try:
        name = params.get('name')
        csr_data = params.get('csr_data')
        
        if not name or not csr_data:
            return jsonify({
                "status": "error",
                "message": "Both 'name' and 'csr_data' parameters are required"
            }), 400
        
        # Ensure reqs directory exists
        reqs_dir = os.path.join(PKI_PATH, 'reqs')
        os.makedirs(reqs_dir, exist_ok=True)
        
        # Save CSR to file
        csr_file_path = os.path.join(reqs_dir, f'{name}.req')
        with open(csr_file_path, 'w') as f:
            f.write(csr_data)
        
        logger.info(f"CSR imported for certificate: {name}")
        return jsonify({
            "status": "success",
            "message": f"CSR imported successfully for {name}",
            "file_path": csr_file_path
        })
        
    except Exception as e:
        logger.error(f"Error importing CSR: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/save-csr', methods=['POST'])
def save_csr():
    """Save CSR data to PKI reqs directory for SCEP enrollment"""
    try:
        data = request.get_json()
        name = data.get('name')
        csr_data = data.get('csr_data')
        
        if not name or not csr_data:
            return jsonify({
                "status": "error",
                "message": "Both 'name' and 'csr_data' parameters are required"
            }), 400
        
        # Ensure reqs directory exists
        reqs_dir = os.path.join(PKI_PATH, 'reqs')
        os.makedirs(reqs_dir, exist_ok=True)
        
        # Save CSR to file
        csr_file_path = os.path.join(reqs_dir, f'{name}.req')
        with open(csr_file_path, 'w') as f:
            f.write(csr_data)
        
        logger.info(f"CSR saved for certificate: {name}")
        return jsonify({
            "status": "success",
            "message": f"CSR saved successfully for {name}",
            "file_path": csr_file_path
        })
        
    except Exception as e:
        logger.error(f"Error saving CSR: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/get-cert/<name>')
def get_certificate(name):
    """Retrieve signed certificate file for SCEP enrollment"""
    try:
        # Check issued certificates directory
        cert_file_path = os.path.join(PKI_PATH, 'issued', f'{name}.crt')
        
        if not os.path.exists(cert_file_path):
            return jsonify({
                "status": "error",
                "message": f"Certificate not found for {name}"
            }), 404
        
        # Read and return certificate file
        with open(cert_file_path, 'rb') as f:
            cert_data = f.read()
        
        logger.info(f"Certificate retrieved for: {name}")
        return Response(
            cert_data,
            mimetype='application/x-pem-file',
            headers={
                'Content-Disposition': f'attachment; filename="{name}.crt"',
                'Content-Length': str(len(cert_data))
            }
        )
        
    except Exception as e:
        logger.error(f"Error retrieving certificate {name}: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)