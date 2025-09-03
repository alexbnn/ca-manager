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

@app.route('/test-restore-debug')
def test_restore_debug():
    """Test restore debug functionality"""
    print("TEST RESTORE DEBUG: This is a test print statement")
    logger.info("TEST RESTORE DEBUG: This is a test logger statement")
    
    # Test the same imports as restore function
    try:
        import base64
        import binascii
        import json
        print("TEST RESTORE DEBUG: All imports successful")
        
        # Test base64 decode
        test_data = base64.b64encode(b'{"test": "data"}').decode('utf-8')
        decoded = base64.b64decode(test_data)
        print(f"TEST RESTORE DEBUG: Base64 decode test successful: {decoded}")
        
        return jsonify({"status": "debug test complete", "imports": "success"})
    except Exception as e:
        print(f"TEST RESTORE DEBUG ERROR: {e}")
        return jsonify({"status": "debug test failed", "error": str(e)}), 500

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
        elif operation == 'get-ca-key':
            return get_ca_private_key()
        elif operation == 'import-req':
            return import_req(params)
        elif operation == 'get-index':
            return get_index_content()
        elif operation == 'import-ca':
            return import_ca(params)
        elif operation == 'create-backup':
            return create_pki_backup(params)
        elif operation == 'restore-backup':
            return restore_pki_backup(params)
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
        
        # Ensure PKI is initialized with all required directories
        required_dirs = [
            PKI_PATH,
            os.path.join(PKI_PATH, 'private'),
            os.path.join(PKI_PATH, 'issued'),
            os.path.join(PKI_PATH, 'certs_by_serial'),
            os.path.join(PKI_PATH, 'reqs'),
            os.path.join(PKI_PATH, 'revoked'),
            os.path.join(PKI_PATH, 'revoked', 'certs_by_serial'),
            os.path.join(PKI_PATH, 'revoked', 'private_by_serial'),
            os.path.join(PKI_PATH, 'revoked', 'reqs_by_serial'),
            os.path.join(PKI_PATH, 'renewed'),
            os.path.join(PKI_PATH, 'renewed', 'certs_by_serial'),
            os.path.join(PKI_PATH, 'renewed', 'private_by_serial'),
            os.path.join(PKI_PATH, 'renewed', 'reqs_by_serial')
        ]
        
        for dir_path in required_dirs:
            os.makedirs(dir_path, exist_ok=True)
        
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
        
        # Create crlnumber file for CRL generation
        crlnumber_path = os.path.join(PKI_PATH, 'crlnumber')
        if not os.path.exists(crlnumber_path):
            with open(crlnumber_path, 'w') as f:
                f.write('01\n')
        
        # Create OpenSSL config file if it doesn't exist
        openssl_cnf_path = os.path.join(PKI_PATH, 'openssl-easyrsa.cnf')
        if not os.path.exists(openssl_cnf_path) and os.path.exists('/usr/share/easy-rsa/openssl-easyrsa.cnf'):
            shutil.copy('/usr/share/easy-rsa/openssl-easyrsa.cnf', openssl_cnf_path)
        
        # Create PKCS#11 config file if template exists
        pkcs11_cnf_path = os.path.join(PKI_PATH, 'pkcs11-easyrsa.cnf')
        if not os.path.exists(pkcs11_cnf_path) and os.path.exists('/usr/share/easy-rsa/pkcs11-easyrsa.cnf'):
            shutil.copy('/usr/share/easy-rsa/pkcs11-easyrsa.cnf', pkcs11_cnf_path)
        
        # Create safessl-easyrsa.cnf if template exists
        safessl_cnf_path = os.path.join(PKI_PATH, 'safessl-easyrsa.cnf')
        if not os.path.exists(safessl_cnf_path) and os.path.exists('/usr/share/easy-rsa/safessl-easyrsa.cnf'):
            shutil.copy('/usr/share/easy-rsa/safessl-easyrsa.cnf', safessl_cnf_path)
        
        # Extract CA serial from certificate and create certs_by_serial link
        try:
            cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'), default_backend())
            serial_hex = format(cert.serial_number, 'X')
            
            # Create symlink in certs_by_serial
            serial_cert_path = os.path.join(PKI_PATH, 'certs_by_serial', f'{serial_hex}.pem')
            if not os.path.exists(serial_cert_path):
                # Copy the CA cert to the serial directory
                with open(serial_cert_path, 'w') as f:
                    f.write(ca_cert_pem)
        except Exception as e:
            logger.warning(f"Could not extract CA serial for certs_by_serial: {e}")
        
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
        
        # Verify the import by checking required files exist
        import_verification = []
        required_files = [
            ('CA Certificate', ca_cert_path),
            ('CA Private Key', ca_key_path),
            ('Serial File', serial_path),
            ('Index File', index_path),
            ('CRL Number', crlnumber_path)
        ]
        
        for file_desc, file_path in required_files:
            if os.path.exists(file_path):
                import_verification.append(f"✓ {file_desc}: {file_path}")
            else:
                import_verification.append(f"✗ {file_desc}: Missing")
        
        verification_text = '\n'.join(import_verification)
        
        return jsonify({
            "status": "success",
            "message": f"Successfully imported CA: {ca_info.get('common_name', 'Unknown')}",
            "ca_info": ca_info,
            "stdout": f"CA certificate and key imported successfully\n\nPKI Structure Created:\n{verification_text}\n\nAll required directories initialized for EasyRSA operations.",
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

def create_pki_backup(params):
    """Create encrypted backup of entire PKI infrastructure"""
    try:
        import base64
        import json
        import gzip
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        import secrets
        
        password = params.get('password', '')
        if not password:
            return jsonify({
                "status": "error",
                "message": "Backup password is required"
            }), 400
        
        logger.info("Starting PKI backup creation")
        
        # Create backup directory structure
        backup_data = {
            'version': '1.0',
            'created': datetime.now().isoformat(),
            'files': {}
        }
        
        # PKI files to backup
        backup_files = [
            'ca.crt',
            'private/ca.key',
            'serial',
            'index.txt',
            'index.txt.attr',
            'crlnumber'
        ]
        
        # Add issued certificates
        issued_dir = os.path.join(PKI_PATH, 'issued')
        if os.path.exists(issued_dir):
            for cert_file in os.listdir(issued_dir):
                if cert_file.endswith('.crt'):
                    backup_files.append(f'issued/{cert_file}')
        
        # Add private keys
        private_dir = os.path.join(PKI_PATH, 'private')
        if os.path.exists(private_dir):
            for key_file in os.listdir(private_dir):
                if key_file.endswith('.key'):
                    backup_files.append(f'private/{key_file}')
        
        # Add revoked certificates
        revoked_dir = os.path.join(PKI_PATH, 'revoked')
        if os.path.exists(revoked_dir):
            for revoked_file in os.listdir(revoked_dir):
                if revoked_file.endswith('.crt'):
                    backup_files.append(f'revoked/{revoked_file}')
        
        # Add CRL files
        crl_pem = os.path.join(PKI_PATH, 'crl.pem')
        if os.path.exists(crl_pem):
            backup_files.append('crl.pem')
        
        # Read all files and add to backup data
        for file_path in backup_files:
            full_path = os.path.join(PKI_PATH, file_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'r') as f:
                        backup_data['files'][file_path] = f.read()
                except Exception as e:
                    logger.warning(f"Could not read file {file_path}: {e}")
        
        # Serialize backup data
        backup_json = json.dumps(backup_data, indent=2)
        
        # Compress data
        compressed_data = gzip.compress(backup_json.encode('utf-8'))
        
        # Encrypt the compressed data
        # Generate salt for key derivation
        salt = secrets.token_bytes(32)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        
        # Generate IV
        iv = secrets.token_bytes(16)
        
        # Encrypt data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad data to 16-byte boundary
        padding_length = 16 - (len(compressed_data) % 16)
        padded_data = compressed_data + bytes([padding_length] * padding_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Create final backup file structure
        final_backup = {
            'format': 'PKI_BACKUP_V1',
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'data': base64.b64encode(encrypted_data).decode('utf-8')
        }
        
        # Convert backup to JSON string (restore expects base64-encoded JSON)
        backup_json = json.dumps(final_backup)
        backup_b64 = base64.b64encode(backup_json.encode('utf-8')).decode('utf-8')
        
        logger.info(f"PKI backup created successfully with {len(backup_data['files'])} files")
        
        return jsonify({
            "status": "success",
            "message": f"PKI backup created with {len(backup_data['files'])} files",
            "backup_data": backup_b64
        })
        
    except Exception as e:
        logger.error(f"Error creating PKI backup: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to create PKI backup: {str(e)}"
        }), 500

def restore_pki_backup(params):
    """Restore PKI infrastructure from encrypted backup"""
    try:
        import base64
        import binascii
        import json
        import gzip
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        logger.info(f"Restore request received with params keys: {list(params.keys())}")
        print(f"RESTORE DEBUG: Restore request received with params keys: {list(params.keys())}")
        
        password = params.get('password', '')
        backup_data_b64 = params.get('backup_data', '')
        
        logger.info(f"Password provided: {bool(password)}, Backup data size: {len(backup_data_b64) if backup_data_b64 else 0}")
        print(f"RESTORE DEBUG: Password provided: {bool(password)}, Backup data size: {len(backup_data_b64) if backup_data_b64 else 0}")
        
        if not password or not backup_data_b64:
            logger.error(f"Missing required parameters. Password: {bool(password)}, Backup data: {bool(backup_data_b64)}")
            print(f"RESTORE DEBUG ERROR: Missing required parameters. Password: {bool(password)}, Backup data: {bool(backup_data_b64)}")
            return jsonify({
                "status": "error",
                "message": "Backup password and data are required"
            }), 400
        
        logger.info("Starting PKI backup restoration")
        print("RESTORE DEBUG: Starting PKI backup restoration")
        
        try:
            # Decode backup data
            logger.info(f"Attempting to decode backup data, length: {len(backup_data_b64)}")
            print(f"RESTORE DEBUG: Attempting to decode backup data, length: {len(backup_data_b64)}")
            backup_bytes = base64.b64decode(backup_data_b64)
            logger.info(f"Decoded backup bytes, length: {len(backup_bytes)}")
            print(f"RESTORE DEBUG: Decoded backup bytes, length: {len(backup_bytes)}")
            
            backup_json = json.loads(backup_bytes.decode('utf-8'))
            logger.info(f"Parsed JSON successfully, keys: {list(backup_json.keys())}")
            print(f"RESTORE DEBUG: Parsed JSON successfully, keys: {list(backup_json.keys())}")
            
            # Verify backup format
            format_version = backup_json.get('format')
            logger.info(f"Backup format: {format_version}")
            print(f"RESTORE DEBUG: Backup format: {format_version}")
            
            if format_version != 'PKI_BACKUP_V1':
                logger.error(f"Invalid backup format: {format_version}, expected: PKI_BACKUP_V1")
                print(f"RESTORE DEBUG ERROR: Invalid backup format: {format_version}, expected: PKI_BACKUP_V1")
                return jsonify({
                    "status": "error",
                    "message": f"Invalid backup file format. Expected PKI_BACKUP_V1, got: {format_version}"
                }), 400
            
            # Extract encryption components
            salt = base64.b64decode(backup_json['salt'])
            iv = base64.b64decode(backup_json['iv'])
            encrypted_data = base64.b64decode(backup_json['data'])
            
            logger.info("Successfully extracted encryption components")
            print("RESTORE DEBUG: Successfully extracted encryption components")
            
        except binascii.Error as e:
            logger.error(f"Base64 decode error: {e}")
            return jsonify({
                "status": "error",
                "message": "Invalid base64 encoding in backup file"
            }), 400
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return jsonify({
                "status": "error",
                "message": "Invalid JSON format in backup file"
            }), 400
        except KeyError as e:
            logger.error(f"Missing required field in backup: {e}")
            return jsonify({
                "status": "error",
                "message": f"Missing required field in backup file: {e}"
            }), 400
        except Exception as e:
            logger.error(f"Backup parsing error: {e}")
            print(f"RESTORE DEBUG FINAL ERROR: Backup parsing error: {e}")
            print(f"RESTORE DEBUG FINAL ERROR: Exception type: {type(e).__name__}")
            import traceback
            print(f"RESTORE DEBUG FINAL ERROR: Traceback: {traceback.format_exc()}")
            return jsonify({
                "status": "error",
                "message": f"Invalid backup file format or corrupted data: {str(e)}"
            }), 400
        
        try:
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
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_data[-1]
            compressed_data = padded_data[:-padding_length]
            
            # Decompress data
            backup_json = gzip.decompress(compressed_data).decode('utf-8')
            backup_data = json.loads(backup_json)
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": "Invalid password or corrupted backup data"
            }), 400
        
        # Backup existing PKI (in case restore fails)
        backup_dir = f"{PKI_PATH}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if os.path.exists(PKI_PATH):
            shutil.move(PKI_PATH, backup_dir)
            logger.info(f"Existing PKI backed up to {backup_dir}")
        
        try:
            # Recreate PKI directory structure
            os.makedirs(PKI_PATH, exist_ok=True)
            os.makedirs(os.path.join(PKI_PATH, 'private'), exist_ok=True)
            os.makedirs(os.path.join(PKI_PATH, 'issued'), exist_ok=True)
            os.makedirs(os.path.join(PKI_PATH, 'revoked'), exist_ok=True)
            
            # Restore all files
            files_restored = 0
            for file_path, content in backup_data.get('files', {}).items():
                full_path = os.path.join(PKI_PATH, file_path)
                
                # Create directory if needed
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                # Write file content
                with open(full_path, 'w') as f:
                    f.write(content)
                
                # Set appropriate permissions for private keys
                if 'private' in file_path or file_path.endswith('.key'):
                    os.chmod(full_path, 0o600)
                
                files_restored += 1
            
            logger.info(f"PKI restoration completed successfully with {files_restored} files restored")
            
            return jsonify({
                "status": "success",
                "message": f"PKI restored successfully from backup. {files_restored} files restored.",
                "backup_version": backup_data.get('version'),
                "backup_date": backup_data.get('created')
            })
            
        except Exception as e:
            # Restore failed, try to restore original PKI
            if os.path.exists(backup_dir):
                if os.path.exists(PKI_PATH):
                    shutil.rmtree(PKI_PATH)
                shutil.move(backup_dir, PKI_PATH)
                logger.error(f"Restore failed, original PKI restored from {backup_dir}")
            
            return jsonify({
                "status": "error",
                "message": f"Failed to restore PKI backup: {str(e)}"
            }), 500
        
    except Exception as e:
        logger.error(f"Error restoring PKI backup: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to restore PKI backup: {str(e)}"
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)