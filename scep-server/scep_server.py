# scep_server.py - SCEP (Simple Certificate Enrollment Protocol) Server
# This server provides SCEP endpoints for device certificate enrollment

from flask import Flask, request, Response, jsonify
import requests
import os
import base64
import logging
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import tempfile
import time

app = Flask(__name__)

# Configuration
EASYRSA_CONTAINER_URL = os.getenv('EASYRSA_CONTAINER_URL', 'http://easyrsa-container:8080')
SCEP_CA_IDENTIFIER_DEFAULT = os.getenv('SCEP_CA_IDENTIFIER', 'pkiclient')

def get_scep_identifier_from_host(host):
    """Generate SCEP identifier from request host"""
    if not host or '.' not in host:
        return SCEP_CA_IDENTIFIER_DEFAULT
    
    subdomain = host.split('.')[0]
    if subdomain in ['localhost', '127']:
        return 'pkiclient'
    else:
        return f"pki-{subdomain}"

DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/scep.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# SCEP Content Types
SCEP_CONTENT_TYPE = 'application/x-pki-message'
SCEP_CA_CERT_CONTENT_TYPE = 'application/x-x509-ca-cert'
SCEP_CA_CHAIN_CONTENT_TYPE = 'application/x-x509-ca-ra-cert-chain'

# SCEP Operations
SCEP_OPERATIONS = {
    'GetCACert': 'Get CA Certificate',
    'GetCACaps': 'Get CA Capabilities', 
    'PKIOperation': 'Certificate Enrollment/Renewal'
}

# SCEP Password Configuration (Always Enabled)
# Try to load from database first via the web interface, fallback to env var
SCEP_PASSWORD = os.getenv('SCEP_PASSWORD', 'MySecretSCEPPassword123')

# Function to load password from database via web interface
def load_password_from_database():
    """Load SCEP password from database through web interface"""
    global SCEP_PASSWORD
    try:
        # Query the web interface internal endpoint to get the stored password
        response = requests.get(
            "http://web-interface:5000/api/internal/scep-password",
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('password'):
                SCEP_PASSWORD = data['password']
                logger.info(f"Loaded SCEP password from database (length: {len(SCEP_PASSWORD)})")
                return True
    except Exception as e:
        logger.warning(f"Could not load password from database: {e}")
    
    # Fallback to environment variable
    SCEP_PASSWORD = os.getenv('SCEP_PASSWORD', 'MySecretSCEPPassword123')
    logger.info(f"Using environment variable for SCEP password (length: {len(SCEP_PASSWORD)})")
    return False

def extract_challenge_password(csr):
    """Extract challenge password from CSR attributes"""
    try:
        # Look for challengePassword in CSR attributes
        for attribute in csr.attributes:
            # Challenge password OID is 1.2.840.113549.1.9.7
            if attribute.oid.dotted_string == '1.2.840.113549.1.9.7':
                # Extract the password value
                try:
                    # Try to get the value directly from the attribute
                    if hasattr(attribute, 'value'):
                        password = attribute.value
                        if isinstance(password, bytes):
                            password = password.decode('utf-8')
                        elif isinstance(password, list) and len(password) > 0:
                            # Handle list of values
                            password = password[0]
                            if isinstance(password, bytes):
                                password = password.decode('utf-8')
                        logger.info(f"Challenge password extracted from CSR: {len(password)} chars")
                        return str(password)
                    else:
                        # Try iterating over attribute values
                        for value in attribute:
                            if hasattr(value, 'value'):
                                password = value.value
                                if isinstance(password, bytes):
                                    password = password.decode('utf-8')
                                logger.info("Challenge password extracted from CSR (iterable)")
                                return password
                            else:
                                # Direct string value
                                password = str(value)
                                logger.info("Challenge password extracted from CSR (direct)")
                                return password
                except Exception as e:
                    logger.error(f"Error processing challenge password attribute: {e}")
                    continue
        
        logger.info("No challenge password found in CSR")
        return None
        
    except Exception as e:
        logger.error(f"Error extracting challenge password: {e}")
        return None

def validate_scep_password(provided_password):
    """Validate SCEP challenge password (Always Enabled)"""
    try:
        # If no password is configured, require password to be enabled
        if not SCEP_PASSWORD:
            logger.warning("SCEP password protection enabled but no password configured")
            return False
        
        # Check if provided password matches configured password
        if provided_password == SCEP_PASSWORD:
            logger.info("SCEP challenge password validated successfully")
            return True
        else:
            logger.warning(f"SCEP challenge password validation failed - provided: {provided_password}")
            return False
            
    except Exception as e:
        logger.error(f"Error validating SCEP password: {e}")
        return False

@app.route('/health')
def health():
    """Health check endpoint with faster timeout for responsiveness"""
    try:
        # Quick health check with short timeout to avoid blocking
        response = requests.get(f"{EASYRSA_CONTAINER_URL}/health", timeout=3)
        easyrsa_healthy = response.status_code == 200
        
        return jsonify({
            "status": "healthy" if easyrsa_healthy else "degraded",
            "scep_server": "online",
            "easyrsa_connection": "healthy" if easyrsa_healthy else "unhealthy",
            "timestamp": datetime.now().isoformat()
        }), 200
    except requests.exceptions.Timeout:
        logger.warning("Health check timeout - EasyRSA container may be busy")
        return jsonify({
            "status": "degraded",
            "scep_server": "online",
            "easyrsa_connection": "timeout",
            "message": "EasyRSA container timeout (may be busy)",
            "timestamp": datetime.now().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 503

@app.route('/scep')
def scep_info():
    """SCEP endpoint information"""
    return jsonify({
        "scep_server": "Extreme Networks PKI SCEP Server",
        "version": "1.0",
        "supported_operations": SCEP_OPERATIONS,
        "endpoints": {
            "scep_url": f"{request.host_url}scep/{get_scep_identifier_from_host(request.headers.get('Host', 'localhost'))}",
            "getcacert": f"{request.host_url}scep/{get_scep_identifier_from_host(request.headers.get('Host', 'localhost'))}?operation=GetCACert",
            "getcacaps": f"{request.host_url}scep/{get_scep_identifier_from_host(request.headers.get('Host', 'localhost'))}?operation=GetCACaps"
        },
        "ca_identifier": get_scep_identifier_from_host(request.headers.get('Host', 'localhost'))
    })

@app.route('/scep/<scep_identifier>', methods=['GET', 'POST'])
def scep_endpoint(scep_identifier):
    """Main SCEP endpoint for certificate operations"""
    try:
        # Validate the SCEP identifier matches expected pattern
        host = request.headers.get('Host', 'localhost')
        expected_identifier = get_scep_identifier_from_host(host)
        
        if scep_identifier != expected_identifier:
            logger.warning(f"SCEP identifier mismatch: got {scep_identifier}, expected {expected_identifier} for host {host}")
            return jsonify({"error": "Invalid SCEP identifier"}), 404
        
        operation = request.args.get('operation')
        message = request.args.get('message')
        
        logger.info(f"SCEP {request.method} request - Operation: {operation}, Identifier: {scep_identifier}")
        
        if request.method == 'GET':
            if operation == 'GetCACert':
                return handle_get_ca_cert()
            elif operation == 'GetCACaps':
                return handle_get_ca_caps()
            else:
                return jsonify({"error": "Invalid operation"}), 400
                
        elif request.method == 'POST':
            if operation == 'PKIOperation':
                return handle_pki_operation()
            else:
                return jsonify({"error": "Invalid operation"}), 400
                
    except Exception as e:
        logger.error(f"SCEP endpoint error: {e}")
        return jsonify({"error": str(e)}), 500

def handle_get_ca_cert():
    """Handle GetCACert operation - return CA certificate"""
    try:
        logger.info("Handling GetCACert request")
        
        # Get CA certificate from EasyRSA container with longer timeout
        response = requests.post(
            f"{EASYRSA_CONTAINER_URL}/execute",
            json={"operation": "show-ca"},
            timeout=60
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to get CA info: {response.status_code}")
            return jsonify({"error": "CA not available"}), 503
            
        ca_info = response.json()
        if ca_info.get('status') != 'success':
            logger.error(f"CA show failed: {ca_info.get('message')}")
            return jsonify({"error": "CA not available"}), 503
        
        # Download CA certificate file with longer timeout
        ca_response = requests.get(f"{EASYRSA_CONTAINER_URL}/download-ca", timeout=60)
        if ca_response.status_code != 200:
            logger.error("Failed to download CA certificate")
            return jsonify({"error": "CA certificate not available"}), 503
            
        ca_cert_data = ca_response.content
        
        logger.info("Successfully retrieved CA certificate")
        return Response(
            ca_cert_data,
            mimetype=SCEP_CA_CERT_CONTENT_TYPE,
            headers={
                'Content-Disposition': 'attachment; filename="ca.pem"',
                'Content-Length': str(len(ca_cert_data))
            }
        )
        
    except Exception as e:
        logger.error(f"GetCACert error: {e}")
        return jsonify({"error": str(e)}), 500

def handle_get_ca_caps():
    """Handle GetCACaps operation - return CA capabilities"""
    try:
        logger.info("Handling GetCACaps request")
        
        # Define SCEP capabilities
        capabilities = [
            "Renewal",          # Certificate renewal
            "SHA-1",           # SHA-1 hash algorithm
            "SHA-256",         # SHA-256 hash algorithm  
            "DES3",            # 3DES encryption
            "AES",             # AES encryption
            "POSTPKIOperation", # POST for PKI operations
        ]
        
        caps_text = "\n".join(capabilities)
        
        logger.info(f"Returning CA capabilities: {capabilities}")
        return Response(
            caps_text,
            mimetype='text/plain',
            headers={'Content-Length': str(len(caps_text))}
        )
        
    except Exception as e:
        logger.error(f"GetCACaps error: {e}")
        return jsonify({"error": str(e)}), 500

def handle_pki_operation():
    """Handle PKIOperation - certificate enrollment/renewal"""
    try:
        logger.info("Handling PKIOperation request")
        
        # Get the PKCS#7 message from request body
        if not request.data:
            logger.error("No PKCS#7 message in request body")
            return jsonify({"error": "No PKCS#7 message provided"}), 400
            
        pkcs7_data = request.data
        logger.info(f"Received PKIOperation request, size: {len(pkcs7_data)} bytes")
        
        # For SCEP simulator and simple CSR requests, try to parse as PEM CSR directly
        # In a full SCEP implementation, this would parse PKCS#7 messages
        try:
            # Try to decode as PEM CSR first (for simulator compatibility)
            csr_pem = pkcs7_data.decode('utf-8')
            
            # Validate it's a CSR
            if '-----BEGIN CERTIFICATE REQUEST-----' in csr_pem and '-----END CERTIFICATE REQUEST-----' in csr_pem:
                logger.info("Received PEM-encoded CSR from SCEP client")
                
                # Parse the CSR to extract subject information and challenge password
                csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
                
                # Extract challenge password from CSR attributes
                challenge_password = extract_challenge_password(csr)
                
                # Validate challenge password if SCEP protection is enabled
                if not validate_scep_password(challenge_password):
                    logger.error("SCEP challenge password validation failed")
                    return jsonify({
                        "status": "error",
                        "message": "Invalid or missing SCEP challenge password"
                    }), 401
                
                # Generate a unique certificate name based on CSR subject
                subject_name = None
                for attribute in csr.subject:
                    if attribute.oid == NameOID.COMMON_NAME:
                        subject_name = attribute.value
                        break
                
                # If no CN found, generate one based on serial number or timestamp
                if not subject_name:
                    for attribute in csr.subject:
                        if attribute.oid == NameOID.SERIAL_NUMBER:
                            subject_name = f"device-{attribute.value}"
                            break
                
                if not subject_name:
                    subject_name = f"scep-device-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                
                # Clean the subject name for filesystem use and make it unique
                base_cert_name = subject_name.replace(' ', '-').replace('/', '-').replace('\\', '-')
                # Add timestamp to ensure uniqueness
                cert_name = f"{base_cert_name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                logger.info(f"Processing certificate request for: {cert_name}")
                
                # Save CSR to EasyRSA and sign it
                result = process_csr_enrollment(csr_pem, cert_name)
                
                if result['success']:
                    logger.info(f"Certificate enrollment successful for {cert_name}")
                    # Return the signed certificate in DER format for SCEP compatibility
                    cert_data = base64.b64decode(result['certificate_b64'])
                    return Response(
                        cert_data,
                        mimetype=SCEP_CONTENT_TYPE,
                        headers={
                            'Content-Disposition': f'attachment; filename="{cert_name}.crt"',
                            'Content-Length': str(len(cert_data))
                        },
                        status=200
                    )
                else:
                    logger.error(f"Certificate enrollment failed: {result['error']}")
                    return jsonify({
                        "status": "error",
                        "message": f"Certificate enrollment failed: {result['error']}"
                    }), 500
            else:
                # Not a PEM CSR, might be PKCS#7 - not implemented yet
                logger.warning("Received non-PEM data, PKCS#7 parsing not implemented")
                return jsonify({
                    "status": "error",
                    "message": "PKCS#7 message parsing not implemented. Send PEM CSR directly."
                }), 501
                
        except UnicodeDecodeError:
            # Binary data, might be PKCS#7
            logger.warning("Received binary data, PKCS#7 parsing not implemented")
            return jsonify({
                "status": "error", 
                "message": "PKCS#7 message parsing not implemented. Send PEM CSR directly."
            }), 501
        
    except Exception as e:
        logger.error(f"PKIOperation error: {e}")
        return jsonify({"error": str(e)}), 500

def process_csr_enrollment(csr_pem, cert_name):
    """Process CSR enrollment by saving to EasyRSA and signing"""
    try:
        logger.info(f"Processing CSR enrollment for certificate: {cert_name}")
        
        # Step 1: Save CSR to EasyRSA container
        csr_save_result = save_csr_to_easyrsa(csr_pem, cert_name)
        if not csr_save_result['success']:
            return {
                'success': False,
                'error': f"Failed to save CSR: {csr_save_result['error']}"
            }
        
        # Step 2: Generate full client certificate using EasyRSA (simplified approach)
        sign_result = communicate_with_easyrsa('build-client-full', {
            'name': cert_name
        })
        
        if not sign_result or sign_result.get('status') != 'success':
            error_msg = sign_result.get('message', 'Unknown error') if sign_result else 'No response from EasyRSA'
            logger.error(f"Failed to sign certificate {cert_name}: {error_msg}")
            return {
                'success': False,
                'error': f"Certificate signing failed: {error_msg}"
            }
        
        # Step 3: Retrieve the signed certificate
        cert_result = get_certificate_from_easyrsa(cert_name)
        if not cert_result['success']:
            return {
                'success': False,
                'error': f"Failed to retrieve signed certificate: {cert_result['error']}"
            }
        
        logger.info(f"Certificate enrollment completed successfully for {cert_name}")
        return {
            'success': True,
            'certificate_pem': cert_result['certificate_pem'],
            'certificate_b64': cert_result['certificate_b64'],
            'cert_name': cert_name
        }
        
    except Exception as e:
        logger.error(f"CSR enrollment processing error: {e}")
        return {
            'success': False,
            'error': str(e)
        }

def save_csr_to_easyrsa(csr_pem, cert_name):
    """Skip CSR saving step - simplified approach for SCEP simulator"""
    # For the SCEP simulator, we skip the CSR import step and let EasyRSA
    # generate its own key pair during the build-client-full operation
    logger.info(f"Skipping CSR import for SCEP simulator - ready for certificate generation: {cert_name}")
    return {'success': True}

def get_certificate_from_easyrsa(cert_name):
    """Retrieve signed certificate from EasyRSA container using existing download endpoint"""
    try:
        logger.info(f"Retrieving signed certificate for: {cert_name}")
        
        # Use the existing get-cert-files operation to get certificate
        response = requests.post(
            f"{EASYRSA_CONTAINER_URL}/execute",
            json={
                'operation': 'get-cert-files',
                'params': {
                    'name': cert_name
                }
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success' and result.get('certificate'):
                cert_data = result['certificate']
                # Convert to base64 for transport
                cert_b64 = base64.b64encode(cert_data.encode()).decode()
                
                logger.info(f"Certificate retrieved successfully for {cert_name}")
                return {
                    'success': True,
                    'certificate_pem': cert_data,
                    'certificate_b64': cert_b64
                }
            else:
                error_msg = result.get('message', 'Certificate not found')
                logger.error(f"Failed to retrieve certificate: {error_msg}")
                return {'success': False, 'error': error_msg}
        else:
            logger.error(f"Failed to retrieve certificate: HTTP {response.status_code}")
            return {'success': False, 'error': f"HTTP {response.status_code}"}
            
    except Exception as e:
        logger.error(f"Error retrieving certificate from EasyRSA: {e}")
        return {'success': False, 'error': str(e)}

def communicate_with_easyrsa(operation, params=None):
    """Helper function to communicate with EasyRSA container"""
    try:
        payload = {"operation": operation}
        if params:
            payload["params"] = params
            
        response = requests.post(
            f"{EASYRSA_CONTAINER_URL}/execute",
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"EasyRSA communication failed: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"EasyRSA communication error: {e}")
        return None

@app.route('/debug')
def debug_info():
    """Debug endpoint for troubleshooting"""
    if not DEBUG_MODE:
        return jsonify({"error": "Debug mode disabled"}), 403
        
    try:
        # Test EasyRSA communication
        easyrsa_status = communicate_with_easyrsa("status")
        
        return jsonify({
            "scep_server_status": "running",
            "easyrsa_container_url": EASYRSA_CONTAINER_URL,
            "easyrsa_status": easyrsa_status,
            "ca_identifier": get_scep_identifier_from_host(request.headers.get('Host', 'localhost')),
            "debug_mode": DEBUG_MODE,
            "supported_operations": SCEP_OPERATIONS,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/reload-config', methods=['POST'])
def reload_config():
    """Reload SCEP server configuration (mainly password)"""
    try:
        global SCEP_PASSWORD
        
        # Check if new password is provided in request
        data = request.get_json() if request.is_json else {}
        new_password = data.get('password') if data else None
        
        if new_password:
            # Update from request data
            os.environ['SCEP_PASSWORD'] = new_password
            SCEP_PASSWORD = new_password
            logger.info(f"SCEP password updated via API request (length: {len(new_password)})")
        else:
            # Just return current status without changing anything
            # (Don't reload from environment unless explicitly requested)
            logger.info(f"SCEP configuration status requested (current length: {len(SCEP_PASSWORD)})")
        
        return jsonify({
            "status": "success",
            "message": "SCEP configuration reloaded successfully",
            "password_length": len(SCEP_PASSWORD),
            "current_password": SCEP_PASSWORD,  # Include actual password for admin queries
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error reloading SCEP configuration: {e}")
        return jsonify({
            "status": "error", 
            "error": str(e)
        }), 500

# Initialize on module load (works with gunicorn)
os.makedirs('/app/logs', exist_ok=True)
logger.info("SCEP Server module loading...")
logger.info(f"EasyRSA Container URL: {EASYRSA_CONTAINER_URL}")
logger.info(f"Debug Mode: {DEBUG_MODE}")

# Try to load password from database on startup
# Add a small delay to ensure web-interface is ready
time.sleep(5)
load_password_from_database()

if __name__ == '__main__':
    # Run the Flask app directly (for development)
    logger.info("Starting SCEP Server in development mode...")
    app.run(host='0.0.0.0', port=8090, debug=DEBUG_MODE)