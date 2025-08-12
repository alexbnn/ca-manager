#!/usr/bin/env python3
"""
OCSP (Online Certificate Status Protocol) Responder
Handles OCSP requests for certificate status checking
"""

from flask import Flask, request, Response, jsonify
import requests
import os
import base64
import logging
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
import struct
import hashlib

app = Flask(__name__)

# Configuration
CA_MANAGER_URL = os.getenv('CA_MANAGER_URL', 'http://ca-manager:5000')
EASYRSA_CONTAINER_URL = os.getenv('EASYRSA_CONTAINER_URL', 'http://easyrsa-container:8080')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

# Configure logging with fallback for permission issues
def setup_logging():
    handlers = [logging.StreamHandler()]  # Always have console output
    
    # Try to add file handler, fall back gracefully if permissions fail
    log_file_paths = [
        '/app/logs/ocsp.log',  # Primary location (Docker volume)
        '/tmp/ocsp.log',       # Fallback location
    ]
    
    for log_path in log_file_paths:
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            # Test write permissions
            test_file = log_path + '.test'
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            # If we get here, we can write to this location
            handlers.append(logging.FileHandler(log_path))
            break
        except (PermissionError, OSError, IOError) as e:
            print(f"Cannot write to {log_path}: {e}")
            continue
    
    logging.basicConfig(
        level=logging.DEBUG if DEBUG_MODE else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

setup_logging()

logger = logging.getLogger(__name__)

# OCSP Response Status
OCSP_GOOD = 0
OCSP_REVOKED = 1
OCSP_UNKNOWN = 2

# Cache for CA certificate and private key
ca_cert_cache = None
ca_key_cache = None
cache_timestamp = None
CACHE_DURATION = 300  # 5 minutes

def get_ca_certificate_and_key():
    """Get CA certificate and private key for signing OCSP responses"""
    global ca_cert_cache, ca_key_cache, cache_timestamp
    
    # Check cache validity
    if (cache_timestamp and ca_cert_cache and ca_key_cache and 
        datetime.now() - cache_timestamp < timedelta(seconds=CACHE_DURATION)):
        return ca_cert_cache, ca_key_cache
    
    try:
        # Get CA certificate
        ca_response = requests.get(f"{EASYRSA_CONTAINER_URL}/download-ca", timeout=30)
        if ca_response.status_code != 200:
            logger.error("Failed to download CA certificate")
            return None, None
            
        ca_cert_pem = ca_response.text
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
        
        # Get CA private key
        key_response = requests.post(
            f"{EASYRSA_CONTAINER_URL}/execute",
            json={"operation": "get-ca-key"},
            timeout=30
        )
        
        if key_response.status_code != 200:
            logger.error("Failed to get CA private key")
            return None, None
            
        key_data = key_response.json()
        if key_data.get('status') != 'success':
            logger.error(f"CA key retrieval failed: {key_data.get('message')}")
            return None, None
            
        ca_key_pem = key_data.get('private_key', '')
        if not ca_key_pem:
            logger.error("No private key in response")
            return None, None
            
        ca_key = serialization.load_pem_private_key(
            ca_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Update cache
        ca_cert_cache = ca_cert
        ca_key_cache = ca_key
        cache_timestamp = datetime.now()
        
        logger.info("CA certificate and key loaded successfully")
        return ca_cert, ca_key
        
    except Exception as e:
        logger.error(f"Error loading CA certificate and key: {e}")
        return None, None

def get_certificate_status(serial_number):
    """Check certificate status from CA Manager database"""
    try:
        # Query CA Manager for certificate status
        response = requests.get(
            f"{CA_MANAGER_URL}/api/ocsp/status/{serial_number}",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                cert_status = data.get('certificate_status')
                if cert_status == 'valid':
                    return OCSP_GOOD, None, None
                elif cert_status == 'revoked':
                    revocation_time = data.get('revocation_time')
                    revocation_reason = data.get('revocation_reason', 0)  # Default: unspecified
                    return OCSP_REVOKED, revocation_time, revocation_reason
                else:
                    return OCSP_UNKNOWN, None, None
            else:
                logger.warning(f"Certificate status check failed: {data.get('message')}")
                return OCSP_UNKNOWN, None, None
        else:
            logger.warning(f"Certificate status API returned {response.status_code}")
            return OCSP_UNKNOWN, None, None
            
    except Exception as e:
        logger.error(f"Error checking certificate status: {e}")
        return OCSP_UNKNOWN, None, None

def parse_ocsp_request(request_data):
    """Parse OCSP request from binary data"""
    try:
        # Parse the OCSP request
        ocsp_request = ocsp.load_der_ocsp_request(request_data)
        
        # Debug: log available attributes
        logger.debug(f"OCSP request attributes: {dir(ocsp_request)}")
        
        # Extract certificate serial number from the first (and typically only) request
        # Try different ways to access the request data
        single_requests = None
        
        # Method 1: Check for single_requests attribute
        if hasattr(ocsp_request, 'single_requests'):
            single_requests = ocsp_request.single_requests
            logger.debug(f"Found single_requests: {len(single_requests) if single_requests else 0}")
        
        # Method 2: Check for requests attribute  
        elif hasattr(ocsp_request, 'requests'):
            single_requests = ocsp_request.requests
            logger.debug(f"Found requests: {len(single_requests) if single_requests else 0}")
            
        # Method 3: Try accessing as iterator (older versions)
        else:
            try:
                single_requests = [req for req in ocsp_request]
                logger.debug(f"Iterator method found: {len(single_requests)} requests")
            except:
                logger.debug("Iterator method failed")
                
        # Method 4: Try direct access to first item
        if not single_requests:
            try:
                # Maybe it has a different structure - try direct access
                if hasattr(ocsp_request, 'serial_number'):
                    # Direct serial number access
                    serial_number = ocsp_request.serial_number
                    logger.info(f"OCSP request for certificate serial (direct): {serial_number}")
                    return serial_number, getattr(ocsp_request, 'nonce', None)
            except:
                pass
            
        if not single_requests:
            logger.error("No single requests found in OCSP request")
            logger.debug(f"OCSP request type: {type(ocsp_request)}")
            return None, None
            
        single_request = single_requests[0]  # Get first SingleRequest
        serial_number = single_request.serial_number
        
        logger.info(f"OCSP request for certificate serial: {serial_number}")
        return serial_number, getattr(ocsp_request, 'nonce', None)
        
    except Exception as e:
        logger.error(f"Error parsing OCSP request: {e}")
        return None, None

def create_ocsp_response(serial_number, cert_status, revocation_time=None, revocation_reason=None, nonce=None):
    """Create and sign OCSP response"""
    try:
        ca_cert, ca_key = get_ca_certificate_and_key()
        if not ca_cert or not ca_key:
            logger.error("Cannot create OCSP response: CA cert/key not available")
            return None
            
        # Create response based on certificate status
        logger.info(f"Creating OCSP response for status: {cert_status} (GOOD={OCSP_GOOD}, REVOKED={OCSP_REVOKED}, UNKNOWN={OCSP_UNKNOWN})")
        
        if cert_status == OCSP_GOOD:
            cert_status_obj = ocsp.OCSPCertStatus.GOOD
            logger.info("Using GOOD status")
        elif cert_status == OCSP_REVOKED:
            logger.info("Using REVOKED status")
            # Parse revocation time if provided
            if revocation_time:
                if isinstance(revocation_time, str):
                    revoked_time = datetime.fromisoformat(revocation_time.replace('Z', '+00:00'))
                else:
                    revoked_time = revocation_time
            else:
                revoked_time = datetime.now()
            
            # Use simple revoked status - details will be in the add_response call
            cert_status_obj = ocsp.OCSPCertStatus.REVOKED
        else:  # UNKNOWN
            cert_status_obj = ocsp.OCSPCertStatus.UNKNOWN
            logger.info("Using UNKNOWN status")
            
        # Build the OCSP response
        builder = ocsp.OCSPResponseBuilder()
        
        # Add responder ID (required before signing)
        builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
        
        # Create dummy certificate for OCSP response (placeholder)
        # In a real implementation, you'd use the actual certificate being checked
        dummy_cert = ca_cert
        
        # Add single response - cryptography 45+ requires all parameters
        if cert_status == OCSP_REVOKED:
            # For revoked certificates, use actual revocation details
            rev_time = revoked_time if 'revoked_time' in locals() else datetime.now()
            rev_reason = revocation_reason or x509.ReasonFlags.unspecified
        else:
            # For GOOD and UNKNOWN certificates, use None values
            rev_time = None
            rev_reason = None
            
        builder = builder.add_response(
            cert=dummy_cert,
            issuer=ca_cert, 
            algorithm=hashes.SHA1(),
            cert_status=cert_status_obj,
            this_update=datetime.now(),
            next_update=datetime.now() + timedelta(hours=24),
            revocation_time=rev_time,
            revocation_reason=rev_reason
        )
        
        # Add nonce if present in request
        if nonce:
            builder = builder.add_extension(
                x509.OCSPNonce(nonce), critical=False
            )
            
        # Sign the response
        response = builder.sign(ca_key, hashes.SHA256())
        
        logger.info(f"OCSP response created for serial {serial_number}, status: {cert_status}")
        return response.public_bytes(serialization.Encoding.DER)
        
    except Exception as e:
        logger.error(f"Error creating OCSP response: {e}")
        return None

@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        # Test CA Manager connectivity
        ca_manager_healthy = False
        try:
            response = requests.get(f"{CA_MANAGER_URL}/health", timeout=5)
            ca_manager_healthy = response.status_code == 200
        except:
            pass
            
        # Test EasyRSA connectivity  
        easyrsa_healthy = False
        try:
            response = requests.get(f"{EASYRSA_CONTAINER_URL}/health", timeout=5)
            easyrsa_healthy = response.status_code == 200
        except:
            pass
            
        status = "healthy" if (ca_manager_healthy and easyrsa_healthy) else "degraded"
        
        return jsonify({
            "status": status,
            "ocsp_responder": "online",
            "ca_manager_connection": "healthy" if ca_manager_healthy else "unhealthy",
            "easyrsa_connection": "healthy" if easyrsa_healthy else "unhealthy",
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 503

@app.route('/ocsp', methods=['GET', 'POST'])
def ocsp_endpoint():
    """Main OCSP endpoint for certificate status requests"""
    try:
        if request.method == 'GET':
            # Handle GET request with base64-encoded OCSP request in URL
            ocsp_request_b64 = request.args.get('ocsp')
            if not ocsp_request_b64:
                return jsonify({"error": "Missing OCSP request parameter"}), 400
                
            try:
                request_data = base64.b64decode(ocsp_request_b64)
            except Exception as e:
                logger.error(f"Invalid base64 OCSP request: {e}")
                return jsonify({"error": "Invalid base64 encoding"}), 400
                
        elif request.method == 'POST':
            # Handle POST request with binary OCSP request in body
            request_data = request.data
            if not request_data:
                return jsonify({"error": "Empty OCSP request"}), 400
        else:
            return jsonify({"error": "Method not allowed"}), 405
            
        logger.info(f"OCSP {request.method} request received, size: {len(request_data)} bytes")
        
        # Parse OCSP request
        serial_number, nonce = parse_ocsp_request(request_data)
        if serial_number is None:
            logger.error("Failed to parse OCSP request")
            return Response(
                b"",  # Empty response for malformed requests
                status=400,
                mimetype='application/ocsp-response'
            )
            
        # Get certificate status
        cert_status, revocation_time, revocation_reason = get_certificate_status(serial_number)
        
        # Create OCSP response
        response_data = create_ocsp_response(
            serial_number, cert_status, revocation_time, revocation_reason, nonce
        )
        
        if response_data is None:
            logger.error("Failed to create OCSP response")
            return Response(
                b"",  # Empty response for internal errors
                status=500,
                mimetype='application/ocsp-response'
            )
            
        logger.info(f"OCSP response sent for serial {serial_number}, status: {cert_status}")
        return Response(
            response_data,
            status=200,
            mimetype='application/ocsp-response',
            headers={
                'Content-Length': str(len(response_data)),
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            }
        )
        
    except Exception as e:
        logger.error(f"OCSP endpoint error: {e}")
        return Response(
            b"",  # Empty response for errors
            status=500,
            mimetype='application/ocsp-response'
        )

@app.route('/debug')
def debug_info():
    """Debug endpoint for troubleshooting"""
    if not DEBUG_MODE:
        return jsonify({"error": "Debug mode disabled"}), 403
        
    try:
        ca_cert, ca_key = get_ca_certificate_and_key()
        
        debug_info = {
            "ocsp_responder_status": "running",
            "ca_manager_url": CA_MANAGER_URL,
            "easyrsa_container_url": EASYRSA_CONTAINER_URL,
            "ca_certificate_loaded": ca_cert is not None,
            "ca_key_loaded": ca_key is not None,
            "cache_valid": cache_timestamp is not None and datetime.now() - cache_timestamp < timedelta(seconds=CACHE_DURATION),
            "debug_mode": DEBUG_MODE,
            "timestamp": datetime.now().isoformat()
        }
        
        if ca_cert:
            debug_info["ca_cert_subject"] = ca_cert.subject.rfc4514_string()
            debug_info["ca_cert_serial"] = str(ca_cert.serial_number)
            
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Create logs directory
    os.makedirs('/app/logs', exist_ok=True)
    
    logger.info("Starting OCSP Responder...")
    logger.info(f"CA Manager URL: {CA_MANAGER_URL}")
    logger.info(f"EasyRSA Container URL: {EASYRSA_CONTAINER_URL}")
    logger.info(f"Debug Mode: {DEBUG_MODE}")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=8091, debug=DEBUG_MODE)