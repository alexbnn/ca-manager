#!/usr/bin/env python3
"""
OCSP Client Simulator
A web application that simulates OCSP certificate status checking
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import requests
import os
import base64
import json
from datetime import datetime, timedelta
import urllib3
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Configure app to work with path prefix
app.config['APPLICATION_ROOT'] = '/ocsp-simulator'
app.secret_key = os.getenv('SECRET_KEY', 'ocsp-simulator-secret-key-change-in-production')

# Configuration
OCSP_RESPONDER_URL = os.getenv('OCSP_RESPONDER_URL', 'http://localhost:8080')
CA_MANAGER_BASE_URL = os.getenv('CA_MANAGER_BASE_URL', 'https://localhost')
DOMAIN = os.getenv('DOMAIN', 'localhost')

@app.route('/ocsp-simulator/')
def index():
    """OCSP simulator main page"""
    # Show external URLs for configuration display
    external_ocsp_url = f"https://ca.{DOMAIN}/ocsp" if DOMAIN != 'localhost' else 'https://ca.localhost/ocsp'
    
    return render_template('index.html', 
                         ocsp_responder_url=external_ocsp_url,
                         ca_manager_url=CA_MANAGER_BASE_URL)

@app.route('/ocsp-simulator/check', methods=['POST'])
def check_certificate():
    """Check certificate status via OCSP"""
    try:
        cert_data = request.form.get('certificate')
        serial_number = request.form.get('serial_number')
        
        if not cert_data and not serial_number:
            return jsonify({'error': 'Please provide either a certificate or serial number'})
        
        # If certificate is provided, extract serial number and other details
        if cert_data:
            try:
                # Handle different certificate formats
                if '-----BEGIN CERTIFICATE-----' in cert_data:
                    cert_pem = cert_data
                else:
                    # Assume base64 encoded
                    cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"
                
                cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                serial_number = str(cert.serial_number)
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                
            except Exception as e:
                return jsonify({'error': f'Invalid certificate format: {str(e)}'})
        else:
            subject = "Unknown (serial number only)"
            issuer = "Unknown (serial number only)"
        
        # Make OCSP request
        ocsp_response = make_ocsp_request(serial_number)
        
        return jsonify({
            'success': True,
            'serial_number': serial_number,
            'subject': subject,
            'issuer': issuer,
            'ocsp_response': ocsp_response
        })
        
    except Exception as e:
        return jsonify({'error': f'OCSP check failed: {str(e)}'})

def get_ca_certificate():
    """Get the CA certificate from the EasyRSA container (same source as OCSP responder)"""
    try:
        # Get CA certificate from EasyRSA container - same endpoint the OCSP responder uses
        easyrsa_url = "http://easyrsa-container:8080/download-ca"
        response = requests.get(easyrsa_url, timeout=10)
        
        if response.status_code == 200:
            ca_cert_pem = response.text
            if ca_cert_pem and 'BEGIN CERTIFICATE' in ca_cert_pem:
                return x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
    except Exception as e:
        print(f"Error getting CA certificate: {e}")
    
    return None

def create_ocsp_request(serial_number, ca_cert):
    """Create a proper OCSP request using cryptography library"""
    try:
        from cryptography.x509 import ocsp
        from cryptography.hazmat.primitives import hashes
        
        # Convert serial number to integer
        if isinstance(serial_number, str):
            if serial_number.isdigit():
                serial_int = int(serial_number)
            else:
                # Try to parse as hex
                hex_serial = serial_number.replace('0x', '').replace('0X', '')
                serial_int = int(hex_serial, 16)
        else:
            serial_int = int(serial_number)
        
        # Create a dummy certificate with the serial number we want to check
        # This is needed because OCSP requests require the actual certificate being checked
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from datetime import datetime, timedelta
        
        # Generate a temporary key pair for the dummy cert
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create a dummy certificate with the target serial number
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "dummy-cert-for-ocsp")
        ])
        
        dummy_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject  # Use CA as issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_int  # Use the serial number we want to check
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=1)
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Create OCSP request using the dummy certificate
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            cert=dummy_cert,
            issuer=ca_cert,
            algorithm=hashes.SHA1()
        )
        
        ocsp_request = builder.build()
        return ocsp_request.public_bytes(serialization.Encoding.DER)
        
    except Exception as e:
        raise Exception(f"Failed to create OCSP request: {str(e)}")

def parse_ocsp_response(response_data):
    """Parse OCSP response"""
    try:
        from cryptography.x509 import ocsp
        
        ocsp_response = ocsp.load_der_ocsp_response(response_data)
        
        if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
            # Handle different ways to access single responses
            if hasattr(ocsp_response, 'single_responses'):
                single_responses = ocsp_response.single_responses
            else:
                # Try alternative property names
                single_responses = getattr(ocsp_response, 'responses', [])
                if not single_responses:
                    # Try as iterable - convert to list first
                    try:
                        single_responses = list(ocsp_response)
                    except TypeError:
                        # If it can't be iterated, try to access directly
                        single_responses = []
                    
            if not single_responses:
                return {
                    'error': 'No single responses found in OCSP response'
                }
                
            # Handle iterator-based access
            try:
                single_response = single_responses[0]
            except (TypeError, IndexError):
                # If subscript doesn't work, try iterator
                try:
                    single_response = next(iter(single_responses))
                except (StopIteration, TypeError):
                    return {
                        'error': 'Unable to access single response from OCSP response'
                    }
            
            status_map = {
                ocsp.OCSPCertStatus.GOOD: 'good',
                ocsp.OCSPCertStatus.REVOKED: 'revoked', 
                ocsp.OCSPCertStatus.UNKNOWN: 'unknown'
            }
            
            cert_status = status_map.get(single_response.certificate_status, 'unknown')
            
            result = {
                'certificate_status': cert_status,
                'serial_number': str(single_response.serial_number),
                'this_update': single_response.this_update.isoformat() if single_response.this_update else None,
                'next_update': single_response.next_update.isoformat() if single_response.next_update else None
            }
            
            if cert_status == 'revoked' and hasattr(single_response, 'revocation_time'):
                result['revocation_time'] = single_response.revocation_time.isoformat()
                if hasattr(single_response, 'revocation_reason'):
                    result['revocation_reason'] = str(single_response.revocation_reason)
            
            return result
        else:
            return {
                'error': f'OCSP response status: {ocsp_response.response_status}'
            }
            
    except Exception as e:
        return {
            'error': f'Failed to parse OCSP response: {str(e)}'
        }

def make_ocsp_request(serial_number):
    """Make real OCSP request for given serial number"""
    try:
        # Get CA certificate first
        ca_cert = get_ca_certificate()
        if not ca_cert:
            return {
                'status': 'error',
                'error_message': 'Could not retrieve CA certificate from CA Manager'
            }
        
        # Create proper OCSP request
        try:
            ocsp_request_data = create_ocsp_request(serial_number, ca_cert)
        except Exception as e:
            return {
                'status': 'error',
                'error_message': f'Failed to create OCSP request: {str(e)}'
            }
        
        # Send OCSP request to the responder
        ocsp_url = f"{OCSP_RESPONDER_URL}/ocsp"
        
        try:
            # Try POST request first (binary data)
            response = requests.post(
                ocsp_url,
                data=ocsp_request_data,
                headers={'Content-Type': 'application/ocsp-request'},
                verify=False,
                timeout=10
            )
            
            if response.status_code != 200:
                # Try GET request with base64 encoding
                ocsp_request_b64 = base64.b64encode(ocsp_request_data).decode()
                response = requests.get(
                    ocsp_url,
                    params={'ocsp': ocsp_request_b64},
                    verify=False,
                    timeout=10
                )
            
            if response.status_code == 200:
                # Check if response is binary OCSP response or JSON error
                content_type = response.headers.get('content-type', '')
                
                if 'application/ocsp-response' in content_type:
                    # Parse binary OCSP response
                    ocsp_result = parse_ocsp_response(response.content)
                    ocsp_result['status'] = 'success'
                    ocsp_result['response_type'] = 'binary'
                    return ocsp_result
                else:
                    # Try to parse as JSON
                    try:
                        json_response = response.json()
                        if 'error' in json_response:
                            return {
                                'status': 'error',
                                'error_message': json_response['error'],
                                'response_type': 'json'
                            }
                        else:
                            return {
                                'status': 'success',
                                'response_type': 'json',
                                **json_response
                            }
                    except:
                        return {
                            'status': 'error',
                            'error_message': f'Unexpected response format: {response.text[:200]}',
                            'http_status': response.status_code
                        }
            else:
                return {
                    'status': 'error',
                    'http_status': response.status_code,
                    'error_message': response.text[:500] if response.text else f'HTTP {response.status_code}'
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'error_message': f'Network error: {str(e)}'
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'error_message': f'Unexpected error: {str(e)}'
        }

@app.route('/ocsp-simulator/test-scenarios')
def test_scenarios():
    """Test common OCSP scenarios"""
    return render_template('test_scenarios.html')

@app.route('/ocsp-simulator/test/<scenario>', methods=['POST'])
def run_test_scenario(scenario):
    """Run predefined test scenarios"""
    try:
        if scenario == 'valid_cert':
            # Test with a known valid certificate serial from the database
            result = make_ocsp_request('7424325A781AF9A59E2450B7E94ADA62')  # David's iPhone - Valid
            
        elif scenario == 'revoked_cert':
            # Test with a known revoked certificate
            result = make_ocsp_request('5C0CFB0FD3D5B3C86E6A42A8B611493B')  # alexbonner@extr.com - Revoked
            
        elif scenario == 'unknown_cert':
            # Test with unknown certificate
            result = make_ocsp_request('ABCDEF123456789012345678')
            
        else:
            return jsonify({'error': 'Unknown test scenario'})
        
        return jsonify({
            'success': True,
            'scenario': scenario,
            'result': result
        })
        
    except Exception as e:
        return jsonify({'error': f'Test scenario failed: {str(e)}'})

@app.route('/ocsp-simulator/health')
def health():
    """Health check endpoint"""
    # Show external URL for health endpoint as well
    external_ocsp_url = f"https://ca.{DOMAIN}/ocsp" if DOMAIN != 'localhost' else 'https://ca.localhost/ocsp'
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'ocsp_responder': external_ocsp_url
    })

if __name__ == '__main__':
    print(f"OCSP Client Simulator")
    print(f"OCSP Server: {OCSP_RESPONDER_URL}")
    app.run(host='0.0.0.0', port=4000, debug=True)