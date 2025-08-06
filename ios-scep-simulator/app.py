#!/usr/bin/env python3
"""
iOS SCEP Client Simulator
A web application that simulates an iOS device requesting certificates via SCEP
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import requests
import os
import base64
import json
from datetime import datetime
import uuid
import random
import string
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import urllib3
from urllib.parse import urlparse

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Configure app to work with path prefix
app.config['APPLICATION_ROOT'] = '/simulator'
app.secret_key = os.getenv('SECRET_KEY', 'ios-scep-simulator-secret-key-change-in-production')

# Configuration
SCEP_SERVER_BASE_URL = os.getenv('SCEP_SERVER_URL', 'https://localhost')
CA_MANAGER_BASE_URL = os.getenv('CA_MANAGER_BASE_URL', 'https://localhost')
DEFAULT_DEVICE_ID = str(uuid.uuid4())

def generate_apple_serial(device_type='iphone'):
    """Generate a realistic Apple device serial number"""
    # Apple serial format: PPYWWSSSSSS (Production, Year, Week, Unique)
    # First 2 chars: Production location
    locations = ['C0', 'DM', 'F4', 'G9', 'H5', 'J9', 'M7', 'P7', 'R9', 'V0']
    
    # Next char: Production year (2024=4, 2025=5)
    year = random.choice(['4', '5'])
    
    # Next char: Production week (1-9, then A-Z for weeks 10-35)
    week_chars = '123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    week = random.choice(week_chars)
    
    # Next 2 chars: Model identifier varies by device
    model_codes = {
        'iphone': ['YW', 'YX', 'YY', 'YZ', 'ZA', 'ZB'],
        'ipad': ['NK', 'NL', 'NM', 'NN', 'NP', 'NQ'],
        'mac': ['ZW', 'ZX', 'ZY', 'ZZ', 'AA', 'AB'],
        'watch': ['JN', 'JP', 'JQ', 'JR', 'JS', 'JT']
    }
    model_code = random.choice(model_codes.get(device_type, model_codes['iphone']))
    
    # Last 6 chars: Unique identifier
    unique = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    
    return f"{random.choice(locations)}{year}{week}{model_code}{unique}"

def generate_device_name(device_type):
    """Generate a random device name"""
    names = {
        'iphone': [
            "John's iPhone", "Sarah's iPhone", "Mike's iPhone", "Emma's iPhone",
            "Alex's iPhone", "Lisa's iPhone", "David's iPhone", "Amy's iPhone",
            "iPhone 15 Pro", "iPhone 15", "iPhone 14 Pro", "Test iPhone"
        ],
        'ipad': [
            "Office iPad", "Studio iPad", "John's iPad", "Conference iPad",
            "iPad Pro", "Design iPad", "Meeting Room iPad", "Test iPad"
        ],
        'mac': [
            "MacBook Pro", "iMac Pro", "Mac Studio", "Development Mac",
            "Office MacBook", "Design MacBook", "Test Mac", "Admin Mac"
        ],
        'watch': [
            "Apple Watch", "John's Watch", "Fitness Watch", "Office Watch",
            "Test Watch", "Dev Watch", "Admin Watch", "Meeting Watch"
        ]
    }
    return random.choice(names.get(device_type, names['iphone']))

# Base device profile templates (static info)
DEVICE_PROFILE_TEMPLATES = {
    'iphone': {
        'model': 'iPhone16,1',
        'os_version': '17.5.1',
        'icon': '📱',
        'device_type': 'iPhone'
    },
    'ipad': {
        'model': 'iPad14,6',
        'os_version': '17.5.1',
        'icon': '📟',
        'device_type': 'iPad'
    },
    'mac': {
        'model': 'Mac14,9',
        'os_version': '14.5',
        'icon': '💻',
        'device_type': 'Mac'
    },
    'watch': {
        'model': 'Watch6,10',
        'os_version': '10.5',
        'icon': '⌚',
        'device_type': 'Apple Watch'
    }
}

def get_random_device_profile(device_type):
    """Generate a randomized device profile"""
    if device_type not in DEVICE_PROFILE_TEMPLATES:
        return None
    
    template = DEVICE_PROFILE_TEMPLATES[device_type].copy()
    
    # Add randomized data
    template.update({
        'name': generate_device_name(device_type),
        'serial': generate_apple_serial(device_type),
        'udid': str(uuid.uuid4())
    })
    
    return template

def generate_device_key_pair():
    """Generate a private key for the device"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def create_csr(device_profile, private_key, challenge_password=None):
    """Create a Certificate Signing Request (CSR) for the device"""
    with open('/app/logs/debug.log', 'a') as f:
        f.write(f"DEBUG: create_csr called with challenge_password: '{challenge_password}' (type: {type(challenge_password)})\n")
        f.flush()
    # Build the subject name based on device profile
    subject_components = [
        x509.NameAttribute(NameOID.COMMON_NAME, f"{device_profile['name']}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Device"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, device_profile['model']),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, device_profile['serial']),
    ]
    
    subject = x509.Name(subject_components)
    
    # Create CSR builder
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    
    # Add Subject Alternative Name with device identifiers
    san_list = [
        x509.DNSName(f"{device_profile['serial'].lower()}.local"),
        x509.RFC822Name(f"{device_profile['serial']}@device.local"),
    ]
    
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    )
    
    # Add challenge password as CSR attribute if provided
    with open('/app/logs/debug.log', 'a') as f:
        f.write(f"DEBUG: Checking challenge_password: '{challenge_password}' (bool: {bool(challenge_password)})\n")
        f.flush()
    if challenge_password:
        try:
            # Challenge password attribute (OID: 1.2.840.113549.1.9.7)
            # Use UTF8String for proper ASN.1 encoding
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import serialization
            
            # Add challenge password attribute with correct API usage
            builder = builder.add_attribute(
                x509.ObjectIdentifier("1.2.840.113549.1.9.7"),  # Challenge password OID
                challenge_password.encode('utf-8')  # Encode as bytes
            )
            with open('/app/logs/debug.log', 'a') as f:
                f.write(f"Added challenge password attribute: {len(challenge_password)} chars\n")
                f.flush()
        except Exception as e:
            with open('/app/logs/debug.log', 'a') as f:
                f.write(f"ERROR: Could not add challenge password attribute: {e}\n")
                f.write(f"ERROR: Exception type: {type(e)}\n")
                f.flush()
            # Continue without challenge password attribute
    
    # Sign the CSR
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    
    # Debug: Check if CSR has attributes
    with open('/app/logs/debug.log', 'a') as f:
        f.write(f"DEBUG: CSR created with {len(csr.attributes)} attributes\n")
        for i, attr in enumerate(csr.attributes):
            f.write(f"DEBUG: Attribute {i}: OID = {attr.oid.dotted_string}\n")
            if attr.oid.dotted_string == '1.2.840.113549.1.9.7':
                f.write(f"DEBUG: Found challenge password attribute!\n")
        f.flush()
    
    return csr

def perform_scep_getcacert(scep_url):
    """Perform SCEP GetCACert operation against real SCEP server"""
    try:
        # Call the real SCEP server endpoint (same as real devices would)
        response = requests.get(
            f"{scep_url}?operation=GetCACert",
            verify=False,
            timeout=30
        )
        
        if response.status_code == 200:
            return {
                'success': True,
                'ca_cert': base64.b64encode(response.content).decode(),
                'content_type': response.headers.get('content-type', ''),
                'size': len(response.content)
            }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def perform_scep_getcacaps(scep_url):
    """Perform SCEP GetCACaps operation against real SCEP server"""
    try:
        # Call the real SCEP server endpoint (same as real devices would)
        response = requests.get(
            f"{scep_url}?operation=GetCACaps",
            verify=False,
            timeout=30
        )
        
        if response.status_code == 200:
            caps = response.text.strip().split('\n')
            return {
                'success': True,
                'capabilities': caps,
                'raw_response': response.text
            }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def perform_scep_pkioperation(scep_url, csr_pem, device_profile):
    """Perform SCEP PKIOperation (certificate enrollment) against real SCEP server"""
    try:
        # Call the real SCEP server endpoint (same as real devices would)
        # This is a simplified implementation - real SCEP would use PKCS#7 messages
        response = requests.post(
            f"{scep_url}?operation=PKIOperation",
            data=csr_pem,
            headers={
                'Content-Type': 'application/pkcs10',
                'User-Agent': f"iOS/{device_profile['os_version']} ({device_profile['model']})"
            },
            verify=False,
            timeout=30
        )
        
        if response.status_code == 200:
            return {
                'success': True,
                'certificate': base64.b64encode(response.content).decode(),
                'content_type': response.headers.get('content-type', ''),
                'size': len(response.content)
            }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def get_ca_manager_scep_url():
    """Get the correct SCEP URL from CA Manager"""
    try:
        # Try to get SCEP URL from CA Manager API
        response = requests.get(
            f"{CA_MANAGER_BASE_URL}/api/scep/url/public",
            timeout=5,
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                scep_url = data.get('scep_url', '')
                # Remove the identifier part to get base URL
                if '/scep/' in scep_url:
                    base_url = scep_url.rsplit('/scep/', 1)[0]
                    return base_url
        
        # Fallback to environment variable
        return SCEP_SERVER_BASE_URL
        
    except Exception as e:
        print(f"Failed to get SCEP URL from CA Manager: {e}")
        return SCEP_SERVER_BASE_URL

def get_full_scep_url(base_url=None):
    """Get the full SCEP client URL with correct identifier"""
    if base_url is None:
        base_url = get_ca_manager_scep_url()
    
    try:
        # Try to get the full SCEP URL from CA Manager API
        response = requests.get(
            f"{CA_MANAGER_BASE_URL}/api/scep/url/public",
            timeout=5,
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return data.get('scep_url', f"{base_url}/scep/pkiclient")
        
        # Fallback: determine identifier from base URL
        parsed = urlparse(base_url)
        if parsed.hostname:
            subdomain = parsed.hostname.split('.')[0]
            if subdomain == 'localhost' or subdomain == '127':
                identifier = 'pkiclient'
            else:
                identifier = f"pki-{subdomain}"
            return f"{base_url}/scep/{identifier}"
        
        return f"{base_url}/scep/pkiclient"
        
    except Exception as e:
        print(f"Failed to get full SCEP URL: {e}")
        return f"{base_url}/scep/pkiclient"

@app.route('/simulator/')
@app.route('/simulator')
def index():
    """Main page showing device simulator"""
    scep_base_url = get_ca_manager_scep_url()
    return render_template('index.html', 
                         devices=DEVICE_PROFILE_TEMPLATES,
                         scep_server_url=scep_base_url)

@app.route('/simulator/device/<device_type>')
def device_detail(device_type):
    """Device detail page with randomized device data"""
    if device_type not in DEVICE_PROFILE_TEMPLATES:
        flash(f"Unknown device type: {device_type}", 'danger')
        return redirect(url_for('index'))
    
    # Generate random device profile each time
    device = get_random_device_profile(device_type)
    scep_base_url = get_ca_manager_scep_url()
    return render_template('device.html', 
                         device=device, 
                         device_type=device_type,
                         scep_server_url=scep_base_url)

@app.route('/simulator/api/scep/test', methods=['POST'])
def test_scep_connection():
    """Test SCEP server connection"""
    data = request.get_json()
    base_scep_url = data.get('scep_url', get_ca_manager_scep_url())
    # Use the SCEP URL directly as returned by CA Manager
    scep_url = base_scep_url
    
    results = {}
    
    # Test GetCACert
    results['getcacert'] = perform_scep_getcacert(scep_url)
    
    # Test GetCACaps
    results['getcacaps'] = perform_scep_getcacaps(scep_url)
    
    return jsonify({
        'success': True,
        'scep_url': scep_url,
        'tests': results,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/simulator/api/scep/enroll', methods=['POST'])
def scep_enroll():
    """Simulate device certificate enrollment via SCEP"""
    data = request.get_json()
    device_type = data.get('device_type')
    base_scep_url = data.get('scep_url', get_ca_manager_scep_url())
    # Use the SCEP URL directly as returned by CA Manager
    scep_url = base_scep_url
    challenge_password = data.get('challenge_password', '')
    
    if device_type not in DEVICE_PROFILE_TEMPLATES:
        return jsonify({
            'success': False,
            'error': f"Invalid device type: {device_type}"
        }), 400
    
    # Generate random device profile for each enrollment
    device_profile = get_random_device_profile(device_type)
    
    try:
        # Step 1: Generate device key pair
        private_key = generate_device_key_pair()
        
        # Step 2: Create CSR
        csr = create_csr(device_profile, private_key, challenge_password)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        
        # Step 3: Get CA Certificate
        ca_result = perform_scep_getcacert(scep_url)
        
        # Step 4: Get CA Capabilities
        caps_result = perform_scep_getcacaps(scep_url)
        
        # Step 5: Perform enrollment
        enrollment_result = perform_scep_pkioperation(scep_url, csr_pem, device_profile)
        
        # Prepare response
        response = {
            'success': True,
            'device_profile': device_profile,
            'enrollment_steps': {
                'key_generation': {
                    'success': True,
                    'key_size': private_key.key_size,
                    'algorithm': 'RSA'
                },
                'csr_creation': {
                    'success': True,
                    'subject': csr.subject.rfc4514_string(),
                    'csr_pem': csr_pem
                },
                'ca_certificate': ca_result,
                'ca_capabilities': caps_result,
                'enrollment': enrollment_result
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'device_type': device_type,
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/simulator/api/devices')
def list_devices():
    """List available device profile templates"""
    return jsonify({
        'success': True,
        'devices': DEVICE_PROFILE_TEMPLATES,
        'count': len(DEVICE_PROFILE_TEMPLATES)
    })

@app.route('/simulator/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'iOS SCEP Simulator',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    print("iOS SCEP Client Simulator")
    print("============================")
    print(f"SCEP Server: {SCEP_SERVER_BASE_URL}")
    print("Starting simulator on http://localhost:3000")
    print("")
    
    app.run(host='0.0.0.0', port=3000, debug=True)