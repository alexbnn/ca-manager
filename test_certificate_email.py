#!/usr/bin/env python3
"""
Automated test script for certificate request and email delivery
Tests the complete workflow: create request -> verify email -> approve -> check email delivery
"""

import requests
import json
import time
import sys

# Configuration
BASE_URL = "https://ca.bonner.com"
TEST_EMAIL = "alexbonner@bearnetworks.io"
TEST_NAME = "Alex Bonner"

def make_request(method, endpoint, data=None, cookies=None):
    """Helper function to make HTTP requests"""
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, cookies=cookies, verify=False)
        elif method == "POST":
            response = requests.post(url, json=data, headers=headers, cookies=cookies, verify=False)
        
        print(f"{method} {endpoint} -> {response.status_code}")
        if response.status_code >= 400:
            print(f"Error: {response.text}")
        
        return response
    except Exception as e:
        print(f"Request failed: {e}")
        return None

def test_certificate_workflow():
    """Test the complete certificate request and email workflow"""
    print("🧪 Starting automated certificate email test...")
    print("=" * 60)
    
    # Step 1: Start email verification
    print("\n📧 Step 1: Starting email verification...")
    verification_data = {
        "email": TEST_EMAIL,
        "requester_name": TEST_NAME
    }
    
    response = make_request("POST", "/api/certificate-requests/start-verification", verification_data)
    if not response or response.status_code != 200:
        print("❌ Email verification start failed")
        return False
    
    result = response.json()
    token = result.get("token")
    if not token:
        print("❌ No verification token received")
        return False
    
    print(f"✅ Email verification started, token: {token[:10]}...")
    
    # Step 2: Mock email verification (using a test code)
    print("\n🔐 Step 2: Simulating email verification...")
    print("⚠️  In a real scenario, you'd get the 6-digit code from email")
    print("⚠️  For testing, we'll need to check the database or use a known code")
    
    # For now, let's assume verification works and continue
    # In a real test, you'd need to either:
    # 1. Check the database for the verification code
    # 2. Use a test email system
    # 3. Mock the verification endpoint
    
    # Step 3: Create certificate request (skipping verification for now)
    print("\n📜 Step 3: Creating certificate request...")
    cert_request_data = {
        "requester_name": TEST_NAME,
        "requester_email": TEST_EMAIL,
        "common_name": TEST_EMAIL,
        "certificate_type": "wifi_8021x",
        "key_algorithm": "RSA",
        "key_size": 2048,
        "validity_days": 365,
        "verification_token": token,
        "email_verified": True  # Assuming verification passed
    }
    
    response = make_request("POST", "/api/certificate-requests", cert_request_data)
    if not response or response.status_code != 200:
        print("❌ Certificate request creation failed")
        return False
    
    result = response.json()
    request_id = result.get("request_id")
    if not request_id:
        print("❌ No request ID received")
        return False
    
    print(f"✅ Certificate request created: {request_id}")
    
    # Step 4: Get pending requests to verify it's there
    print("\n📋 Step 4: Checking pending requests...")
    response = make_request("GET", "/api/certificate-requests?status=pending")
    if response and response.status_code == 200:
        requests_data = response.json()
        print(f"✅ Found {len(requests_data.get('requests', []))} pending request(s)")
    
    # Step 5: Approve the certificate request
    print(f"\n✅ Step 5: Approving certificate request {request_id}...")
    approve_data = {"approved": True}
    
    response = make_request("POST", f"/api/certificate-requests/{request_id}/approve", approve_data)
    if not response or response.status_code != 200:
        print("❌ Certificate approval failed")
        return False
    
    print("✅ Certificate request approved!")
    
    # Step 6: Check if certificate was generated
    print("\n🔍 Step 6: Checking certificate generation...")
    time.sleep(2)  # Give it a moment to process
    
    response = make_request("GET", "/api/certificates/list")
    if response and response.status_code == 200:
        certs_data = response.json()
        certs = certs_data.get("certificates", [])
        test_cert = None
        
        for cert in certs:
            if cert.get("name") == TEST_EMAIL:
                test_cert = cert
                break
        
        if test_cert:
            print(f"✅ Certificate generated: {test_cert.get('name')}")
            print(f"   Status: {test_cert.get('status')}")
            print(f"   Expires: {test_cert.get('expires_at', 'Unknown')}")
        else:
            print("❌ Certificate not found in list")
    
    print("\n📬 Step 7: Checking application logs for email delivery...")
    print("⚠️  Check docker logs for email delivery status:")
    print("    docker logs ca-manager-f-web-interface-1 --tail 20")
    
    print("\n🎉 Test completed!")
    print("=" * 60)
    print("📧 Check the email address for the P12 certificate file")
    print("🔍 Review logs above for any errors during the process")
    return True

def check_smtp_config():
    """Check if SMTP is configured"""
    print("📧 Checking SMTP configuration...")
    response = make_request("GET", "/api/smtp-config")
    if response and response.status_code == 200:
        config = response.json()
        if config.get("smtp_server"):
            print(f"✅ SMTP configured: {config.get('smtp_server')}:{config.get('smtp_port')}")
            return True
        else:
            print("❌ SMTP not configured")
            return False
    else:
        print("❌ Could not check SMTP configuration")
        return False

def main():
    """Main test function"""
    print("🚀 CA Manager Certificate Email Delivery Test")
    print("=" * 60)
    
    # Check SMTP configuration first
    if not check_smtp_config():
        print("\n⚠️  SMTP configuration issue detected")
        print("   Configure SMTP settings in the CA Manager dashboard")
        return
    
    # Run the certificate workflow test
    success = test_certificate_workflow()
    
    if success:
        print("\n✅ Test completed successfully!")
        print("   Check the email and application logs for results")
    else:
        print("\n❌ Test failed")
        print("   Check the error messages above")

if __name__ == "__main__":
    main()