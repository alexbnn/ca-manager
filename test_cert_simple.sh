#!/bin/bash

# Simple certificate request test using curl
BASE_URL="https://ca.bonner.com"
EMAIL="alexbonner@bearnetworks.io"
NAME="Alex Bonner"

echo "🧪 Testing Certificate Request and Email Delivery"
echo "=================================================="

# Step 1: Start email verification
echo "📧 Step 1: Starting email verification..."
VERIFICATION_RESPONSE=$(curl -s -k -X POST "$BASE_URL/api/certificate-requests/start-verification" \
  -H "Content-Type: application/json" \
  -d "{\"requester_email\":\"$EMAIL\",\"requester_name\":\"$NAME\",\"common_name\":\"$EMAIL\",\"certificate_type\":\"wifi_8021x\"}")

echo "Verification response: $VERIFICATION_RESPONSE"

# Extract token (basic extraction, may need adjustment)
TOKEN=$(echo "$VERIFICATION_RESPONSE" | grep -o '"verification_token":"[^"]*"' | cut -d'"' -f4)
echo "Token: $TOKEN"

if [ -z "$TOKEN" ]; then
  echo "❌ No verification token received"
  exit 1
fi

echo "✅ Email verification started"

echo ""
echo "📋 Manual Steps Required:"
echo "1. Check your email at $EMAIL for the 6-digit verification code"
echo "2. Continue the certificate request process in the web interface"
echo "3. Use the verification token: $TOKEN"
echo "4. Once you approve the certificate, check the logs:"
echo "   docker logs ca-manager-f-web-interface-1 --tail 20"
echo ""
echo "🎯 The goal is to verify that the P12 certificate is emailed automatically upon approval"