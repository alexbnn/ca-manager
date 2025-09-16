#!/bin/bash

# Simple RADIUS Test Script
echo "🔐 Simple RADIUS Authentication Test"
echo "=================================="

# Get the RADIUS username
echo "Getting RADIUS user information..."
RADIUS_USER=$(docker exec ca-manager-f-postgres-1 psql -U pkiuser -d pkiauth -t -c "SELECT radius_username FROM idp_radius_auth WHERE is_active = true LIMIT 1;" 2>/dev/null | tr -d ' ')

if [[ -z "$RADIUS_USER" ]]; then
    echo "❌ No active RADIUS users found!"
    echo "Please create a user through the IDP authentication first."
    exit 1
fi

echo "✅ Found RADIUS user: $RADIUS_USER"
echo

# Test different authentication scenarios
echo "Testing RADIUS authentication scenarios:"
echo

# Test 1: Wrong password (should fail)
echo "1️⃣  Testing with wrong password (should fail):"
docker exec ca-manager-f-radius-server-1 radtest $RADIUS_USER wrongpassword localhost 1812 testing123
echo

# Test 2: Empty password (should fail)
echo "2️⃣  Testing with empty password (should fail):"
docker exec ca-manager-f-radius-server-1 radtest $RADIUS_USER "" localhost 1812 testing123
echo

# Test 3: Different authentication types
echo "3️⃣  Testing CHAP authentication:"
docker exec ca-manager-f-radius-server-1 radtest -t chap $RADIUS_USER testpassword localhost 1812 testing123
echo

echo "4️⃣  Testing MSCHAP authentication:"
docker exec ca-manager-f-radius-server-1 radtest -t mschap $RADIUS_USER testpassword localhost 1812 testing123
echo

# Show recent RADIUS logs
echo "📋 Recent RADIUS server activity:"
docker logs ca-manager-f-radius-server-1 --tail 10
echo

echo "🔍 To check RADIUS authentication in real-time:"
echo "   docker logs ca-manager-f-radius-server-1 -f"
echo
echo "💡 Note: The password for RADIUS users is typically auto-generated."
echo "   Check the web interface or application logs for the actual password."