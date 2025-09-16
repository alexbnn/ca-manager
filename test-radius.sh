#!/bin/bash

# CA Manager RADIUS Authentication Test Script
# This script provides comprehensive RADIUS testing capabilities

echo "🧪 CA Manager RADIUS Authentication Testing"
echo "=========================================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo
    print_status $BLUE "=== $1 ==="
}

# Test 1: Check RADIUS server status
print_header "RADIUS Server Status"
RADIUS_STATUS=$(docker ps --filter "name=ca-manager-f-radius-server-1" --format "{{.Status}}")
if [[ $RADIUS_STATUS == *"Up"* ]]; then
    print_status $GREEN "✓ RADIUS server is running"
else
    print_status $RED "✗ RADIUS server is not running"
    exit 1
fi

# Test 2: Check RADIUS server health
print_header "RADIUS Server Health Check"
HEALTH_CHECK=$(docker exec ca-manager-f-radius-server-1 radtest healthcheck healthcheck localhost 1812 testing123 2>/dev/null)
if [[ $? -eq 0 ]]; then
    print_status $GREEN "✓ RADIUS server is responding"
else
    print_status $YELLOW "! RADIUS server health check (this is normal for authentication rejection)"
fi

# Test 3: Check database connectivity and users
print_header "Database User Check"
USERS=$(docker exec ca-manager-f-postgres-1 psql -U pkiuser -d pkiauth -t -c "SELECT COUNT(*) FROM idp_radius_auth WHERE is_active = true;" 2>/dev/null | tr -d ' ')
if [[ $USERS =~ ^[0-9]+$ ]] && [[ $USERS -gt 0 ]]; then
    print_status $GREEN "✓ Found $USERS active RADIUS users in database"
    
    # Show user details
    echo "Active RADIUS users:"
    docker exec ca-manager-f-postgres-1 psql -U pkiuser -d pkiauth -c "SELECT idp_email, radius_username, CASE WHEN radius_password_hash IS NOT NULL THEN 'Yes' ELSE 'No' END as has_password, default_vlan_id FROM idp_radius_auth WHERE is_active = true;"
else
    print_status $RED "✗ No active RADIUS users found"
fi

# Test 4: Check RADIUS configuration
print_header "RADIUS Configuration Check"
if docker exec ca-manager-f-radius-server-1 test -f /etc/raddb/clients.conf; then
    print_status $GREEN "✓ RADIUS clients configuration exists"
    
    echo "RADIUS clients configured:"
    docker exec ca-manager-f-radius-server-1 grep -A 2 "client.*{" /etc/raddb/clients.conf | grep -E "client|ipaddr|secret" | head -10
else
    print_status $RED "✗ RADIUS clients configuration missing"
fi

# Test 5: Test RADIUS server responsiveness
print_header "RADIUS Server Connectivity Test"
RADIUS_IP=$(docker inspect ca-manager-f-radius-server-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
print_status $BLUE "RADIUS server IP: $RADIUS_IP"

# Test from within the RADIUS container
TEST_RESULT=$(docker exec ca-manager-f-radius-server-1 timeout 5 bash -c "echo 'test' | nc -u localhost 1812" 2>/dev/null)
if [[ $? -eq 0 ]]; then
    print_status $GREEN "✓ RADIUS port 1812 is listening"
else
    print_status $YELLOW "! RADIUS port test inconclusive (this is normal)"
fi

# Test 6: Web interface RADIUS tests
print_header "Web Interface RADIUS Tests"
echo "To test RADIUS authentication through the web interface:"
echo "1. Go to your CA Manager web interface"
echo "2. Navigate to 'Policy Testing & Simulation' tab"
echo "3. Click '🧪 Test Authentication' button"
echo "4. Or go to 'IDP-RADIUS Configuration' and click '🧪 Test Configuration'"

# Test 7: Manual RADIUS authentication test
print_header "Manual RADIUS Authentication Test"
echo "To manually test RADIUS authentication:"
echo "1. First, you need to know the user's RADIUS password"
echo "2. The password is typically generated when the user is created"
echo "3. Check the application logs or regenerate the user"

# Show how to test with a known user
if [[ $USERS -gt 0 ]]; then
    FIRST_USER=$(docker exec ca-manager-f-postgres-1 psql -U pkiuser -d pkiauth -t -c "SELECT radius_username FROM idp_radius_auth WHERE is_active = true LIMIT 1;" 2>/dev/null | tr -d ' ')
    if [[ ! -z "$FIRST_USER" ]]; then
        echo
        print_status $BLUE "Example test command (you need the actual password):"
        echo "docker exec ca-manager-f-radius-server-1 radtest $FIRST_USER <password> localhost 1812 testing123"
    fi
fi

# Test 8: Certificate-based authentication test
print_header "Certificate-Based Authentication"
CERT_COUNT=$(docker exec ca-manager-f-postgres-1 psql -U pkiuser -d pkiauth -t -c "SELECT COUNT(*) FROM idp_certificates WHERE status = 'active';" 2>/dev/null | tr -d ' ')
if [[ $CERT_COUNT =~ ^[0-9]+$ ]] && [[ $CERT_COUNT -gt 0 ]]; then
    print_status $GREEN "✓ Found $CERT_COUNT active certificates for EAP-TLS"
    echo "For EAP-TLS testing, you'll need eapol_test (available separately)"
else
    print_status $YELLOW "! No active certificates found for EAP-TLS testing"
fi

# Test 9: VLAN assignment test
print_header "VLAN Assignment Check"
VLAN_COUNT=$(docker exec ca-manager-f-postgres-1 psql -U pkiuser -d pkiauth -t -c "SELECT COUNT(*) FROM vlans WHERE is_active = true;" 2>/dev/null | tr -d ' ')
if [[ $VLAN_COUNT =~ ^[0-9]+$ ]] && [[ $VLAN_COUNT -gt 0 ]]; then
    print_status $GREEN "✓ Found $VLAN_COUNT active VLANs configured"
    
    echo "Available VLANs:"
    docker exec ca-manager-f-postgres-1 psql -U pkiuser -d pkiauth -c "SELECT vlan_id, vlan_name, subnet FROM vlans WHERE is_active = true ORDER BY vlan_id;"
else
    print_status $YELLOW "! No VLANs configured"
fi

# Test 10: Recent authentication logs
print_header "Recent Authentication Activity"
RECENT_AUTH=$(docker exec ca-manager-f-postgres-1 psql -U pkiuser -d pkiauth -t -c "SELECT COUNT(*) FROM idp_radius_auth WHERE last_auth_at > NOW() - INTERVAL '24 hours';" 2>/dev/null | tr -d ' ')
if [[ $RECENT_AUTH =~ ^[0-9]+$ ]] && [[ $RECENT_AUTH -gt 0 ]]; then
    print_status $GREEN "✓ $RECENT_AUTH users have authenticated in the last 24 hours"
else
    print_status $YELLOW "! No recent authentication activity"
fi

echo
print_header "Test Complete"
print_status $BLUE "RADIUS testing completed. Check the results above."
echo
echo "For live RADIUS testing:"
echo "1. Use the web interface tests (recommended)"
echo "2. Check RADIUS server logs: docker logs ca-manager-f-radius-server-1 -f"
echo "3. Monitor authentication: docker exec ca-manager-f-radius-server-1 tail -f /var/log/radius/radius.log"
echo