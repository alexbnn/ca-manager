#!/bin/bash

echo "🔍 Automatic Tab Debugging Tool"
echo "================================"

DOMAIN="ca.bonnerseptien.com"
BASE_URL="https://$DOMAIN"

# Function to test if page loads
test_page_load() {
    echo "📡 Testing page load..."

    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -k "$BASE_URL/ca-manager" \
        -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

    HTTP_CODE=$(echo $RESPONSE | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    BODY=$(echo $RESPONSE | sed -E 's/HTTPSTATUS:[0-9]*$//')

    echo "   HTTP Status: $HTTP_CODE"

    if [ "$HTTP_CODE" -eq 200 ]; then
        echo "   ✅ Page loads successfully"

        # Check if tab content exists in HTML
        APPROVALS_COUNT=$(echo "$BODY" | grep -c 'id="approvals"')
        USER_MGMT_COUNT=$(echo "$BODY" | grep -c 'id="user-management"')
        TAB_CONTENT_COUNT=$(echo "$BODY" | grep -c 'class="tab-content"')

        echo "   📊 Tab analysis:"
        echo "      - Approvals tab: $APPROVALS_COUNT found"
        echo "      - User management tab: $USER_MGMT_COUNT found"
        echo "      - Total tab-content elements: $TAB_CONTENT_COUNT found"

        # Check CSS rules
        CSS_ACTIVE_COUNT=$(echo "$BODY" | grep -c "\.tab-content\.active")
        CSS_DISPLAY_COUNT=$(echo "$BODY" | grep -c "display.*block.*important")

        echo "   🎨 CSS analysis:"
        echo "      - .tab-content.active rules: $CSS_ACTIVE_COUNT found"
        echo "      - display:block !important rules: $CSS_DISPLAY_COUNT found"

        # Check for JavaScript
        SWITCH_TAB_COUNT=$(echo "$BODY" | grep -c "function switchTab")

        echo "   🔧 JavaScript analysis:"
        echo "      - switchTab function: $SWITCH_TAB_COUNT found"

        return 0
    else
        echo "   ❌ Page failed to load (HTTP $HTTP_CODE)"
        return 1
    fi
}

# Function to inject debug script via browser automation
inject_debug_script() {
    echo ""
    echo "🚀 Debug script created at: $(pwd)/debug-tabs.js"
    echo ""
    echo "📋 Manual debugging steps:"
    echo "1. Open browser and go to: $BASE_URL/ca-manager"
    echo "2. Open Developer Tools (F12)"
    echo "3. Go to Console tab"
    echo "4. Copy and paste the debug script:"
    echo ""
    echo "   // Copy from here:"
    cat debug-tabs.js | head -20
    echo "   // ... (see debug-tabs.js for full script)"
    echo ""
    echo "5. The script will automatically analyze the tabs"
    echo ""
}

# Function to check docker containers
check_containers() {
    echo "🐳 Checking Docker containers..."

    WEB_STATUS=$(docker ps --filter "name=ca-manager-f-web-interface-1" --format "{{.Status}}")

    if [ -n "$WEB_STATUS" ]; then
        echo "   ✅ Web interface: $WEB_STATUS"
    else
        echo "   ❌ Web interface container not running"
        return 1
    fi

    # Check recent logs for errors
    echo "   📝 Recent logs:"
    docker logs ca-manager-f-web-interface-1 --tail 5 2>/dev/null | sed 's/^/      /'
}

# Function to test API endpoints
test_api_endpoints() {
    echo ""
    echo "🔌 Testing API endpoints..."

    # Test authentication status
    AUTH_RESPONSE=$(curl -s -k "$BASE_URL/api/auth/status" | jq -r '.authenticated // "unknown"' 2>/dev/null || echo "error")
    echo "   🔐 Authentication: $AUTH_RESPONSE"

    # Test metrics endpoint
    METRICS_RESPONSE=$(curl -s -k "$BASE_URL/api/metrics" -w "HTTPSTATUS:%{http_code}")
    METRICS_CODE=$(echo $METRICS_RESPONSE | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    echo "   📊 Metrics endpoint: HTTP $METRICS_CODE"
}

# Run all tests
main() {
    check_containers

    if [ $? -eq 0 ]; then
        test_page_load
        test_api_endpoints
        inject_debug_script

        echo ""
        echo "🎯 Automatic debugging complete!"
        echo "💡 For real-time debugging, run the JavaScript in your browser console."
    fi
}

# Make script executable and run
chmod +x "$0"
main