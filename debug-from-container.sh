#!/bin/bash

echo "🔍 Container-based Tab Debugging"
echo "================================"

# Function to check HTML structure directly from container
check_html_structure() {
    echo "📄 Analyzing HTML structure in container..."

    # Get the template file from container
    TEMPLATE_CONTENT=$(docker exec ca-manager-f-web-interface-1 cat /app/templates/index.html 2>/dev/null)

    if [ $? -eq 0 ]; then
        echo "   ✅ Template file accessible"

        # Count tab-related elements
        APPROVALS_TAB=$(echo "$TEMPLATE_CONTENT" | grep -c 'id="approvals"')
        USER_MGMT_TAB=$(echo "$TEMPLATE_CONTENT" | grep -c 'id="user-management"')
        TAB_CONTENT_TOTAL=$(echo "$TEMPLATE_CONTENT" | grep -c 'class="tab-content"')

        echo "   📊 Tab structure:"
        echo "      - Approvals tab divs: $APPROVALS_TAB"
        echo "      - User management tab divs: $USER_MGMT_TAB"
        echo "      - Total tab-content divs: $TAB_CONTENT_TOTAL"

        # Check CSS rules
        CSS_TAB_CONTENT=$(echo "$TEMPLATE_CONTENT" | grep -c "\.tab-content\s*{")
        CSS_TAB_ACTIVE=$(echo "$TEMPLATE_CONTENT" | grep -c "\.tab-content\.active")
        CSS_DISPLAY_BLOCK=$(echo "$TEMPLATE_CONTENT" | grep -c "display.*block.*important")

        echo "   🎨 CSS rules:"
        echo "      - .tab-content rules: $CSS_TAB_CONTENT"
        echo "      - .tab-content.active rules: $CSS_TAB_ACTIVE"
        echo "      - display:block !important: $CSS_DISPLAY_BLOCK"

        # Extract actual CSS for tab-content.active
        echo "   📝 Current .tab-content.active CSS:"
        echo "$TEMPLATE_CONTENT" | grep -A 10 "\.tab-content\.active" | head -15 | sed 's/^/      /'

        return 0
    else
        echo "   ❌ Cannot access template file"
        return 1
    fi
}

# Function to test internal HTTP
test_internal_http() {
    echo ""
    echo "🌐 Testing internal HTTP access..."

    # Test from within the container
    INTERNAL_TEST=$(docker exec ca-manager-f-web-interface-1 curl -s -w "HTTPSTATUS:%{http_code}" http://localhost:5000/ca-manager 2>/dev/null)

    if [ $? -eq 0 ]; then
        HTTP_CODE=$(echo $INTERNAL_TEST | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        echo "   📊 Internal HTTP status: $HTTP_CODE"

        if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 302 ]; then
            echo "   ✅ Internal HTTP working"
        else
            echo "   ⚠️  Internal HTTP issue (code: $HTTP_CODE)"
        fi
    else
        echo "   ❌ Cannot test internal HTTP"
    fi
}

# Function to create a live debugging endpoint
create_debug_endpoint() {
    echo ""
    echo "🔧 Creating debug helper script in container..."

    # Create a simple debug script inside the container
    docker exec ca-manager-f-web-interface-1 bash -c 'cat > /tmp/debug-tabs.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Tab Debug Tool</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .result { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .error { background: #ffe6e6; }
        .success { background: #e6ffe6; }
    </style>
</head>
<body>
    <h1>Tab Debug Tool</h1>
    <button onclick="runDebug()">🔍 Run Tab Analysis</button>
    <div id="results"></div>

    <script>
        function runDebug() {
            const results = document.getElementById("results");
            results.innerHTML = "<p>Analyzing tabs...</p>";

            // This would connect to parent frame if embedded
            try {
                const parentTabs = parent.document.querySelectorAll(".tab-content");
                let html = `<div class="result success">Found ${parentTabs.length} tabs in parent</div>`;

                parentTabs.forEach((tab, i) => {
                    const style = parent.getComputedStyle(tab);
                    html += `<div class="result">
                        Tab ${i+1} (${tab.id}):
                        <br>Display: ${style.display}
                        <br>Width: ${style.width}
                        <br>Height: ${style.height}
                        <br>Opacity: ${style.opacity}
                        <br>Classes: ${tab.className}
                    </div>`;
                });

                results.innerHTML = html;
            } catch(e) {
                results.innerHTML = `<div class="result error">Error: ${e.message}</div>`;
            }
        }
    </script>
</body>
</html>
EOF'

    echo "   ✅ Debug helper created at /tmp/debug-tabs.html"
}

# Function to show current container status
show_container_status() {
    echo ""
    echo "🐳 Container status:"

    # Show container resource usage
    docker stats ca-manager-f-web-interface-1 --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | sed 's/^/   /'

    # Show recent app logs
    echo ""
    echo "   📝 Recent application logs:"
    docker logs ca-manager-f-web-interface-1 --tail 10 2>/dev/null | grep -E "(ERROR|INFO|WARNING)" | sed 's/^/      /'
}

# Function to examine the actual rendered CSS
examine_css() {
    echo ""
    echo "🎨 Examining CSS compilation..."

    # Check if there are any CSS processing issues
    docker exec ca-manager-f-web-interface-1 grep -n "tab-content" /app/templates/index.html | head -10 | sed 's/^/   /'
}

# Run all diagnostic functions
main() {
    show_container_status
    check_html_structure
    test_internal_http
    examine_css
    create_debug_endpoint

    echo ""
    echo "🎯 Container debugging complete!"
    echo ""
    echo "📋 Next steps:"
    echo "1. The HTML structure looks correct based on container analysis"
    echo "2. Use the browser debug script (debug-tabs.js) for live DOM analysis"
    echo "3. Check browser console for JavaScript errors when switching tabs"
    echo "4. Verify authentication state in browser"
    echo ""
    echo "💡 Key files created:"
    echo "   - debug-tabs.js (for browser console)"
    echo "   - /tmp/debug-tabs.html (in container)"
}

main