#!/bin/bash

echo "iOS SCEP Client Simulator"
echo "============================"

# Get Traefik container IP dynamically
echo "Resolving Traefik container IP..."
TRAEFIK_IP=$(getent hosts traefik | awk '{ print $1 }')

if [ -n "$TRAEFIK_IP" ]; then
    echo "✓ Found Traefik at IP: $TRAEFIK_IP"
    
    # Clean up any existing entries for our domains
    sed -i "/${DOMAIN:-localhost}/d" /etc/hosts 2>/dev/null || true
    
    # Add domain to hosts file pointing to Traefik
    echo "Adding host entries:"
    echo "  - $TRAEFIK_IP ${DOMAIN:-localhost}"
    
    echo "$TRAEFIK_IP ${DOMAIN:-localhost}" >> /etc/hosts
    
    # Also add any other subdomains that might be needed
    if [ "${DOMAIN}" != "localhost" ]; then
        echo "$TRAEFIK_IP www.${DOMAIN}" >> /etc/hosts
        echo "  - $TRAEFIK_IP www.${DOMAIN}"
    fi
    
    echo "✓ Host entries configured successfully"
else
    echo "⚠ Warning: Could not resolve Traefik IP"
    echo "  This may cause connectivity issues with the CA Manager"
    echo "  Using localhost fallback..."
    
    echo "127.0.0.1 ${DOMAIN:-localhost}" >> /etc/hosts
fi

# Display SCEP configuration
echo ""
echo "SCEP Configuration:"
echo "  Server URL: ${SCEP_SERVER_URL}"
echo "  CA Manager: ${CA_MANAGER_BASE_URL}"
echo "  Domain: ${DOMAIN:-localhost}"
echo ""

# Verify connectivity (optional - helps with debugging)
if [ -n "$TRAEFIK_IP" ]; then
    echo "Testing connectivity..."
    if ping -c 1 -W 1 $TRAEFIK_IP > /dev/null 2>&1; then
        echo "✓ Network connectivity to Traefik confirmed"
    else
        echo "⚠ Cannot ping Traefik (this may be normal if ICMP is blocked)"
    fi
fi

echo "Starting simulator on http://localhost:3000"
echo ""

# Start the Flask application
exec python app.py