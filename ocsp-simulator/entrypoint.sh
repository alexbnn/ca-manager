#!/bin/bash

echo "OCSP Client Simulator"
echo "====================="

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

# Display OCSP configuration
echo ""
echo "OCSP Configuration:"
echo "  OCSP Responder URL: ${OCSP_RESPONDER_URL}"
echo "  CA Manager: ${CA_MANAGER_BASE_URL}"
echo "  Domain: ${DOMAIN:-localhost}"
echo ""

echo "Starting OCSP simulator on http://localhost:4000"
echo ""

# Start the Flask application
exec python app.py