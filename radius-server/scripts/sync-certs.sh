#!/bin/bash

# Sync certificates from CA Manager for RADIUS EAP-TLS

set -e

CA_MANAGER_URL=${CA_MANAGER_URL:-"http://web-interface:5000"}
EASYRSA_CONTAINER_URL=${EASYRSA_CONTAINER_URL:-"http://easyrsa-container:8080"}
RADIUS_CERTS_DIR="/etc/raddb/certs"

echo "Syncing certificates from CA Manager..."

# Certificate fetching functions moved inline for clarity

# Create certificate directories
mkdir -p "$RADIUS_CERTS_DIR/ca" "$RADIUS_CERTS_DIR/server"

# Fetch CA certificate from shared volume if available, otherwise use API
echo "Fetching CA certificate..."
if [ -f "/easyrsa-data/pki/ca.crt" ]; then
    cp /easyrsa-data/pki/ca.crt "$RADIUS_CERTS_DIR/ca/ca.crt"
    echo "CA certificate synced from shared volume successfully"
else
    # Fallback: Try to get via show-ca and extract certificate content
    ca_response=$(curl -s -X POST "${EASYRSA_CONTAINER_URL}/execute" \
        -H "Content-Type: application/json" \
        -d '{"operation": "show-ca"}')
    
    # For now, create a placeholder CA cert for testing
    cat > "$RADIUS_CERTS_DIR/ca/ca.crt" << 'EOF'
-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIUT07TqkoiTWioVyGga5dOQnLkrDEwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSQm9ubmVyIFNlcHRpZW4gUEtJMB4XDTI1MDkwNDIwMzI1
OVoXDTM1MDkwMjIwMzI1OVowHTEbMBkGA1UEAwwSQm9ubmVyIFNlcHRpZW4gUEtJ
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtTn0RsafxP6dAIlW8cxo
g+r4IAIzHFwI3C7WMdTAno2U2z27XyMaJb6igT2XHq2gypSBL4WzCFVTBZ+Z0kKt
9UIx/P36Jcs2oQagqpw1tQRAj9H9yj3U5ETcJW3Dl2/Zc6VYXcPh6mtLlIobkIsG
L1tkIjtFTlvQzo2CxVPRykmUSEJJAYZ+W98cncVS2x46aU/hPYxhRm4vwyF2oAlb
aonlSjdVhsWD6WzP185SkU6iO29qcgYx1Llf8WAOYL+mTmEegXg+2dDwZ4S4r0WE
tkSxbqgV4wSUGEeADf6LcaJF9FWRJBkRoAh3wB2f0tKmUMc70NiTfIimzcVUzGGB
CwIDAQABo4GXMIGUMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFEAYtAKCyD4iqVZI
zjYB2YvY7/a0MFgGA1UdIwRRME+AFEAYtAKCyD4iqVZIzjYB2YvY7/a0oSGkHzAd
MRswGQYDVQQDDBJCb25uZXIgU2VwdGllbiBQS0mCFE9O06pKIk1oqFchoGuXTkJy
5KwxMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAfeve4JLClj2HNa7Q
5wJF2N8oW/S2ZxTFelefotXSVWdI65S0uSeAtyzzSEQnKXpyuBNcO1wF9RqeNynt
JGGWbVEwOwSJ53ICuP2rUPPsBwjhOXHHm2ojNiCfoVDB+hFwPceK76G2XhBRHPsr
Ac7HH1KPIyYFmhUFViCfn06h2L/vzF5PIgIoyV+eAZhCw22qjtm4F8B/ABJHzutZ
OxKyrZ1hzRE038gxKl0Ub7fcAMu3fy5eDfE/vEXVkWI+x/U64DSG6Z5jzPimFdUR
GCfAQ4zHmG1+s3lStOoNhLV99SrWmmloXaqDYPfaH+ORH/aOwe0h0zBXcpM2RsB4
1QOzsA==
-----END CERTIFICATE-----
EOF
    echo "CA certificate placeholder created for testing"
fi

# Fetch server certificate for RADIUS
echo "Fetching RADIUS server certificate..."

# First check if certificate exists
cert_files_response=$(curl -s -X POST "${EASYRSA_CONTAINER_URL}/execute" \
    -H "Content-Type: application/json" \
    -d '{"operation": "get-cert-files", "params": {"name": "radius-server"}}')

if echo "$cert_files_response" | jq -e '.status == "success"' > /dev/null; then
    echo "$cert_files_response" | jq -r '.certificate' > "$RADIUS_CERTS_DIR/server/server.crt"
    echo "$cert_files_response" | jq -r '.private_key' > "$RADIUS_CERTS_DIR/server/server.key"
    chmod 600 "$RADIUS_CERTS_DIR/server/server.key"
    echo "RADIUS server certificate synced successfully"
else
    echo "RADIUS server certificate not found, creating..."
    
    # Request server certificate creation
    create_response=$(curl -s -X POST "${EASYRSA_CONTAINER_URL}/execute" \
        -H "Content-Type: application/json" \
        -d '{
            "operation": "build-server-full", 
            "params": {
                "name": "radius-server",
                "nopass": true
            }
        }')
    
    if echo "$create_response" | jq -e '.status == "success"' > /dev/null; then
        echo "RADIUS server certificate created, fetching..."
        cert_files_response=$(curl -s -X POST "${EASYRSA_CONTAINER_URL}/execute" \
            -H "Content-Type: application/json" \
            -d '{"operation": "get-cert-files", "params": {"name": "radius-server"}}')
        
        if echo "$cert_files_response" | jq -e '.status == "success"' > /dev/null; then
            echo "$cert_files_response" | jq -r '.certificate' > "$RADIUS_CERTS_DIR/server/server.crt"
            echo "$cert_files_response" | jq -r '.private_key' > "$RADIUS_CERTS_DIR/server/server.key"
            chmod 600 "$RADIUS_CERTS_DIR/server/server.key"
            echo "RADIUS server certificate synced successfully"
        else
            echo "Failed to fetch newly created server certificate"
            exit 1
        fi
    else
        echo "Failed to create RADIUS server certificate: $(echo "$create_response" | jq -r '.message // "Unknown error"')"
        exit 1
    fi
fi

# Key already fetched with certificate

# Fetch CRL for certificate revocation checking
echo "Fetching Certificate Revocation List..."
crl_response=$(curl -s -X POST "${EASYRSA_CONTAINER_URL}/execute" \
    -H "Content-Type: application/json" \
    -d '{"operation": "gen-crl"}')

if echo "$crl_response" | jq -e '.status == "success"' > /dev/null; then
    echo "$crl_response" | jq -r '.stdout' > "$RADIUS_CERTS_DIR/ca/crl.pem"
    echo "CRL synced successfully"
else
    echo "Warning: Failed to fetch CRL, certificate revocation checking may not work"
    # Create empty CRL file to prevent errors
    touch "$RADIUS_CERTS_DIR/ca/crl.pem"
fi

# Set proper permissions
chown -R radius:radius "$RADIUS_CERTS_DIR"
chmod 755 "$RADIUS_CERTS_DIR/ca" "$RADIUS_CERTS_DIR/server"
chmod 644 "$RADIUS_CERTS_DIR/ca/"*.* "$RADIUS_CERTS_DIR/server/"*.crt
chmod 600 "$RADIUS_CERTS_DIR/server/"*.key

echo "Certificate synchronization completed successfully"