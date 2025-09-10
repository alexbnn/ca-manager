#!/bin/bash

# FreeRADIUS startup script with CA Manager integration

set -e

echo "Starting FreeRADIUS with CA Manager integration..."

# Initialize FreeRADIUS configuration with minimal changes to default
echo "Initializing FreeRADIUS configuration..."

echo "Applying FreeRADIUS customizations..."

# Always apply our custom EAP configuration
echo "Applying EAP-TLS certificate configuration..."
cp /etc/raddb-custom/mods-available/eap /etc/raddb/mods-available/eap

# Override clients config
cp /etc/raddb-custom/clients.conf /etc/raddb/clients.conf

# Ensure our configuration is properly applied
echo "Verifying EAP configuration..."
if grep -q "client = yes" /etc/raddb/mods-available/eap; then
    echo "ERROR: Default EAP config detected, fixing..."
    sed -i 's/client = yes/# client = yes/g' /etc/raddb/mods-available/eap
fi

echo "FreeRADIUS configuration applied successfully"

chown -R radius:radius /etc/raddb
chmod -R 755 /etc/raddb

# Wait for CA Manager to be available
echo "Waiting for CA Manager to be available..."
until curl -f -s http://web-interface:5000/health > /dev/null 2>&1; do
    echo "Waiting for CA Manager..."
    sleep 5
done

echo "CA Manager is available, syncing certificates..."

# Sync certificates from CA Manager
/opt/radius-scripts/sync-certs.sh

# Validate configuration
echo "Validating FreeRADIUS configuration..."
if ! radiusd -C -d /etc/raddb 2>&1; then
    echo "WARNING: FreeRADIUS configuration validation had issues, attempting to start anyway..."
fi

echo "Starting FreeRADIUS..."

# Start FreeRADIUS in foreground
exec radiusd -X -d /etc/raddb