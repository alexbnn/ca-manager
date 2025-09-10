#!/bin/bash

# Health check for FreeRADIUS server

set -e

# Check if FreeRADIUS process is running
if ! pgrep -f radiusd > /dev/null; then
    echo "ERROR: FreeRADIUS process not running"
    exit 1
fi

# Check if RADIUS is listening on authentication port
if ! netstat -ln | grep -q ":1812 "; then
    echo "ERROR: FreeRADIUS not listening on port 1812"
    exit 1
fi

# Test RADIUS server with a simple status request
if ! echo "Message-Authenticator = 0x00" | radclient -x localhost:1812 status testing123 2>/dev/null | grep -q "Received Access-Accept"; then
    # If status check fails, try a basic connectivity test
    if ! timeout 5 bash -c '</dev/tcp/localhost/1812'; then
        echo "ERROR: Cannot connect to RADIUS server"
        exit 1
    fi
fi

# Check certificate files exist
if [ ! -f "/etc/raddb/certs/ca/ca.crt" ]; then
    echo "WARNING: CA certificate not found"
fi

if [ ! -f "/etc/raddb/certs/server/server.crt" ]; then
    echo "WARNING: Server certificate not found"
fi

echo "FreeRADIUS health check passed"
exit 0