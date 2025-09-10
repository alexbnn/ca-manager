#!/bin/bash

# Authentication logging script for RADIUS

USERNAME="$1"
NAS_IP="$2"
CERT_CN="$3"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
LOG_FILE="/var/log/radius/auth.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Log authentication attempt
echo "[$TIMESTAMP] EAP-TLS AUTH: User=$USERNAME, NAS=$NAS_IP, CertCN=$CERT_CN" >> "$LOG_FILE"

exit 0