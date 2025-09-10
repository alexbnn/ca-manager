FROM alpine:3.18

# Install FreeRADIUS and additional packages
RUN apk add --no-cache \
    freeradius \
    freeradius-eap \
    freeradius-utils \
    openssl \
    curl \
    jq \
    bash

# Create directories for certificates and configuration
RUN mkdir -p /etc/raddb/certs/ca \
             /etc/raddb/certs/server \
             /var/log/radius \
             /var/run/radiusd

# Copy scripts
COPY scripts/ /opt/radius-scripts/

# Save default FreeRADIUS config as base
RUN cp -r /etc/raddb /etc/raddb-default

# Copy our customizations
COPY raddb/ /etc/raddb-custom/

# Set permissions and ensure directories are writable
RUN chown -R radius:radius /etc/raddb /var/log/radius /var/run/radiusd /opt/radius-scripts && \
    chmod -R 755 /etc/raddb && \
    chmod +x /opt/radius-scripts/*.sh && \
    chmod 755 /etc/raddb/certs /etc/raddb/certs/ca /etc/raddb/certs/server

# Expose RADIUS ports
EXPOSE 1812/udp 1813/udp 18120/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /opt/radius-scripts/health-check.sh

# Run as root (needed for certificate operations and binding to privileged ports)
USER root

# Start FreeRADIUS
CMD ["/opt/radius-scripts/start.sh"]