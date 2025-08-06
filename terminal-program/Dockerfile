# Enhanced Dockerfile for EasyRSA container with cryptography support
FROM alpine:3.18

# Install EasyRSA and dependencies including build tools for cryptography
RUN apk add --no-cache \
    easy-rsa \
    python3 \
    py3-pip \
    python3-dev \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    curl \
    openssl \
    bash \
    && pip3 install --no-cache-dir Flask==3.0.0 cryptography==41.0.7 \
    && apk del gcc musl-dev python3-dev libffi-dev openssl-dev

# Set working directory
WORKDIR /app

# Copy the EasyRSA API wrapper
COPY easyrsa_api.py /app/easyrsa_api.py

# Create PKI directory with proper permissions
RUN mkdir -p /app/pki && chmod 755 /app/pki

# Create logs directory
RUN mkdir -p /app/logs && chmod 755 /app/logs

# Create non-root user and set permissions
RUN adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app && \
    chown -R appuser:appuser /app/pki && \
    chown -R appuser:appuser /app/logs

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=easyrsa_api.py
ENV FLASK_ENV=production

# Run the EasyRSA API wrapper
CMD ["python3", "/app/easyrsa_api.py"]