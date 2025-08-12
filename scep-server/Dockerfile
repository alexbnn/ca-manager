# Multi-stage build for optimized SCEP server image
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies in user directory
RUN pip install --user --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 scepuser

# Copy Python packages from builder stage to scepuser's directory
COPY --from=builder /root/.local /home/scepuser/.local

# Copy application files
COPY scep_server.py .

# Create logs directory and set ownership
RUN mkdir -p /app/logs && \
    chown -R scepuser:scepuser /app && \
    chown -R scepuser:scepuser /home/scepuser/.local

# Switch to non-root user
USER scepuser

# Add local bin to PATH
ENV PATH=/home/scepuser/.local/bin:$PATH

# Expose port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8090/health || exit 1

# Environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=scep_server.py
ENV FLASK_ENV=production

# Use gunicorn for production with increased timeout and workers
CMD ["gunicorn", "--bind", "0.0.0.0:8090", "--workers", "3", "--worker-class", "sync", "--timeout", "300", "--keep-alive", "5", "--max-requests", "1000", "--max-requests-jitter", "100", "scep_server:app"]