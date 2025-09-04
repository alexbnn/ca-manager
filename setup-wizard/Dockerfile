FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY setup_wizard.py .
COPY templates/ templates/
COPY static/ static/

# Install required system packages
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create user and set permissions - we'll run as root to access docker socket
# This is safe since the container is isolated and only used for deployment
RUN useradd -m -u 1000 setupuser && \
    chown -R setupuser:setupuser /app

# Note: Running as root to access Docker socket - container is ephemeral and deployment-only

EXPOSE 8000

CMD ["python", "setup_wizard.py"]