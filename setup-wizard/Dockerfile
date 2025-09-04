FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY setup_wizard.py .
COPY templates/ templates/
COPY static/ static/

# Create non-root user and add to docker group for socket access
RUN useradd -m -u 1000 setupuser && \
    groupadd docker && \
    usermod -aG docker setupuser && \
    chown -R setupuser:setupuser /app

USER setupuser

EXPOSE 8000

CMD ["python", "setup_wizard.py"]