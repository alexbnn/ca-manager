#!/bin/bash

# CA Manager Deployment Script with Git Support
# This script rebuilds the CA Manager with version management capabilities

set -e  # Exit on any error

echo "🚀 CA Manager Deployment with Git Support"
echo "=========================================="

# Check if running as root or with docker permissions
if ! docker ps >/dev/null 2>&1; then
    echo "❌ ERROR: Cannot access Docker. Please run with appropriate permissions."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose >/dev/null 2>&1; then
    echo "❌ ERROR: docker-compose is not installed or not in PATH"
    exit 1
fi

echo "📋 Pre-deployment checks passed"

# Stop existing containers
echo "🛑 Stopping existing containers..."
docker-compose down

# Build new containers with Git support
echo "🔨 Building containers with Git and Docker CLI support..."
echo "   This may take a few minutes as it installs additional dependencies..."

# Build only the web-interface container with no cache to ensure latest changes
docker-compose build --no-cache web-interface

if [ $? -eq 0 ]; then
    echo "✅ Container build completed successfully"
else
    echo "❌ Container build failed"
    exit 1
fi

# Start containers
echo "🚀 Starting updated containers..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to initialize..."
sleep 10

# Check container status
echo "🔍 Checking container status..."
docker-compose ps

# Verify web interface is responding
echo "🌐 Verifying web interface..."
sleep 5
if curl -k -s https://ca.bonnerseptien.com/health > /dev/null; then
    echo "✅ Web interface is responding"
else
    echo "⚠️  Web interface may still be starting up"
fi

echo ""
echo "🎉 Deployment completed!"
echo "📋 What's new:"
echo "   • Git version control support enabled"
echo "   • Docker CLI access for container management"
echo "   • Version Management section in General Settings"
echo "   • Branch switching and update capabilities"
echo "   • GitHub integration for latest version checking"
echo ""
echo "🔗 Access your CA Manager at: https://ca.bonnerseptien.com"
echo "⚙️  Version management is available in General Settings tab"