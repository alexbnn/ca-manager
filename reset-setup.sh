#!/bin/bash
# CA Manager Reset Script - Prepare for first-time setup
# This script removes all configuration and data to enable a fresh setup

set -e

echo "🔄 CA Manager Reset Script"
echo "=========================="
echo ""
echo "⚠️  WARNING: This will delete ALL CA Manager data and configuration!"
echo "⚠️  This includes:"
echo "   • All certificates and PKI data"
echo "   • User accounts and authentication data"
echo "   • SSL certificates"
echo "   • Audit logs and session data"
echo "   • Configuration files"
echo ""

# Confirmation prompt
read -p "Are you sure you want to reset CA Manager? (type 'yes' to confirm): " confirm
if [ "$confirm" != "yes" ]; then
    echo "❌ Reset cancelled."
    exit 0
fi

echo ""
echo "🛑 Stopping all containers..."
docker-compose down 2>/dev/null || echo "ℹ️  No running containers found"

echo ""
echo "🗑️  Removing configuration files..."

# Remove setup flag files
if [ -f ".env" ]; then
    rm -f .env
    echo "✅ Removed .env"
else
    echo "ℹ️  .env not found"
fi

if [ -f "setup_complete.flag" ]; then
    rm -f setup_complete.flag
    echo "✅ Removed setup_complete.flag"
else
    echo "ℹ️  setup_complete.flag not found"
fi

if [ -f "deploy_ready.flag" ]; then
    rm -f deploy_ready.flag
    echo "✅ Removed deploy_ready.flag"
else
    echo "ℹ️  deploy_ready.flag not found"
fi

if [ -f "cleanup_instructions.json" ]; then
    rm -f cleanup_instructions.json
    echo "✅ Removed cleanup_instructions.json"
else
    echo "ℹ️  cleanup_instructions.json not found"
fi

echo ""
echo "🐳 Removing Docker volumes..."

# Use the actual project name pattern from Docker Compose
PROJECT_NAME="camanager-v312"

# List of volumes to remove
VOLUMES=(
    "${PROJECT_NAME}_postgres-data"
    "${PROJECT_NAME}_easyrsa-pki"
    "${PROJECT_NAME}_redis-data"
    "${PROJECT_NAME}_letsencrypt-data"
    "${PROJECT_NAME}_pki-logs"
    "${PROJECT_NAME}_easyrsa-logs"
    "${PROJECT_NAME}_scep-logs"
    "${PROJECT_NAME}_traefik-logs"
)

for volume in "${VOLUMES[@]}"; do
    if docker volume inspect "$volume" >/dev/null 2>&1; then
        docker volume rm "$volume" 2>/dev/null && echo "✅ Removed volume: $volume" || echo "⚠️  Could not remove volume: $volume"
    else
        echo "ℹ️  Volume not found: $volume"
    fi
done

echo ""
echo "🧹 Cleaning up unused Docker resources..."
docker system prune -f >/dev/null 2>&1 || true

echo ""
echo "✅ Reset complete!"
echo ""
echo "🚀 You can now run the first-time setup:"
echo "   ./deploy.sh"
echo ""
echo "📝 The setup wizard will be available at: http://localhost:8000"
echo ""