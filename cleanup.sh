#!/bin/bash

#############################################
# CA Manager Complete Cleanup Script
# Removes all Docker resources and deployment files
# Use this to completely reset the system
#############################################

# Removed set -e to prevent early exits on non-critical errors

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    echo -e "${2}${1}${NC}"
}

# Function to confirm action
confirm_action() {
    read -p "$1 [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return 1
    fi
    return 0
}

# Check for force flag
FORCE_MODE=false
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
    FORCE_MODE=true
fi

# Header
clear
print_color "================================================" "$BLUE"
print_color "     CA Manager Complete Cleanup Script" "$BLUE"
print_color "================================================" "$BLUE"
echo

if [ "$FORCE_MODE" = false ]; then
    print_color "⚠️  WARNING: This will completely remove:" "$YELLOW"
    echo "  • All Docker containers (including non-CA Manager ones)"
    echo "  • All Docker images" 
    echo "  • All Docker volumes (DATA WILL BE LOST!)"
    echo "  • All Docker networks"
    echo "  • All deployment configuration files"
    echo "  • Environment files and setup flags"
    echo
    print_color "This action is IRREVERSIBLE!" "$RED"
    echo

    # Confirmation
    if ! confirm_action "Are you ABSOLUTELY sure you want to proceed?"; then
        print_color "Cleanup cancelled." "$GREEN"
        exit 0
    fi

    # Second confirmation for safety
    if ! confirm_action "This will DELETE ALL DATA. Type 'y' to confirm one more time"; then
        print_color "Cleanup cancelled." "$GREEN"
        exit 0
    fi
else
    print_color "🚀 Running in FORCE mode - skipping confirmations" "$YELLOW"
fi

echo
print_color "Starting complete cleanup..." "$YELLOW"
echo

# Step 1: Stop docker-compose stack if it exists
print_color "Step 1: Stopping docker-compose stack..." "$BLUE"
if [ -f "docker-compose.yml" ]; then
    docker-compose down -v 2>/dev/null || true
    print_color "✓ Docker-compose stack stopped" "$GREEN"
else
    print_color "⊖ No docker-compose.yml found, skipping" "$YELLOW"
fi

# Step 2: Stop all running containers
print_color "Step 2: Stopping all Docker containers..." "$BLUE"
if [ "$(docker ps -q)" ]; then
    docker stop $(docker ps -aq) 2>/dev/null || true
    print_color "✓ All containers stopped" "$GREEN"
else
    print_color "⊖ No running containers found" "$YELLOW"
fi

# Step 3: Remove all containers
print_color "Step 3: Removing all Docker containers..." "$BLUE"
if [ "$(docker ps -aq)" ]; then
    docker rm -f $(docker ps -aq) 2>/dev/null || true
    print_color "✓ All containers removed" "$GREEN"
else
    print_color "⊖ No containers to remove" "$YELLOW"
fi

# Step 4: Remove all images
print_color "Step 4: Removing all Docker images..." "$BLUE"
if [ "$(docker images -q)" ]; then
    docker rmi -f $(docker images -aq) 2>/dev/null || true
    print_color "✓ All images removed" "$GREEN"
else
    print_color "⊖ No images to remove" "$YELLOW"
fi

# Step 5: Remove all volumes
print_color "Step 5: Removing all Docker volumes..." "$BLUE"
if [ "$(docker volume ls -q)" ]; then
    docker volume rm $(docker volume ls -q) 2>/dev/null || true
    print_color "✓ All volumes removed" "$GREEN"
else
    print_color "⊖ No volumes to remove" "$YELLOW"
fi

# Step 6: Remove custom networks
print_color "Step 6: Removing Docker networks..." "$BLUE"
# Get all networks except default ones
NETWORKS=$(docker network ls --format "{{.Name}}" 2>/dev/null | grep -v -E "^(bridge|host|none)$" || true)
if [ ! -z "$NETWORKS" ]; then
    echo "$NETWORKS" | xargs -r docker network rm 2>/dev/null || true
    print_color "✓ Custom networks removed" "$GREEN"
else
    print_color "⊖ No custom networks to remove" "$YELLOW"
fi

# Step 7: Docker system prune
print_color "Step 7: Running Docker system prune..." "$BLUE"
docker system prune -a --volumes -f 2>/dev/null || true
print_color "✓ Docker system pruned" "$GREEN"

# Step 8: Remove deployment configuration files
print_color "Step 8: Removing deployment configuration files..." "$BLUE"

# Array of files to remove
FILES_TO_REMOVE=(
    ".env"
    "setup-wizard/output/.env"
    "setup-wizard/output/setup_complete.flag"
    "setup-wizard/output/docker_labels.json"
    "setup-wizard/output/traefik.yml"
    "setup-wizard/output/traefik-dynamic.yml"
    "setup-wizard/output/deploy_ready.flag"
    "setup-wizard/output/cleanup_instructions.json"
    "setup_complete.json"
    "setup_complete.flag" 
    "deployment_complete.flag"
    "deploy_ready.flag"
    "setup-wizard/deploy_ready.flag"
    "setup-wizard/setup_complete.flag"
    "test_wizard_fixes.py"
    "test_config_generation.py"
    "test_backup_data.json"
    "test_backup_restore.py"
    "debug_backup.py"
    "debug_backup2.py"
    "debug_backup_creation.py"
)

# Remove each file if it exists
for file in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$file" ]; then
        rm -f "$file"
        echo "  ✓ Removed: $file"
    fi
done

# Remove output directory if empty
if [ -d "setup-wizard/output" ]; then
    rmdir "setup-wizard/output" 2>/dev/null || true
fi

print_color "✓ Configuration files cleaned" "$GREEN"

# Step 9: Clean Docker builder cache
print_color "Step 9: Cleaning Docker builder cache..." "$BLUE"
docker builder prune -a -f 2>/dev/null || true
print_color "✓ Builder cache cleaned" "$GREEN"

# Step 10: Verify cleanup
echo
print_color "========================================" "$BLUE"
print_color "         Cleanup Verification" "$BLUE"
print_color "========================================" "$BLUE"
echo

print_color "Docker Status:" "$YELLOW"
echo "  Containers: $(docker ps -aq | wc -l)"
echo "  Images: $(docker images -q | wc -l)"
echo "  Volumes: $(docker volume ls -q | wc -l)"
echo "  Networks: $(docker network ls --format "{{.Name}}" | grep -v -E "^(bridge|host|none)$" | wc -l)"

# Check for remaining files
REMAINING_FILES=0
for file in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$file" ]; then
        REMAINING_FILES=$((REMAINING_FILES + 1))
    fi
done
echo "  Config files remaining: $REMAINING_FILES"

echo
print_color "========================================" "$GREEN"
print_color "     🧹 Cleanup Complete!" "$GREEN"
print_color "========================================" "$GREEN"
echo
print_color "The system has been completely reset." "$GREEN"
print_color "You can now run ./deploy.sh to start fresh." "$GREEN"
echo

# Optional: Show disk space recovered
if command -v df &> /dev/null; then
    echo
    print_color "Disk space after cleanup:" "$BLUE"
    df -h . | grep -v Filesystem
fi