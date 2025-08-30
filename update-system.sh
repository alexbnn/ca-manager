#!/bin/bash

# CA Manager System Update Script
# This script handles updating the CA Manager system to different branches or latest version

set -e  # Exit on any error

REPO_URL="https://github.com/alexbnn/ca-manager.git"
WORK_DIR="/app/source"
COMPOSE_FILE="/app/source/docker-compose.yml"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

update_to_branch() {
    local target_branch=${1:-"main"}
    
    log "Starting update to branch: $target_branch"
    
    cd "$WORK_DIR"
    
    # Ensure we have the latest remote information
    log "Fetching latest changes from remote..."
    git fetch origin
    
    # Get current branch for comparison
    current_branch=$(git branch --show-current)
    log "Current branch: $current_branch"
    
    # Switch to target branch if different
    if [ "$current_branch" != "$target_branch" ]; then
        log "Switching from $current_branch to $target_branch"
        git checkout "origin/$target_branch" -b "$target_branch" 2>/dev/null || git checkout "$target_branch"
        git pull origin "$target_branch"
    else
        log "Already on $target_branch, pulling latest changes"
        git pull origin "$target_branch"
    fi
    
    # Check if docker-compose.yml exists
    if [ ! -f "$COMPOSE_FILE" ]; then
        log "ERROR: $COMPOSE_FILE not found in $WORK_DIR"
        exit 1
    fi
    
    # Get the current container ID
    CONTAINER_ID=$(hostname)
    log "Current container ID: $CONTAINER_ID"
    
    # Use Docker API to restart the container
    log "Requesting container restart via Docker socket..."
    
    # Find the web-interface container by name pattern
    WEB_CONTAINER=$(docker ps --filter "ancestor=ca-manager-f-web-interface" --format "{{.ID}}" | head -1)
    if [ -n "$WEB_CONTAINER" ]; then
        log "Found web interface container: $WEB_CONTAINER"
        log "Restarting container to apply branch changes..."
        
        # Restart the container (this will exit our current process)
        docker restart "$WEB_CONTAINER" &
        
        log "Restart command sent. Container will be available shortly."
        exit 0
    else
        log "Warning: Could not find web interface container for restart"
        log "Branch switch completed, but manual restart may be required"
    fi
    
    # Wait a moment for services to start
    sleep 5
    
    # Check if containers are running
    log "Checking container status..."
    docker-compose ps
    
    log "Update completed successfully!"
    log "CA Manager is now running version: $target_branch"
}

update_current_branch() {
    local current_branch=$(git branch --show-current)
    log "Updating current branch: $current_branch"
    update_to_branch "$current_branch"
}

# Check if running as root or with docker permissions
if ! docker ps >/dev/null 2>&1; then
    log "ERROR: Cannot access Docker. Please run with appropriate permissions."
    exit 1
fi

# Check if git is available
if ! command -v git >/dev/null 2>&1; then
    log "ERROR: Git is not installed or not in PATH"
    exit 1
fi

# Main execution
case "${1:-update}" in
    "switch")
        if [ -z "$2" ]; then
            log "ERROR: Branch name required for switch command"
            log "Usage: $0 switch <branch-name>"
            exit 1
        fi
        update_to_branch "$2"
        ;;
    "update"|"")
        update_current_branch
        ;;
    "help"|"-h"|"--help")
        echo "CA Manager System Update Script"
        echo ""
        echo "Usage:"
        echo "  $0 update              - Update current branch to latest version"
        echo "  $0 switch <branch>     - Switch to a different branch"
        echo "  $0 help                - Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 update              # Update current branch"
        echo "  $0 switch main         # Switch to main branch"
        echo "  $0 switch development  # Switch to development branch"
        ;;
    *)
        log "ERROR: Unknown command: $1"
        log "Use '$0 help' for usage information"
        exit 1
        ;;
esac