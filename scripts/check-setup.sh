#!/bin/bash
# CA Manager Setup Checker
# This script checks for common setup issues

echo "==================================="
echo "CA Manager Setup Checker"
echo "==================================="
echo ""

# Function to check if docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo "❌ Docker is not running or not installed"
        echo "   Please start Docker Desktop or install Docker"
        exit 1
    fi
    echo "✅ Docker is running"
}

# Function to check if containers are running
check_containers() {
    local running=$(docker-compose ps --services --filter "status=running" 2>/dev/null | wc -l)
    local expected=9  # Adjust based on your services
    
    if [ "$running" -lt 2 ]; then
        echo "⚠️  No containers are running"
        echo "   Run: docker-compose up -d"
        return 1
    fi
    echo "✅ Containers are running ($running services)"
}

# Function to check database connectivity
check_database() {
    echo -n "Checking database connectivity... "
    
    # Try to connect to PostgreSQL
    if docker-compose exec -T postgres pg_isready -U pkiuser -d pkiauth > /dev/null 2>&1; then
        echo "✅"
    else
        echo "❌"
        echo ""
        echo "   Database connection failed. This usually means:"
        echo "   1. The database password in .env doesn't match the PostgreSQL volume"
        echo "   2. The database container is not ready yet"
        echo ""
        echo "   To fix password mismatch:"
        echo "   docker-compose down"
        echo "   docker volume rm ca-manager-f_postgres-data"
        echo "   docker-compose up -d"
        return 1
    fi
}

# Function to check if .env file exists
check_env_file() {
    if [ ! -f ".env" ]; then
        echo "⚠️  No .env file found"
        echo "   Run the setup wizard first or create .env manually"
        return 1
    fi
    echo "✅ .env file exists"
}

# Function to test admin login
test_admin_login() {
    echo -n "Testing admin login... "
    
    # Get the domain from .env
    DOMAIN=$(grep "^DOMAIN=" .env | cut -d'=' -f2 || echo "localhost")
    
    # Try to login (this will fail with self-signed cert, but we can check the response)
    response=$(curl -s -k -X POST "https://${DOMAIN}/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"admin"}' 2>/dev/null || echo "")
    
    if echo "$response" | grep -q "success"; then
        echo "✅"
    elif echo "$response" | grep -q "Database connection failed"; then
        echo "❌"
        echo "   Database connection issue detected"
        echo "   See database check above for resolution"
    elif [ -z "$response" ]; then
        echo "⚠️"
        echo "   Could not reach the application at https://${DOMAIN}"
        echo "   Services may still be starting up"
    else
        echo "⚠️"
        echo "   Login test returned: ${response:0:100}..."
    fi
}

# Main execution
main() {
    check_docker
    check_env_file
    check_containers
    
    if check_containers > /dev/null 2>&1; then
        sleep 2  # Give services a moment to be ready
        check_database
        test_admin_login
    fi
    
    echo ""
    echo "==================================="
    echo "Check complete!"
    echo ""
    echo "Default credentials: admin / admin"
    echo "Access the application at: https://localhost (or your configured domain)"
    echo "==================================="
}

# Run the checks
main