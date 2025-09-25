#!/bin/bash

# CA Manager Deployment Debug Script
# Run this when deployment fails to collect comprehensive logs

echo "=== CA Manager Deployment Debug Report ==="
echo "Generated on: $(date)"
echo "System: $(uname -a)"
echo

# System Information
echo "=== SYSTEM INFORMATION ==="
echo "Docker Version:"
docker --version 2>&1 || echo "Docker not available"
echo
echo "Docker Compose Version:"
docker-compose --version 2>&1 || echo "Docker Compose not available"
echo
echo "Available Memory:"
free -h 2>/dev/null || echo "Memory info not available"
echo
echo "Available Disk Space:"
df -h . 2>/dev/null || echo "Disk info not available"
echo

# Container Status
echo "=== CONTAINER STATUS ==="
echo "All Containers:"
docker ps -a 2>&1
echo
echo "Docker Compose Services:"
docker-compose ps 2>&1
echo

# Health Checks
echo "=== HEALTH CHECKS ==="
echo "PostgreSQL Health:"
docker-compose exec -T postgres pg_isready -U pkiuser -d pkiauth 2>&1 || echo "PostgreSQL check failed"
echo
echo "Redis Health:"
docker-compose exec -T redis redis-cli ping 2>&1 || echo "Redis check failed"
echo

# Network Information
echo "=== NETWORK STATUS ==="
echo "Docker Networks:"
docker network ls 2>&1
echo
echo "CA Manager Network:"
docker network inspect ca-manager-f_easyrsa-network 2>&1 || echo "Network not found"
echo

# Service Logs (Last 50 lines each)
echo "=== SERVICE LOGS ==="
services=("postgres" "web-interface" "easyrsa-container" "redis" "traefik")

for service in "${services[@]}"; do
    echo "--- $service logs (last 50 lines) ---"
    docker-compose logs --tail=50 "$service" 2>&1 || echo "$service logs not available"
    echo
done

# Database Connection Test
echo "=== DATABASE CONNECTION TEST ==="
echo "Testing PostgreSQL connection from web-interface container:"
docker-compose exec -T web-interface python3 -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(os.getenv('DATABASE_URL', 'postgresql://pkiuser:pkipass@postgres:5432/pkiauth'))
    print('✓ Database connection successful')
    cursor = conn.cursor()
    cursor.execute('SELECT version();')
    version = cursor.fetchone()
    print(f'PostgreSQL Version: {version[0]}')
    cursor.close()
    conn.close()
except Exception as e:
    print(f'✗ Database connection failed: {e}')
" 2>&1 || echo "Database connection test failed"
echo

# Environment Variables
echo "=== ENVIRONMENT VARIABLES ==="
echo "Docker Compose Environment:"
docker-compose config 2>&1 | head -20
echo

# Port Conflicts
echo "=== PORT USAGE ==="
echo "Checking for port conflicts:"
for port in 80 443 5432 6379 8080 8081; do
    if command -v lsof &> /dev/null; then
        lsof -i :$port 2>/dev/null || echo "Port $port: Available"
    elif command -v netstat &> /dev/null; then
        netstat -tulpn 2>/dev/null | grep :$port || echo "Port $port: Available"
    else
        echo "Port checking tools not available"
        break
    fi
done
echo

# Resource Usage
echo "=== RESOURCE USAGE ==="
echo "Container Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" 2>&1 || echo "Resource stats not available"
echo

echo "=== END DEBUG REPORT ==="
echo "Please copy this entire output and share it for debugging assistance."