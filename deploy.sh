#!/bin/bash
# CA Manager Deployment Script with Setup Wizard

set -e

echo "🚀 CA Manager Deployment Script"
echo "================================="

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if setup has been completed
if [ -f ".env" ] && [ -f "setup_complete.flag" ]; then
    echo "✅ Setup already completed. Starting CA Manager..."
    
    # Check for existing postgres volume that might have old password
    if docker volume ls | grep -q "postgres-data"; then
        echo ""
        echo "⚠️  Warning: Existing PostgreSQL data volume detected."
        echo "   If you have database connection issues, you may need to reset it:"
        echo "   docker-compose down"
        echo "   docker volume rm ca-manager-f_postgres-data"
        echo "   ./deploy.sh"
        echo ""
    fi
    
    docker-compose up -d
    echo ""
    echo "🌐 CA Manager is running!"
    echo "📊 Main Application: https://localhost/"
    echo "📈 Traefik Dashboard: http://localhost:8081/"
    echo "🔑 Default login: admin / admin"
    exit 0
fi

echo ""
echo "🎯 First-time setup detected. Starting Setup Wizard..."
echo ""

# Check if port 8000 is available
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null ; then
    echo "❌ Port 8000 is already in use. Please free up the port and try again."
    exit 1
fi

# Start the setup wizard
echo "🧙 Starting Setup Wizard on http://localhost:8000"
echo ""
docker-compose -f docker-compose.setup.yml up --build -d

# Wait for the setup wizard to be ready
echo "⏳ Waiting for Setup Wizard to start..."
for i in {1..30}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Check if setup wizard is running
if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "❌ Setup Wizard failed to start. Please check the logs:"
    docker-compose -f docker-compose.setup.yml logs
    exit 1
fi

echo ""
echo "✨ Setup Wizard is ready!"
echo ""
echo "🌐 Open your browser and go to: http://localhost:8000"
echo ""
echo "📋 Complete the setup wizard to configure:"
echo "   • Domain name and SSL certificates"
echo "   • Organization details for PKI"
echo "   • Administrator credentials"
echo "   • OCSP responder settings"
echo "   • Security settings"
echo ""
echo "💡 After completing the wizard:"
echo "   1. Download the generated configuration"
echo "   2. Run 'docker-compose down -f docker-compose.setup.yml'"
echo "   3. Run './deploy.sh' again to start the main application"
echo ""

# Monitor for deployment signal in background
echo "🔍 Monitoring for deployment signal..."
(
    while true; do
        # Check if deployment signal exists (files should be in main directory due to volume mount)
        if [ -f "setup_complete.flag" ] && [ -f "deploy_ready.flag" ]; then
            echo ""
            echo "🚀 Deployment signal received! Starting CA Manager..."
            
            # Handle cleanup instructions from setup wizard
            echo "🧹 Processing cleanup instructions..."
            
            if [ -f "cleanup_instructions.json" ]; then
                echo "📋 Found cleanup instructions, processing..."
                
                # Check if database reset is needed
                if grep -q '"reset_database": true' cleanup_instructions.json; then
                    echo "🗄️ Resetting database to avoid password conflicts..."
                    
                    # Get project name for volume names
                    PROJECT_NAME=$(basename "$(pwd)" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
                    
                    # Stop any running containers first
                    docker-compose down 2>/dev/null || true
                    
                    # Remove postgres data volume
                    docker volume rm "${PROJECT_NAME}_postgres-data" 2>/dev/null && echo "✅ Removed old database volume" || echo "ℹ️ No existing database volume found"
                    
                    # Clean up other volumes if specified
                    if grep -q "easyrsa-pki" cleanup_instructions.json; then
                        docker volume rm "${PROJECT_NAME}_easyrsa-pki" 2>/dev/null && echo "✅ Removed PKI volume" || true
                    fi
                fi
                
                # Clean up the instructions file
                rm -f cleanup_instructions.json
            fi
            
            # Verify configuration files exist (should be created by setup wizard via volume mount)
            echo "📄 Verifying configuration files..."
            
            if [ -f ".env" ]; then
                echo "✅ .env file found"
            else
                echo "❌ .env file missing"
            fi
            
            if [ -f "traefik.yml" ]; then
                echo "✅ traefik.yml found"
            else
                echo "❌ traefik.yml missing"
            fi
            
            # Give the deployment API response time to return before stopping wizard
            echo "⏳ Waiting for deployment response to complete..."
            sleep 3
            
            # Stop setup wizard
            docker-compose -f docker-compose.setup.yml down
            
            # Start main application
            docker-compose up -d
            
            echo ""
            echo "✅ CA Manager deployment complete!"
            echo ""
            echo "🌐 Your CA Manager is now running:"
            if [ -f ".env" ]; then
                DOMAIN=$(grep "DOMAIN=" .env | cut -d'=' -f2 | tr -d '"' || echo "localhost")
                echo "📊 Main Application: https://$DOMAIN/"
                echo "🍎 SCEP Simulator: https://$DOMAIN/simulator/"
                echo "🔍 OCSP Simulator: https://$DOMAIN/ocsp-simulator/"
            else
                echo "📊 Main Application: https://localhost/"
                echo "🍎 SCEP Simulator: https://localhost/simulator/"
                echo "🔍 OCSP Simulator: https://localhost/ocsp-simulator/"
            fi
            echo "📈 Traefik Dashboard: http://localhost:8081/"
            echo ""
            
            exit 0
        fi
        sleep 2
    done
) &

# Keep the script running to show logs
echo "📜 Setup Wizard logs (Ctrl+C to exit, or complete setup in browser for auto-deployment):"
docker-compose -f docker-compose.setup.yml logs -f