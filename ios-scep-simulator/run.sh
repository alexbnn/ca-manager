#!/bin/bash

# iOS SCEP Client Simulator Startup Script

echo "iOS SCEP Client Simulator"
echo "============================="
echo ""

# Sync domain from parent CA Manager .env file
if [ -f "../.env" ]; then
    PARENT_DOMAIN=$(grep "^DOMAIN=" ../.env 2>/dev/null | cut -d'=' -f2)
    if [ -n "$PARENT_DOMAIN" ]; then
        echo "📡 Syncing domain from CA Manager: $PARENT_DOMAIN"
        echo "DOMAIN=$PARENT_DOMAIN" > .env
    fi
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.11 or later."
    exit 1
fi

# Check if Docker is available
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo "🐳 Docker detected. Choose your preferred method:"
    echo "1) Run with Docker Compose (recommended)"
    echo "2) Run with Python directly"
    echo ""
    read -p "Enter your choice (1 or 2): " choice
    
    case $choice in
        1)
            echo "🚀 Starting with Docker Compose..."
            docker-compose up -d
            
            if [ $? -eq 0 ]; then
                echo ""
                echo "✅ iOS SCEP Simulator is now running!"
                echo "🌐 Web Interface: http://localhost:3000"
                echo ""
                echo "To stop the simulator, run: docker-compose down"
                echo "To view logs, run: docker-compose logs -f ios-scep-simulator"
            else
                echo "❌ Failed to start with Docker Compose"
                exit 1
            fi
            ;;
        2)
            echo "🐍 Starting with Python..."
            ;;
        *)
            echo "❌ Invalid choice. Exiting."
            exit 1
            ;;
    esac
else
    echo "🐍 Starting with Python..."
fi

# If we reach here, we're running with Python
if [ "$choice" != "1" ]; then
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        echo "📦 Creating virtual environment..."
        python3 -m venv venv
    fi

    # Activate virtual environment
    echo "⚡ Activating virtual environment..."
    source venv/bin/activate

    # Install dependencies
    echo "📚 Installing dependencies..."
    pip install -r requirements.txt

    # Create directories
    mkdir -p templates static logs

    # Start the application
    echo ""
    echo "🚀 Starting iOS SCEP Client Simulator..."
    echo "🌐 Web Interface will be available at: http://localhost:3000"
    echo ""
    echo "Press Ctrl+C to stop the simulator"
    echo ""
    
    python app.py
fi