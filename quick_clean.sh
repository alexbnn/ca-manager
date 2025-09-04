#!/bin/bash

echo "🧹 Quick cleanup of deployment files..."

# Main deployment files
rm -f .env
rm -f setup_complete.flag  
rm -f deployment_complete.flag
rm -f deploy_ready.flag

# Setup wizard output
rm -rf setup-wizard/output/

echo "✅ Quick cleanup complete!"
echo "Files removed:"
echo "  • .env"
echo "  • setup_complete.flag"
echo "  • deployment_complete.flag" 
echo "  • deploy_ready.flag"
echo "  • setup-wizard/output/ (entire directory)"