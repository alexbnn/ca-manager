#!/bin/bash
# RadSec Proxy deployment script
set -e

echo "Deploying RadSec proxy..."

# Download and run Extreme Networks installer
curl -L https://oh-uz.extremecloudiq.com/proxy-installer/master-installer.sh | bash -s -- -o deploy -t eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJSYWFTIiwiaWF0IjoxNzU4NzQwNjYyLCJleHAiOjE3NTg3NDI0NjIsInBheWxvYWQiOnsic2l0ZV9pZCI6MTU2OTk0MzY5MDc3NTQ2NCwicHJveHlfaWQiOjE1Njk5NDM2OTA3NzQyODMsIndvcmtzcGFjZV9pZCI6ODMsImNlcnRpZmljYXRlc19yb3RhdGlvbl90aW1lX2luX2RheXMiOjMwLCJldmVudF90eXBlIjpudWxsLCJmcmVlcmFkaXVzX2lwX2FkZHJlc3MiOiIzLjE1LjkwLjExIiwic2VydmVyX2Jhc2VfdXJsIjoib2gtdXouZXh0cmVtZWNsb3VkaXEuY29tIn19.ompFqbLtn4wTokw04KOqPR1XdNr5tQyFBNbeRp9luqE

echo "RadSec proxy deployment completed"
