#!/usr/bin/env python3
"""
Deployment Monitor - Provides real-time feedback during CA Manager deployment
"""

import subprocess
import threading
import queue
import json
import time
from flask import Flask, Response, jsonify
import docker
from pathlib import Path

app = Flask(__name__)
deployment_status = {
    'phase': 'initializing',
    'progress': 0,
    'current_task': '',
    'logs': [],
    'services': {},
    'errors': []
}

class DeploymentMonitor:
    def __init__(self):
        self.client = docker.from_env()
        self.log_queue = queue.Queue()
        self.is_running = False
        
    def monitor_deployment(self):
        """Monitor Docker Compose deployment progress"""
        global deployment_status
        
        services = [
            'traefik',
            'postgres', 
            'redis',
            'web-interface',
            'easyrsa-container',
            'scep-server',
            'ios-scep-simulator',
            'ocsp-simulator',
            'ocsp-responder'
        ]
        
        # Initialize service status
        for service in services:
            deployment_status['services'][service] = {
                'status': 'pending',
                'health': 'unknown',
                'logs': []
            }
        
        deployment_status['phase'] = 'building'
        deployment_status['progress'] = 10
        
        try:
            # Monitor container status
            while self.is_running:
                containers = self.client.containers.list(all=True)
                
                completed_services = 0
                for container in containers:
                    # Extract service name from container name (format: ca-manager-f-SERVICE-1)
                    name_parts = container.name.split('-')
                    if len(name_parts) >= 3 and 'ca-manager' in container.name:
                        service_name = name_parts[3] if len(name_parts) > 3 else name_parts[2]
                        
                        if service_name in deployment_status['services']:
                            status = container.status
                            deployment_status['services'][service_name]['status'] = status
                            
                            if status == 'running':
                                completed_services += 1
                                # Check health if available
                                try:
                                    health = container.attrs.get('State', {}).get('Health', {})
                                    if health:
                                        deployment_status['services'][service_name]['health'] = health.get('Status', 'unknown')
                                except:
                                    pass
                
                # Calculate progress
                if len(services) > 0:
                    progress = 10 + (completed_services / len(services)) * 80
                    deployment_status['progress'] = int(progress)
                    
                    if completed_services == len(services):
                        deployment_status['phase'] = 'configuring_ssl'
                        deployment_status['current_task'] = 'Requesting Let\'s Encrypt certificates...'
                        
                        # Check for certificate acquisition
                        if self.check_certificates():
                            deployment_status['phase'] = 'completed'
                            deployment_status['progress'] = 100
                            deployment_status['current_task'] = 'Deployment successful!'
                            break
                
                time.sleep(2)
                
        except Exception as e:
            deployment_status['errors'].append(str(e))
            deployment_status['phase'] = 'error'
    
    def check_certificates(self):
        """Check if Let's Encrypt certificates have been acquired"""
        try:
            traefik = self.client.containers.get('ca-manager-f-traefik-1')
            logs = traefik.logs(tail=100).decode('utf-8')
            return 'certificate obtained successfully' in logs.lower() or 'server responded with a certificate' in logs.lower()
        except:
            return False
    
    def stream_logs(self, service_name):
        """Stream logs from a specific service"""
        try:
            container = self.client.containers.get(f'ca-manager-f-{service_name}-1')
            for line in container.logs(stream=True, follow=True):
                yield f"data: {json.dumps({'service': service_name, 'log': line.decode('utf-8').strip()})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

monitor = DeploymentMonitor()

@app.route('/api/deployment/status')
def get_deployment_status():
    """Get current deployment status"""
    return jsonify(deployment_status)

@app.route('/api/deployment/logs/<service>')
def stream_service_logs(service):
    """Stream logs for a specific service"""
    return Response(monitor.stream_logs(service), mimetype='text/event-stream')

@app.route('/api/deployment/start', methods=['POST'])
def start_deployment_monitoring():
    """Start monitoring the deployment"""
    if not monitor.is_running:
        monitor.is_running = True
        thread = threading.Thread(target=monitor.monitor_deployment)
        thread.daemon = True
        thread.start()
        return jsonify({'status': 'monitoring started'})
    return jsonify({'status': 'already monitoring'})

@app.route('/api/deployment/progress')
def deployment_progress_stream():
    """Server-Sent Events stream for real-time progress"""
    def generate():
        last_status = None
        while True:
            current_status = json.dumps(deployment_status)
            if current_status != last_status:
                yield f"data: {current_status}\n\n"
                last_status = current_status
                
                if deployment_status['phase'] in ['completed', 'error']:
                    break
            time.sleep(1)
    
    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001, debug=True)