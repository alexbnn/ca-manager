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
    'errors': [],
    'recovery_attempts': {},
    'start_time': None,
    'timeout_minutes': 5
}

class DeploymentMonitor:
    def __init__(self):
        self.client = docker.from_env()
        self.log_queue = queue.Queue()
        self.is_running = False
        self.max_recovery_attempts = 3

    def attempt_service_recovery(self, service_name, container_name):
        """Attempt to recover a failed service"""
        global deployment_status

        if service_name not in deployment_status['recovery_attempts']:
            deployment_status['recovery_attempts'][service_name] = 0

        attempts = deployment_status['recovery_attempts'][service_name]

        if attempts >= self.max_recovery_attempts:
            deployment_status['errors'].append(f"Service {service_name} failed after {self.max_recovery_attempts} recovery attempts")
            return False

        deployment_status['recovery_attempts'][service_name] += 1
        deployment_status['current_task'] = f"Attempting recovery for {service_name} (attempt {attempts + 1}/{self.max_recovery_attempts})"
        deployment_status['logs'].append(f"RECOVERY: Attempting to restart {service_name}")

        try:
            # Try to restart the container
            subprocess.run(['docker-compose', 'restart', service_name],
                          cwd='/app', check=True, capture_output=True, text=True)
            deployment_status['logs'].append(f"RECOVERY: Successfully restarted {service_name}")
            return True
        except subprocess.CalledProcessError as e:
            deployment_status['logs'].append(f"RECOVERY: Failed to restart {service_name}: {e}")
            # Try to rebuild and restart
            try:
                subprocess.run(['docker-compose', 'up', '-d', '--build', service_name],
                              cwd='/app', check=True, capture_output=True, text=True)
                deployment_status['logs'].append(f"RECOVERY: Successfully rebuilt and restarted {service_name}")
                return True
            except subprocess.CalledProcessError as e2:
                deployment_status['logs'].append(f"RECOVERY: Failed to rebuild {service_name}: {e2}")
                return False
        except Exception as e:
            deployment_status['logs'].append(f"RECOVERY: Unexpected error recovering {service_name}: {e}")
            return False

    def check_timeout(self):
        """Check if deployment has exceeded timeout"""
        global deployment_status

        if deployment_status['start_time'] is None:
            deployment_status['start_time'] = time.time()
            return False

        elapsed_minutes = (time.time() - deployment_status['start_time']) / 60

        if elapsed_minutes > deployment_status['timeout_minutes']:
            deployment_status['phase'] = 'timeout'
            deployment_status['current_task'] = f'Deployment timed out after {deployment_status["timeout_minutes"]} minutes'
            deployment_status['errors'].append(f'Deployment exceeded {deployment_status["timeout_minutes"]} minute timeout')
            return True

        return False
        
    def monitor_deployment(self):
        """Monitor Docker Compose deployment progress using the working logic from deployment-status.py"""
        global deployment_status

        deployment_status['phase'] = 'building'
        deployment_status['progress'] = 10
        deployment_status['logs'].append("Starting deployment monitoring...")

        try:
            # Monitor container status
            while self.is_running:
                # Check for timeout first
                if self.check_timeout():
                    break

                # Use the same logic as deployment-status.py
                containers = self.client.containers.list(all=True)

                # Filter CA Manager containers - same logic as working standalone script
                ca_manager_containers = []
                for container in containers:
                    if 'ca-manager-f-' in container.name and container.name.endswith('-1'):
                        service_name = container.name.replace('ca-manager-f-', '').replace('-1', '')
                        ca_manager_containers.append((service_name, container))

                if not ca_manager_containers:
                    deployment_status['current_task'] = 'Waiting for containers to start...'
                    deployment_status['logs'].append("No CA Manager containers found, waiting...")
                    time.sleep(2)
                    continue

                # Update services dictionary with discovered containers
                running_services = 0
                total_services = len(ca_manager_containers)

                # Clear and rebuild services status
                deployment_status['services'] = {}

                for service_name, container in ca_manager_containers:
                    status = container.status

                    # Get health status - same logic as working script
                    health_status = "N/A"
                    try:
                        container_info = container.attrs
                        health = container_info.get('State', {}).get('Health', {})
                        if health:
                            health_status = health.get('Status', 'unknown')
                        elif status == 'running':
                            health_status = "healthy"
                    except:
                        health_status = "unknown"

                    # Update service in status
                    deployment_status['services'][service_name] = {
                        'status': status,
                        'health': health_status,
                        'logs': []
                    }

                    # Count running services
                    if status == 'running':
                        running_services += 1

                    # Log status for debugging
                    deployment_status['logs'].append(f"{service_name}: {status} ({health_status})")

                # Calculate progress - same logic as working script
                if total_services > 0:
                    progress = (running_services / total_services) * 100
                    deployment_status['progress'] = int(progress)
                    deployment_status['current_task'] = f'Monitoring {running_services}/{total_services} services running'

                    if running_services == total_services:
                        deployment_status['phase'] = 'completed'
                        deployment_status['progress'] = 100
                        deployment_status['current_task'] = 'Deployment successful!'
                        deployment_status['logs'].append(f'All {total_services} services are running successfully')

                        # Keep running to continue showing status, don't break
                        # This allows the GUI to stay active and show completion status

                    elif running_services > 0:
                        deployment_status['phase'] = 'building'
                    else:
                        deployment_status['phase'] = 'error'
                        deployment_status['current_task'] = 'No services are running'
                else:
                    deployment_status['current_task'] = 'Waiting for services to start...'

                time.sleep(2)  # 2-second polling to match standalone script
                
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