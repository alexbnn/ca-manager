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
        """Monitor Docker Compose deployment progress"""
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

                containers = self.client.containers.list(all=True)

                # Dynamically discover services on each iteration
                current_services = set()
                for container in containers:
                    if 'ca-manager-f-' in container.name and container.name.endswith('-1'):
                        service_name = container.name.replace('ca-manager-f-', '').replace('-1', '')
                        current_services.add(service_name)

                # Initialize any new services we discover
                for service_name in current_services:
                    if service_name not in deployment_status['services']:
                        deployment_status['services'][service_name] = {
                            'status': 'pending',
                            'health': 'unknown',
                            'logs': []
                        }
                        deployment_status['logs'].append(f"Discovered new service: {service_name}")

                completed_services = 0
                failed_services = []

                for container in containers:
                    # Extract service name from container name (format: ca-manager-f-SERVICE-1)
                    if 'ca-manager-f-' in container.name and container.name.endswith('-1'):
                        # Remove prefix and suffix to get service name
                        service_name = container.name.replace('ca-manager-f-', '').replace('-1', '')

                        if service_name in deployment_status['services']:
                            status = container.status
                            previous_status = deployment_status['services'][service_name].get('status', '')
                            deployment_status['services'][service_name]['status'] = status

                            # Log status changes
                            if previous_status and previous_status != status:
                                deployment_status['logs'].append(f"{service_name}: {previous_status} -> {status}")

                            if status == 'running':
                                completed_services += 1
                                # Check health if available
                                try:
                                    health = container.attrs.get('State', {}).get('Health', {})
                                    if health:
                                        health_status = health.get('Status', 'unknown')
                                        deployment_status['services'][service_name]['health'] = health_status

                                        # If health check is failing, consider it a failure
                                        if health_status == 'unhealthy':
                                            failed_services.append((service_name, container.name))
                                            deployment_status['logs'].append(f"{service_name}: Health check failing")
                                    else:
                                        # No health check means it's considered healthy if running
                                        deployment_status['services'][service_name]['health'] = 'healthy'
                                except Exception as e:
                                    deployment_status['logs'].append(f"Error checking health for {service_name}: {e}")
                                    deployment_status['services'][service_name]['health'] = 'healthy'  # Assume healthy if no health check

                            elif status in ['exited', 'dead', 'restarting']:
                                failed_services.append((service_name, container.name))
                                deployment_status['logs'].append(f"{service_name}: Container in failed state: {status}")

                # Attempt recovery for failed services
                for service_name, container_name in failed_services:
                    if service_name not in deployment_status['recovery_attempts'] or \
                       deployment_status['recovery_attempts'][service_name] < self.max_recovery_attempts:
                        deployment_status['logs'].append(f"Initiating recovery for failed service: {service_name}")
                        self.attempt_service_recovery(service_name, container_name)
                
                # Calculate progress based on discovered services
                total_services = len(current_services)
                if total_services > 0:
                    progress = 10 + (completed_services / total_services) * 80
                    deployment_status['progress'] = int(progress)
                    deployment_status['current_task'] = f'Monitoring {completed_services}/{total_services} services running'

                    if completed_services == total_services:
                        deployment_status['phase'] = 'completed'
                        deployment_status['progress'] = 100
                        deployment_status['current_task'] = 'Deployment successful!'
                        deployment_status['logs'].append(f'All {total_services} services are running successfully')
                        break
                else:
                    deployment_status['current_task'] = 'Waiting for services to start...'
                
                time.sleep(1)  # 1-second polling as requested
                
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