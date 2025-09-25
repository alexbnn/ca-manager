#!/usr/bin/env python3
"""
Web-based Deployment Status Monitor
Provides a GUI interface to monitor CA Manager deployment status
"""

import docker
import json
import time
from datetime import datetime
from flask import Flask, render_template_string, jsonify, Response
import threading

app = Flask(__name__)

# Global status storage
deployment_status = {
    'last_updated': None,
    'services': {},
    'total_services': 0,
    'running_services': 0,
    'progress': 0,
    'phase': 'checking',
    'errors': []
}

def update_deployment_status():
    """Update deployment status from Docker"""
    global deployment_status

    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)

        # Filter CA Manager containers
        ca_manager_containers = []
        for container in containers:
            if 'ca-manager-f-' in container.name and container.name.endswith('-1'):
                service_name = container.name.replace('ca-manager-f-', '').replace('-1', '')
                ca_manager_containers.append((service_name, container))

        services = {}
        running_count = 0
        total_count = len(ca_manager_containers)

        if total_count == 0:
            deployment_status.update({
                'last_updated': datetime.now().isoformat(),
                'services': {},
                'total_services': 0,
                'running_services': 0,
                'progress': 0,
                'phase': 'no_containers',
                'errors': ['No CA Manager containers found']
            })
            return

        for service_name, container in ca_manager_containers:
            status = container.status

            # Get health status
            health_status = "N/A"
            health_color = "gray"
            try:
                container_info = container.attrs
                health = container_info.get('State', {}).get('Health', {})
                if health:
                    health_status = health.get('Status', 'unknown')
                    if health_status == "healthy":
                        health_color = "green"
                    elif health_status == "unhealthy":
                        health_color = "red"
                    elif health_status == "starting":
                        health_color = "yellow"
                elif status == 'running':
                    health_status = "healthy"
                    health_color = "green"
            except:
                pass

            # Status color
            if status == 'running':
                status_color = "green"
                running_count += 1
            elif status in ['exited', 'dead']:
                status_color = "red"
            else:
                status_color = "yellow"

            services[service_name] = {
                'status': status,
                'status_color': status_color,
                'health': health_status,
                'health_color': health_color
            }

        # Calculate progress
        progress = (running_count / total_count) * 100 if total_count > 0 else 0

        # Determine phase
        if running_count == total_count:
            phase = 'completed'
        elif running_count > 0:
            phase = 'in_progress'
        else:
            phase = 'failed'

        deployment_status.update({
            'last_updated': datetime.now().isoformat(),
            'services': services,
            'total_services': total_count,
            'running_services': running_count,
            'progress': int(progress),
            'phase': phase,
            'errors': []
        })

    except docker.errors.DockerException as e:
        deployment_status.update({
            'last_updated': datetime.now().isoformat(),
            'phase': 'error',
            'errors': [f'Docker error: {str(e)}']
        })
    except Exception as e:
        deployment_status.update({
            'last_updated': datetime.now().isoformat(),
            'phase': 'error',
            'errors': [f'Unexpected error: {str(e)}']
        })

def status_updater():
    """Background thread to update status every 2 seconds"""
    while True:
        update_deployment_status()
        time.sleep(2)

# Start background status updater
status_thread = threading.Thread(target=status_updater, daemon=True)
status_thread.start()

@app.route('/')
def index():
    """Main deployment status page"""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CA Manager - Deployment Status</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                overflow: hidden;
            }

            .header {
                background: linear-gradient(45deg, #2c3e50, #34495e);
                color: white;
                padding: 30px;
                text-align: center;
            }

            .header h1 {
                font-size: 2.5em;
                margin-bottom: 10px;
            }

            .header .subtitle {
                opacity: 0.8;
                font-size: 1.1em;
            }

            .progress-section {
                padding: 30px;
                background: #f8f9fa;
                border-bottom: 1px solid #e9ecef;
            }

            .progress-info {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }

            .progress-text {
                font-size: 1.3em;
                font-weight: 600;
            }

            .progress-percentage {
                font-size: 2em;
                font-weight: bold;
                color: #2c3e50;
            }

            .progress-bar-container {
                background: #e9ecef;
                height: 20px;
                border-radius: 10px;
                overflow: hidden;
                position: relative;
            }

            .progress-bar {
                height: 100%;
                background: linear-gradient(45deg, #28a745, #20c997);
                border-radius: 10px;
                transition: width 0.5s ease;
                position: relative;
                overflow: hidden;
            }

            .progress-bar::after {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                bottom: 0;
                right: 0;
                background: linear-gradient(45deg, transparent 25%, rgba(255,255,255,.2) 25%, rgba(255,255,255,.2) 50%, transparent 50%, transparent 75%, rgba(255,255,255,.2) 75%);
                background-size: 30px 30px;
                animation: progress-animation 1s linear infinite;
            }

            @keyframes progress-animation {
                0% { background-position: 0 0; }
                100% { background-position: 30px 0; }
            }

            .services-section {
                padding: 30px;
            }

            .services-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }

            .service-card {
                background: white;
                border: 2px solid #e9ecef;
                border-radius: 10px;
                padding: 20px;
                transition: all 0.3s ease;
            }

            .service-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }

            .service-card.running {
                border-color: #28a745;
                background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            }

            .service-card.stopped {
                border-color: #dc3545;
                background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
            }

            .service-card.starting {
                border-color: #ffc107;
                background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
            }

            .service-name {
                font-size: 1.2em;
                font-weight: bold;
                margin-bottom: 10px;
                color: #2c3e50;
            }

            .service-status {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 8px;
            }

            .status-badge {
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.9em;
                font-weight: 600;
                text-transform: uppercase;
                color: white;
            }

            .status-badge.green { background: #28a745; }
            .status-badge.red { background: #dc3545; }
            .status-badge.yellow { background: #ffc107; color: #333; }
            .status-badge.gray { background: #6c757d; }

            .phase-banner {
                text-align: center;
                padding: 20px;
                font-size: 1.5em;
                font-weight: bold;
                color: white;
                margin-bottom: 20px;
                border-radius: 10px;
            }

            .phase-banner.completed {
                background: linear-gradient(45deg, #28a745, #20c997);
            }

            .phase-banner.in_progress {
                background: linear-gradient(45deg, #007bff, #0056b3);
            }

            .phase-banner.failed {
                background: linear-gradient(45deg, #dc3545, #c82333);
            }

            .phase-banner.error {
                background: linear-gradient(45deg, #6f42c1, #563d7c);
            }

            .access-urls {
                background: #e8f5e8;
                padding: 20px;
                border-radius: 10px;
                margin-top: 20px;
            }

            .access-urls h3 {
                color: #155724;
                margin-bottom: 15px;
            }

            .access-urls a {
                display: block;
                color: #155724;
                text-decoration: none;
                margin-bottom: 8px;
                padding: 8px 12px;
                background: white;
                border-radius: 5px;
                border-left: 4px solid #28a745;
            }

            .access-urls a:hover {
                background: #f8f9fa;
            }

            .last-updated {
                text-align: center;
                color: #6c757d;
                font-size: 0.9em;
                margin-top: 20px;
                padding: 20px;
                border-top: 1px solid #e9ecef;
            }

            .refresh-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background: #28a745;
                margin-left: 8px;
                animation: pulse 2s infinite;
            }

            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚀 CA Manager</h1>
                <p class="subtitle">Deployment Status Monitor</p>
            </div>

            <div class="progress-section">
                <div class="progress-info">
                    <span class="progress-text" id="progress-text">Loading...</span>
                    <span class="progress-percentage" id="progress-percentage">--%</span>
                </div>
                <div class="progress-bar-container">
                    <div class="progress-bar" id="progress-bar" style="width: 0%"></div>
                </div>
            </div>

            <div class="services-section">
                <div id="phase-banner" class="phase-banner" style="display: none;"></div>

                <h2>Services Status</h2>
                <div class="services-grid" id="services-grid">
                    <div style="text-align: center; color: #6c757d;">Loading services...</div>
                </div>

                <div id="access-urls" class="access-urls" style="display: none;">
                    <h3>🌐 Access URLs</h3>
                    <a href="https://localhost/" target="_blank">📊 Main Application</a>
                    <a href="https://localhost/simulator/" target="_blank">🍎 SCEP Simulator</a>
                    <a href="https://localhost/ocsp-simulator/" target="_blank">🔍 OCSP Simulator</a>
                    <a href="http://localhost:8081/" target="_blank">📈 Traefik Dashboard</a>
                </div>
            </div>

            <div class="last-updated">
                <span id="last-updated">Last updated: Never</span>
                <span class="refresh-indicator"></span>
            </div>
        </div>

        <script>
            function updateStatus() {
                fetch('/api/status')
                    .then(response => response.json())
                    .then(data => {
                        // Update progress
                        const progressBar = document.getElementById('progress-bar');
                        const progressText = document.getElementById('progress-text');
                        const progressPercentage = document.getElementById('progress-percentage');

                        progressBar.style.width = data.progress + '%';
                        progressText.textContent = `${data.running_services}/${data.total_services} services running`;
                        progressPercentage.textContent = data.progress + '%';

                        // Update phase banner
                        const phaseBanner = document.getElementById('phase-banner');
                        phaseBanner.className = 'phase-banner ' + data.phase;
                        phaseBanner.style.display = 'block';

                        switch(data.phase) {
                            case 'completed':
                                phaseBanner.innerHTML = '🎉 DEPLOYMENT COMPLETE!';
                                break;
                            case 'in_progress':
                                phaseBanner.innerHTML = '⏳ DEPLOYMENT IN PROGRESS';
                                break;
                            case 'failed':
                                phaseBanner.innerHTML = '❌ DEPLOYMENT FAILED';
                                break;
                            case 'error':
                                phaseBanner.innerHTML = '🚨 MONITORING ERROR';
                                break;
                            case 'no_containers':
                                phaseBanner.innerHTML = '📦 NO CONTAINERS FOUND';
                                break;
                            default:
                                phaseBanner.innerHTML = '🔍 CHECKING STATUS';
                        }

                        // Update services grid
                        const servicesGrid = document.getElementById('services-grid');
                        if (Object.keys(data.services).length === 0) {
                            servicesGrid.innerHTML = '<div style="text-align: center; color: #6c757d;">No services found</div>';
                        } else {
                            let servicesHtml = '';
                            for (const [name, service] of Object.entries(data.services)) {
                                const cardClass = service.status === 'running' ? 'running' :
                                                service.status === 'exited' || service.status === 'dead' ? 'stopped' : 'starting';

                                servicesHtml += `
                                    <div class="service-card ${cardClass}">
                                        <div class="service-name">${name}</div>
                                        <div class="service-status">
                                            <span>Status:</span>
                                            <span class="status-badge ${service.status_color}">${service.status}</span>
                                        </div>
                                        <div class="service-status">
                                            <span>Health:</span>
                                            <span class="status-badge ${service.health_color}">${service.health}</span>
                                        </div>
                                    </div>
                                `;
                            }
                            servicesGrid.innerHTML = servicesHtml;
                        }

                        // Show access URLs if deployment is complete
                        const accessUrls = document.getElementById('access-urls');
                        accessUrls.style.display = data.phase === 'completed' ? 'block' : 'none';

                        // Update last updated time
                        const lastUpdated = document.getElementById('last-updated');
                        if (data.last_updated) {
                            const date = new Date(data.last_updated);
                            lastUpdated.textContent = `Last updated: ${date.toLocaleString()}`;
                        }
                    })
                    .catch(error => {
                        console.error('Error fetching status:', error);
                        document.getElementById('progress-text').textContent = 'Error loading status';
                    });
            }

            // Initial load and refresh every 2 seconds
            updateStatus();
            setInterval(updateStatus, 2000);
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template)

@app.route('/api/status')
def api_status():
    """API endpoint for deployment status"""
    return jsonify(deployment_status)

@app.route('/api/progress')
def progress_stream():
    """Server-Sent Events stream for real-time updates"""
    def generate():
        last_status = None
        while True:
            current_status = json.dumps(deployment_status)
            if current_status != last_status:
                yield f"data: {current_status}\n\n"
                last_status = current_status
            time.sleep(2)

    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    print("🚀 Starting CA Manager Deployment Status Monitor")
    print("📊 Access the GUI at: http://localhost:8002")
    print("🔄 Status updates every 2 seconds")
    print("")

    # Initialize status on startup
    update_deployment_status()

    app.run(host='0.0.0.0', port=8002, debug=False)