#!/usr/bin/env python3
"""
CA Manager Setup Wizard
Modern web-based first-time setup for CA Manager deployment
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, Response
import os
import json
import yaml
import secrets
import re
import subprocess
import threading
import time
import queue
from pathlib import Path
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    print("⚠️  Docker SDK not available. Deployment monitoring will be limited.")

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration file paths
SETUP_CONFIG_FILE = '/app/setup_complete.json'
TRAEFIK_CONFIG_FILE = '/app/traefik.yml'
DOCKER_COMPOSE_FILE = '/app/docker-compose.yml'
ENV_FILE = '/app/.env'

# Deployment monitoring globals
deployment_status = {
    'phase': 'waiting',
    'progress': 0,
    'current_task': 'Waiting for deployment to start...',
    'services': {},
    'logs': [],
    'errors': [],
    'domain': 'localhost'
}
deployment_monitor_thread = None

def is_setup_complete():
    """Check if setup has been completed"""
    return os.path.exists(SETUP_CONFIG_FILE)

def check_existing_deployment():
    """Check for existing CA Manager deployment"""
    try:
        # Check for existing volumes that might conflict
        result = subprocess.run(['docker', 'volume', 'ls', '--format', '{{.Name}}'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            volumes = result.stdout.strip().split('\n')
            ca_volumes = [v for v in volumes if 'postgres-data' in v or 'easyrsa-pki' in v]
            return ca_volumes
        return []
    except Exception:
        return []

def validate_domain(domain):
    """Validate domain name format"""
    if not domain or domain.lower() == 'localhost':
        return True
    
    # Basic domain validation
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(pattern, domain) is not None

def generate_secure_password():
    """Generate a secure password"""
    return secrets.token_urlsafe(16)

def update_traefik_config(domain, ssl_type, email=None):
    """Update Traefik configuration with domain and SSL settings"""
    config = {
        'api': {
            'dashboard': True,
            'insecure': True
        },
        'entryPoints': {
            'web': {
                'address': ':80',
                'http': {
                    'redirections': {
                        'entrypoint': {
                            'to': 'websecure',
                            'scheme': 'https'
                        }
                    }
                }
            },
            'websecure': {
                'address': ':443'
            }
        },
        'providers': {
            'docker': {
                'endpoint': 'unix:///var/run/docker.sock',
                'exposedByDefault': False,
                'network': 'easyrsa-network'
            }
        },
        'log': {
            'level': 'INFO',
            'filePath': '/var/log/traefik/traefik.log'
        },
        'accessLog': {
            'filePath': '/var/log/traefik/access.log'
        },
        'metrics': {
            'prometheus': {
                'addRoutersLabels': True
            }
        }
    }
    
    use_letsencrypt = ssl_type in ['letsencrypt-http', 'letsencrypt-tls']
    
    if use_letsencrypt and email and domain != 'localhost':
        acme_config = {
            'email': email,
            'storage': '/letsencrypt/acme.json'
        }
        
        # Configure challenge type based on SSL type
        if ssl_type == 'letsencrypt-http':
            acme_config['httpChallenge'] = {
                'entryPoint': 'web'
            }
        elif ssl_type == 'letsencrypt-tls':
            acme_config['tlsChallenge'] = {}
        
        config['certificatesResolvers'] = {
            'letsencrypt': {
                'acme': acme_config
            }
        }
    
    # Always add file provider for dynamic configuration
    config['providers']['file'] = {
        'filename': '/etc/traefik/traefik-dynamic.yml',
        'watch': True
    }
    
    return config

def update_docker_compose_labels(domain, ssl_type):
    """Generate Docker Compose labels for services"""
    # Use the domain directly without adding ca subdomain
    ca_domain = domain
    
    web_labels = [
        "traefik.enable=true",
        f"traefik.http.routers.web.rule=Host(`{domain}`)",
        "traefik.http.routers.web.priority=10",
        "traefik.http.routers.web.tls=true",
        "traefik.http.services.web.loadbalancer.server.port=5000"
    ]
    
    scep_labels = [
        "traefik.enable=true",
        f"traefik.http.routers.scep.rule=Host(`{ca_domain}`) && PathPrefix(`/scep`)",
        "traefik.http.routers.scep.priority=100",
        "traefik.http.routers.scep.tls=true",
        "traefik.http.services.scep.loadbalancer.server.port=8090"
    ]
    
    # Add OCSP responder labels
    ocsp_responder_labels = [
        "traefik.enable=true",
        f"traefik.http.routers.ocsp.rule=Host(`{ca_domain}`) && PathPrefix(`/ocsp`)",
        "traefik.http.routers.ocsp.priority=100",
        "traefik.http.routers.ocsp.tls=true",
        "traefik.http.services.ocsp.loadbalancer.server.port=8091"
    ]
    
    # Add OCSP simulator labels 
    ocsp_simulator_labels = [
        "traefik.enable=true",
        f"traefik.http.routers.ocsp-simulator.rule=Host(`{domain}`) && PathPrefix(`/ocsp-simulator`)",
        "traefik.http.routers.ocsp-simulator.priority=500",
        "traefik.http.routers.ocsp-simulator.tls=true",
        "traefik.http.services.ocsp-simulator.loadbalancer.server.port=4000"
    ]
    
    # Add iOS simulator labels
    ios_simulator_labels = [
        "traefik.enable=true",
        f"traefik.http.routers.simulator.rule=Host(`{domain}`) && PathPrefix(`/simulator`)",
        "traefik.http.routers.simulator.priority=1000",
        "traefik.http.routers.simulator.tls=true",
        "traefik.http.services.simulator.loadbalancer.server.port=3000"
    ]
    
    use_letsencrypt = ssl_type in ['letsencrypt-http', 'letsencrypt-tls']
    
    if use_letsencrypt and domain != 'localhost':
        web_labels.append("traefik.http.routers.web.tls.certResolver=letsencrypt")
        scep_labels.append("traefik.http.routers.scep.tls.certResolver=letsencrypt")
        ocsp_responder_labels.append("traefik.http.routers.ocsp.tls.certResolver=letsencrypt")
        ocsp_simulator_labels.append("traefik.http.routers.ocsp-simulator.tls.certResolver=letsencrypt")
        ios_simulator_labels.append("traefik.http.routers.simulator.tls.certResolver=letsencrypt")
    
    return {
        'web_labels': web_labels,
        'scep_labels': scep_labels,
        'ocsp_responder_labels': ocsp_responder_labels,
        'ocsp_simulator_labels': ocsp_simulator_labels,
        'ios_simulator_labels': ios_simulator_labels
    }

def create_traefik_dynamic_config():
    """Create traefik-dynamic.yml configuration"""
    return """# Traefik Dynamic Configuration
# This file handles TLS certificates and additional routing rules

# TLS Configuration for self-signed certificates
tls:
  options:
    default:
      minVersion: "VersionTLS12"
      cipherSuites:
        - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
        - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  
  certificates:
    - certFile: /ssl/server.crt
      keyFile: /ssl/server.key

# HTTP Middlewares
http:
  middlewares:
    # Security headers
    security-headers:
      headers:
        customRequestHeaders:
          X-Forwarded-Proto: "https"
        customResponseHeaders:
          X-Frame-Options: "DENY"
          X-Content-Type-Options: "nosniff"
          X-XSS-Protection: "1; mode=block"
          Strict-Transport-Security: "max-age=31536000; includeSubDomains"
          Referrer-Policy: "strict-origin-when-cross-origin"
        contentTypeNosniff: true
        frameDeny: true
        sslRedirect: true
        
    # Rate limiting
    api-rate-limit:
      rateLimit:
        burst: 10
        average: 5
        period: "1m"
        
    web-rate-limit:
      rateLimit:
        burst: 30
        average: 10
        period: "1m"
        
    # WebSocket-friendly headers for noVNC
    websocket-headers:
      headers:
        customRequestHeaders:
          X-Forwarded-Proto: "https"
        # Remove problematic security headers for WebSocket connections
        customResponseHeaders:
          X-Content-Type-Options: "nosniff"
        contentTypeNosniff: false
        frameDeny: false

  # Services can be defined here if needed
  services: {}
"""

def create_env_file(config):
    """Create .env file with configuration"""
    # Use the domain directly without adding ca subdomain
    domain = config['domain']
    ca_domain = domain
    
    env_content = f"""# CA Manager Configuration v4.0.0 - Generated by Setup Wizard
# Domain Configuration
DOMAIN={domain}
SCEP_SERVER_URL=https://{domain}/scep

# OCSP Configuration
OCSP_RESPONDER_URL=http://ocsp-responder:8091
CA_MANAGER_BASE_URL=https://{domain}

# Security Configuration
SECRET_KEY={config['secret_key']}
ADMIN_PASSWORD_HASH={config['admin_password']}

# Database Configuration
POSTGRES_DB=pkiauth
POSTGRES_USER=pkiuser
POSTGRES_PASSWORD={config['db_password']}
DATABASE_URL=postgresql://pkiuser:{config['db_password']}@postgres:5432/pkiauth

# PKI Configuration
EASYRSA_REQ_COUNTRY={config.get('country', 'US')}
EASYRSA_REQ_PROVINCE={config.get('state', 'California')}
EASYRSA_REQ_CITY={config.get('city', 'San Francisco')}
EASYRSA_REQ_ORG={config.get('organization', 'My Organization')}
EASYRSA_REQ_EMAIL={config.get('email', 'admin@localhost')}
EASYRSA_REQ_OU={config.get('organizational_unit', 'IT Department')}

# Application Settings
AUTHENTICATION_ENABLED=true
MULTI_USER_MODE=true
LOG_LEVEL=INFO
FLASK_ENV=production

# Rate Limiting
RATELIMIT_STORAGE_URL=redis://redis:6379

"""
    return env_content

def monitor_deployment():
    """Monitor Docker Compose deployment progress"""
    global deployment_status
    
    if not DOCKER_AVAILABLE:
        deployment_status['errors'].append("Docker SDK not available for monitoring")
        deployment_status['phase'] = 'error'
        return
    
    try:
        # Try to connect to Docker daemon
        client = docker.from_env()
        client.ping()  # Test connection
    except Exception as e:
        deployment_status['errors'].append(f"Cannot connect to Docker daemon: {str(e)}")
        # Fall back to subprocess monitoring
        return monitor_deployment_fallback()
    
    services = [
        'traefik', 'postgres', 'redis', 'web-interface', 'easyrsa-container',
        'scep-server', 'ios-scep-simulator', 'ocsp-simulator', 'ocsp-responder'
    ]
    
    # Initialize service status
    for service in services:
        deployment_status['services'][service] = {
            'status': 'pending',
            'health': 'unknown'
        }
    
    try:
        client = docker.from_env()
        deployment_status['phase'] = 'building'
        deployment_status['progress'] = 5
        deployment_status['current_task'] = 'Building Docker images...'
        
        # Monitor for up to 10 minutes
        max_iterations = 300  # 300 * 2 seconds = 10 minutes
        iteration = 0
        
        while iteration < max_iterations:
            try:
                containers = client.containers.list(all=True)
                running_services = 0
                healthy_services = 0
                
                # Update service statuses
                for container in containers:
                    if 'ca-manager-f' in container.name:
                        # Extract service name from container name
                        name_parts = container.name.split('-')
                        if len(name_parts) >= 4:
                            service_name = '-'.join(name_parts[3:-1])  # Handle multi-part service names
                            
                            if service_name in deployment_status['services']:
                                status = container.status
                                deployment_status['services'][service_name]['status'] = status
                                
                                if status == 'running':
                                    running_services += 1
                                    
                                    # Check health if available
                                    try:
                                        health = container.attrs.get('State', {}).get('Health', {})
                                        if health:
                                            health_status = health.get('Status', 'unknown')
                                            deployment_status['services'][service_name]['health'] = health_status
                                            if health_status == 'healthy':
                                                healthy_services += 1
                                    except:
                                        pass
                
                # Update progress based on running services
                if len(services) > 0:
                    progress = 10 + (running_services / len(services)) * 70
                    deployment_status['progress'] = int(progress)
                    
                    if running_services >= len(services) * 0.8:  # 80% of services running
                        deployment_status['phase'] = 'configuring_ssl'
                        deployment_status['current_task'] = 'Configuring SSL certificates...'
                        
                        # Check for successful certificate acquisition
                        if check_certificates():
                            deployment_status['phase'] = 'completed'
                            deployment_status['progress'] = 100
                            deployment_status['current_task'] = 'Deployment completed successfully!'
                            break
                    elif running_services > 0:
                        deployment_status['phase'] = 'starting_services'
                        deployment_status['current_task'] = f'Starting services ({running_services}/{len(services)} running)...'
                
                iteration += 1
                time.sleep(2)
                
            except Exception as e:
                deployment_status['logs'].append(f"Monitoring error: {str(e)}")
                time.sleep(5)
                
    except Exception as e:
        deployment_status['errors'].append(f"Failed to start deployment monitoring: {str(e)}")
        deployment_status['phase'] = 'error'

def monitor_deployment_fallback():
    """Fallback deployment monitoring using subprocess"""
    global deployment_status
    
    deployment_status['phase'] = 'building'
    deployment_status['progress'] = 10
    deployment_status['current_task'] = 'Building and starting services...'
    
    # Simulate progress over time since we can't directly monitor Docker
    max_iterations = 180  # 3 minutes
    iteration = 0
    
    while iteration < max_iterations:
        try:
            # Check if docker-compose is still running
            result = subprocess.run(['docker-compose', 'ps', '-q'], 
                                  capture_output=True, text=True, cwd='/app')
            
            if result.returncode == 0:
                container_ids = result.stdout.strip().split('\n')
                running_containers = [cid for cid in container_ids if cid.strip()]
                
                if len(running_containers) > 0:
                    # Update progress based on time elapsed
                    progress = min(20 + (iteration / max_iterations) * 70, 90)
                    deployment_status['progress'] = int(progress)
                    
                    if iteration > 60:  # After 2 minutes, assume services are starting
                        deployment_status['phase'] = 'starting_services'
                        deployment_status['current_task'] = 'Services are starting...'
                        
                    if iteration > 120:  # After 4 minutes, check for completion
                        deployment_status['phase'] = 'configuring_ssl'
                        deployment_status['current_task'] = 'Configuring SSL certificates...'
                        
                        # Check if we can access the application
                        if check_application_ready():
                            deployment_status['phase'] = 'completed'
                            deployment_status['progress'] = 100
                            deployment_status['current_task'] = 'Deployment completed successfully!'
                            break
            
            iteration += 1
            time.sleep(1)
            
        except Exception as e:
            deployment_status['logs'].append(f"Monitoring error: {str(e)}")
            time.sleep(2)
    
    # If we've waited long enough, assume deployment is complete
    if deployment_status['phase'] != 'completed':
        deployment_status['phase'] = 'completed'
        deployment_status['progress'] = 100
        deployment_status['current_task'] = 'Deployment should be complete - check manually if needed'

def check_application_ready():
    """Check if the application is ready by testing HTTP access"""
    try:
        import urllib.request
        urllib.request.urlopen('http://localhost:80', timeout=5)
        return True
    except:
        return False

def check_certificates():
    """Check if Let's Encrypt certificates have been acquired"""
    try:
        if not DOCKER_AVAILABLE:
            return False
            
        client = docker.from_env()
        traefik_container = client.containers.get('ca-manager-f-traefik-1')
        logs = traefik_container.logs(tail=100).decode('utf-8')
        
        success_indicators = [
            'certificate obtained successfully',
            'server responded with a certificate',
            'acme: certificate obtained successfully'
        ]
        
        return any(indicator in logs.lower() for indicator in success_indicators)
    except:
        return False

@app.route('/progress')
def deployment_progress():
    """Show deployment progress page"""
    return render_template('deployment_progress.html')

@app.route('/api/deployment/status')
def get_deployment_status():
    """Get current deployment status"""
    return jsonify(deployment_status)

@app.route('/api/deployment/start', methods=['POST'])
def start_deployment_monitoring():
    """Start deployment monitoring"""
    global deployment_monitor_thread
    
    data = request.get_json() or {}
    domain = data.get('domain', 'localhost')
    deployment_status['domain'] = domain
    
    if deployment_monitor_thread is None or not deployment_monitor_thread.is_alive():
        deployment_status['phase'] = 'initializing'
        deployment_status['progress'] = 0
        deployment_status['current_task'] = 'Starting deployment monitoring...'
        
        deployment_monitor_thread = threading.Thread(target=monitor_deployment)
        deployment_monitor_thread.daemon = True
        deployment_monitor_thread.start()
        
        return jsonify({'success': True, 'message': 'Deployment monitoring started'})
    
    return jsonify({'success': True, 'message': 'Monitoring already active'})

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
                
                # Stop streaming when deployment is complete or failed
                if deployment_status['phase'] in ['completed', 'error']:
                    break
                    
            time.sleep(1)
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/')
def index():
    """Main setup wizard page"""
    if is_setup_complete():
        return redirect(url_for('complete'))
    return render_template('wizard.html')

@app.route('/api/setup', methods=['POST'])
def setup_configuration():
    """Process setup configuration"""
    try:
        data = request.get_json()
        
        # Validate required fields (admin_password no longer required)
        required_fields = ['domain', 'ssl_type', 'organization', 'country']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        domain = data['domain'].strip().lower()
        ssl_type = data['ssl_type']
        use_letsencrypt = ssl_type in ['letsencrypt-http', 'letsencrypt-tls']
        email = data.get('email', '').strip()
        
        # Validate domain
        if not validate_domain(domain):
            return jsonify({'error': 'Invalid domain format'}), 400
        
        # Validate email if using Let's Encrypt
        if use_letsencrypt and domain != 'localhost':
            if not email or '@' not in email:
                return jsonify({'error': 'Valid email required for Let\'s Encrypt certificates'}), 400
        
        # Generate configuration
        config = {
            'domain': domain,
            'ssl_type': data['ssl_type'],
            'email': email,
            'secret_key': secrets.token_urlsafe(32),
            'admin_password': '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',  # SHA-256 hash of 'admin'
            'db_password': secrets.token_urlsafe(16),
            'organization': data['organization'],
            'country': data['country'],
            'state': data.get('state', 'California'),
            'city': data.get('city', 'San Francisco'),
            'organizational_unit': data.get('organizational_unit', 'IT Department'),
            'use_letsencrypt': use_letsencrypt,
            'setup_timestamp': str(Path().cwd())
        }
        
        # Update Traefik configuration
        traefik_config = update_traefik_config(domain, ssl_type, email)
        
        # Create configuration files (in production, these would be written to mounted volumes)
        config_output = {
            'traefik_config': traefik_config,
            'env_content': create_env_file(config),
            'docker_labels': update_docker_compose_labels(domain, ssl_type),
            'setup_complete': True,
            'domain': domain  # Include domain for redirect after deployment
        }
        
        # Save configuration files to mounted volume
        try:
            # Ensure output directory exists and has proper permissions
            import stat
            output_dir = '/app/output'
            
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, mode=0o755, exist_ok=True)
            
            # Check if we can write to the directory
            if not os.access(output_dir, os.W_OK):
                return jsonify({'error': f'Cannot write to output directory: {output_dir}'}), 500
            
            # Write .env file
            env_path = os.path.join(output_dir, '.env')
            with open(env_path, 'w') as f:
                f.write(create_env_file(config))
            print(f"✅ Written .env file to {env_path}")
            
            # Write traefik configuration
            traefik_path = os.path.join(output_dir, 'traefik.yml')
            with open(traefik_path, 'w') as f:
                yaml.dump(traefik_config, f, default_flow_style=False)
            print(f"✅ Written traefik.yml to {traefik_path}")
            
            # Write traefik dynamic configuration
            traefik_dynamic_path = os.path.join(output_dir, 'traefik-dynamic.yml')
            with open(traefik_dynamic_path, 'w') as f:
                f.write(create_traefik_dynamic_config())
            print(f"✅ Written traefik-dynamic.yml to {traefik_dynamic_path}")
            
            # Update docker-compose labels
            labels_dict = update_docker_compose_labels(domain, ssl_type)
            
            # Save setup completion marker
            completion_path = os.path.join(output_dir, 'setup_complete.flag')
            
            # Remove existing file if it exists (to handle permission issues)
            if os.path.exists(completion_path):
                try:
                    os.remove(completion_path)
                    print(f"🗑️ Removed existing {completion_path}")
                except Exception as e:
                    print(f"⚠️ Could not remove existing file: {e}")
            
            with open(completion_path, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"✅ Written setup_complete.flag to {completion_path}")
            
            # Save labels for docker-compose update
            labels_config = labels_dict
            labels_path = os.path.join(output_dir, 'docker_labels.json')
            with open(labels_path, 'w') as f:
                json.dump(labels_config, f, indent=2)
            print(f"✅ Written docker_labels.json to {labels_path}")
                
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"❌ Failed to save configuration: {str(e)}")
            print(f"Error details: {error_details}")
            return jsonify({'error': f'Failed to save configuration: {str(e)}'}), 500
        
        return jsonify({
            'success': True,
            'message': 'Configuration generated successfully!',
            'config': config_output,
            'next_steps': [
                'Download the generated configuration files',
                'Update your docker-compose.yml with the new labels',
                'Create the .env file with your configuration',
                'Run docker-compose up -d to start your CA Manager',
                f'Access your CA Manager at https://{domain}'
            ]
        })
        
    except Exception as e:
        return jsonify({'error': f'Setup failed: {str(e)}'}), 500

@app.route('/api/deploy', methods=['POST'])
def deploy_application():
    """Trigger deployment of the main application"""
    try:
        output_dir = '/app/output'
        
        # Ensure output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, mode=0o755, exist_ok=True)
            print(f"Created output directory: {output_dir}")
        
        # Check if setup was completed
        setup_complete_path = os.path.join(output_dir, 'setup_complete.flag')
        if not os.path.exists(setup_complete_path):
            print(f"Setup not completed - missing {setup_complete_path}")
            return jsonify({'error': 'Setup not completed. Please run the setup first.'}), 400
        
        # Update docker-compose.yml with new labels (if it exists)
        docker_compose_path = os.path.join(output_dir, 'docker-compose.yml')
        if os.path.exists(docker_compose_path):
            update_docker_compose_file()
        else:
            print(f"Warning: docker-compose.yml not found at {docker_compose_path}, skipping update")
        
        # Create cleanup instructions for the deployment script
        cleanup_instructions = {
            'reset_database': True,
            'cleanup_volumes': ['postgres-data'],  # Reset database to avoid password conflicts
            'reason': 'New setup with different database password'
        }
        
        cleanup_path = os.path.join(output_dir, 'cleanup_instructions.json')
        with open(cleanup_path, 'w') as f:
            json.dump(cleanup_instructions, f, indent=2)
        print(f"✅ Written cleanup instructions to {cleanup_path}")
        
        # Signal that deployment should start
        deploy_ready_path = os.path.join(output_dir, 'deploy_ready.flag')
        with open(deploy_ready_path, 'w') as f:
            f.write('ready')
        print(f"✅ Created deploy_ready.flag at {deploy_ready_path}")
        
        return jsonify({
            'success': True,
            'message': 'Deployment triggered successfully!',
            'files_created': [
                'cleanup_instructions.json',
                'deploy_ready.flag'
            ]
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"❌ Deployment failed: {str(e)}")
        print(f"Error details: {error_details}")
        return jsonify({'error': f'Deployment failed: {str(e)}'}), 500

def update_docker_compose_file():
    """Update docker-compose.yml with generated labels"""
    try:
        with open('/app/output/docker_labels.json', 'r') as f:
            labels = json.load(f)
        
        # Read current docker-compose.yml
        with open('/app/output/docker-compose.yml', 'r') as f:
            compose_content = f.read()
        
        # Generate label strings for each service
        service_labels = {}
        for service_name, service_labels_list in labels.items():
            service_labels[service_name] = '\n'.join([f'      - "{label}"' for label in service_labels_list])
        
        # Update the compose file (this is a simplified approach)
        # Replace the labels sections for each service
        import re
        
        # Service name mappings
        service_mappings = {
            'web_labels': 'web-interface',
            'scep_labels': 'scep-server',
            'ocsp_responder_labels': 'ocsp-responder',
            'ocsp_simulator_labels': 'ocsp-simulator',
            'ios_simulator_labels': 'ios-scep-simulator'
        }
        
        # Replace labels for each service
        for label_key, service_name in service_mappings.items():
            if label_key in service_labels:
                pattern = rf'(  {re.escape(service_name)}:.*?)(    labels:\s*\n(?:      - "[^"]*"\s*\n)*)'
                replacement = f'\\1    labels:\n{service_labels[label_key]}\n'
                compose_content = re.sub(pattern, replacement, compose_content, flags=re.DOTALL)
        
        # Write back the updated file
        with open('/app/output/docker-compose.yml', 'w') as f:
            f.write(compose_content)
            
    except Exception as e:
        print(f"Warning: Could not update docker-compose.yml: {e}")
        # Non-fatal error, deployment can continue

@app.route('/complete')
def complete():
    """Setup completion page"""
    return render_template('complete.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'setup_complete': is_setup_complete()})

@app.route('/api/status')
def deployment_status():
    """Get deployment status and warnings"""
    try:
        existing_volumes = check_existing_deployment()
        warnings = []
        
        if existing_volumes:
            warnings.append({
                'type': 'existing_deployment',
                'message': 'Found existing CA Manager data volumes. Database will be reset to avoid password conflicts.',
                'volumes': existing_volumes
            })
        
        return jsonify({
            'status': 'ready',
            'existing_volumes': existing_volumes,
            'warnings': warnings,
            'setup_complete': is_setup_complete()
        })
        
    except Exception as e:
        return jsonify({'error': f'Status check failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)