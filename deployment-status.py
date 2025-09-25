#!/usr/bin/env python3
"""
Standalone Deployment Status Checker
Run this script to check the current status of CA Manager services
"""

import docker
import json
import sys
from datetime import datetime

def check_deployment_status():
    """Check current status of all CA Manager services"""
    try:
        client = docker.from_env()

        print("=" * 60)
        print(f"CA Manager Deployment Status - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        # Get all containers
        containers = client.containers.list(all=True)

        # Filter CA Manager containers - dynamically detect project name
        ca_manager_containers = []
        project_prefix = None

        # First pass: detect the project prefix from any container
        for container in containers:
            if container.name.endswith('-1') and any(service in container.name for service in ['web-interface', 'postgres', 'redis', 'easyrsa-container', 'traefik']):
                # Extract project prefix (everything before the service name)
                parts = container.name.split('-')
                if len(parts) >= 3:  # project-service-1 format
                    # Find where the service name starts
                    for i, part in enumerate(parts[:-1]):  # exclude the '-1' part
                        test_service = '-'.join(parts[i:-1])
                        if test_service in ['web-interface', 'postgres', 'redis', 'easyrsa-container', 'traefik', 'scep-server', 'ios-scep-simulator', 'ocsp-simulator', 'ocsp-responder', 'radius-server']:
                            project_prefix = '-'.join(parts[:i]) + '-'
                            break
                    if project_prefix:
                        break

        # Second pass: collect containers with detected prefix
        if project_prefix:
            for container in containers:
                if container.name.startswith(project_prefix) and container.name.endswith('-1'):
                    # Extract service name (remove project prefix and -1 suffix)
                    service_name = container.name[len(project_prefix):].replace('-1', '')
                    ca_manager_containers.append((service_name, container))

            print(f"Detected project prefix: '{project_prefix}' ({len(ca_manager_containers)} containers)")
        else:
            print("Could not detect project prefix from container names")

        if not ca_manager_containers:
            print("❌ No CA Manager containers found")
            print("   Make sure Docker Compose is running with the correct project name")
            return False

        print(f"Found {len(ca_manager_containers)} CA Manager services:")
        print()

        running_services = 0
        total_services = len(ca_manager_containers)

        for service_name, container in sorted(ca_manager_containers):
            status = container.status

            # Get health status if available
            health_status = "N/A"
            try:
                container_info = container.attrs
                health = container_info.get('State', {}).get('Health', {})
                if health:
                    health_status = health.get('Status', 'unknown')
                elif status == 'running':
                    health_status = "healthy"
            except:
                pass

            # Status emoji
            if status == 'running':
                status_emoji = "✅"
                running_services += 1
            elif status in ['exited', 'dead']:
                status_emoji = "❌"
            else:
                status_emoji = "⏳"

            # Health emoji
            health_emoji = ""
            if health_status == "healthy":
                health_emoji = "💚"
            elif health_status == "unhealthy":
                health_emoji = "💔"
            elif health_status == "starting":
                health_emoji = "💛"

            print(f"{status_emoji} {service_name:<20} {status:<12} {health_emoji} {health_status}")

        print()
        print("-" * 60)

        # Calculate progress
        progress = (running_services / total_services) * 100 if total_services > 0 else 0

        if running_services == total_services:
            print(f"🎉 DEPLOYMENT COMPLETE! All {total_services} services are running")
            print(f"📊 Progress: {progress:.0f}% ({running_services}/{total_services})")

            # Show access URLs
            print()
            print("🌐 Access URLs:")
            print("   📊 Main Application: https://localhost/")
            print("   🍎 SCEP Simulator: https://localhost/simulator/")
            print("   🔍 OCSP Simulator: https://localhost/ocsp-simulator/")
            print("   📈 Traefik Dashboard: http://localhost:8081/")

        elif running_services > 0:
            print(f"⏳ DEPLOYMENT IN PROGRESS: {running_services}/{total_services} services running")
            print(f"📊 Progress: {progress:.0f}%")

        else:
            print("❌ DEPLOYMENT FAILED: No services are running")
            print("   Run ./debug-deployment.sh for detailed troubleshooting")

        print()
        print("💡 Run this script again to refresh the status")
        return running_services == total_services

    except docker.errors.DockerException as e:
        print(f"❌ Error connecting to Docker: {e}")
        print("   Make sure Docker is running and accessible")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    try:
        success = check_deployment_status()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Status check interrupted")
        sys.exit(1)