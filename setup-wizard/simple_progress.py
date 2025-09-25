#!/usr/bin/env python3
"""
Simple Deployment Progress Monitor
Shows a clean progress page and redirects when the main application is ready
"""

from flask import Flask, render_template_string, jsonify, request
import requests
import threading
import time
import os

app = Flask(__name__)

# Global status
deployment_status = {
    'ready': False,
    'checking': True,
    'domain': None,
    'start_time': time.time(),
    'last_check': None,
    'error': None
}

def check_main_application():
    """Background thread to check if main application is ready"""
    global deployment_status

    # Get domain from environment or use localhost
    domain = os.getenv('DOMAIN', 'localhost')
    deployment_status['domain'] = domain

    # Try both HTTP and HTTPS
    urls_to_try = [
        f"https://{domain}/",
        f"http://{domain}/",
        f"https://localhost/",
        f"http://localhost/"
    ]

    while deployment_status['checking']:
        deployment_status['last_check'] = time.time()

        for url in urls_to_try:
            try:
                print(f"Checking if CA Manager is ready at: {url}")
                response = requests.get(url, timeout=5, verify=False)  # Skip SSL verification for dev

                if response.status_code == 200:
                    # Check if it's actually the CA Manager login page
                    if 'login' in response.text.lower() or 'ca manager' in response.text.lower() or 'username' in response.text.lower():
                        print(f"✅ CA Manager is ready at: {url}")
                        deployment_status['ready'] = True
                        deployment_status['ready_url'] = url
                        return

            except requests.exceptions.RequestException as e:
                print(f"Still waiting... {url} not ready: {e}")
                continue

        # Wait 5 seconds before next check
        time.sleep(5)

# Start background checker
checker_thread = threading.Thread(target=check_main_application, daemon=True)
checker_thread.start()

@app.route('/')
def progress_page():
    """Main progress page"""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CA Manager - Deployment in Progress</title>
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
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
            }

            .container {
                text-align: center;
                background: rgba(255, 255, 255, 0.1);
                padding: 60px 40px;
                border-radius: 20px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                max-width: 500px;
                width: 90%;
            }

            .logo {
                font-size: 3em;
                margin-bottom: 20px;
                filter: drop-shadow(0 4px 8px rgba(0, 0, 0, 0.3));
            }

            .title {
                font-size: 2.5em;
                font-weight: 300;
                margin-bottom: 10px;
                color: white;
            }

            .subtitle {
                font-size: 1.2em;
                margin-bottom: 40px;
                opacity: 0.9;
            }

            .spinner {
                width: 80px;
                height: 80px;
                border: 8px solid rgba(255, 255, 255, 0.3);
                border-top: 8px solid white;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 30px auto;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            .status {
                font-size: 1.1em;
                margin-bottom: 20px;
                opacity: 0.9;
            }

            .progress-text {
                font-size: 1.4em;
                font-weight: 600;
                margin-bottom: 15px;
                color: #fff;
            }

            .time-elapsed {
                font-size: 0.9em;
                opacity: 0.7;
                margin-top: 20px;
            }

            .dots {
                display: inline-block;
                animation: dots 2s infinite;
            }

            @keyframes dots {
                0% { content: ''; }
                25% { content: '.'; }
                50% { content: '..'; }
                75% { content: '...'; }
                100% { content: ''; }
            }

            .ready-message {
                display: none;
                background: rgba(40, 167, 69, 0.9);
                padding: 20px;
                border-radius: 10px;
                margin-top: 20px;
            }

            .ready-message.show {
                display: block;
            }

            .redirect-counter {
                font-size: 1.2em;
                font-weight: bold;
                margin-top: 10px;
            }

            @media (max-width: 600px) {
                .container {
                    padding: 40px 30px;
                }

                .title {
                    font-size: 2em;
                }

                .subtitle {
                    font-size: 1em;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">🚀</div>
            <h1 class="title">CA Manager</h1>
            <p class="subtitle">Setting up your PKI infrastructure</p>

            <div id="loading-section">
                <div class="spinner"></div>
                <div class="progress-text">Deployment in Progress<span class="dots"></span></div>
                <div class="status" id="status">Initializing services...</div>
                <div class="time-elapsed" id="time-elapsed">Time elapsed: 0 seconds</div>
            </div>

            <div class="ready-message" id="ready-message">
                <h3>🎉 CA Manager is Ready!</h3>
                <p>Redirecting you to the application...</p>
                <div class="redirect-counter" id="redirect-counter">3</div>
            </div>
        </div>

        <script>
            let startTime = Date.now();
            let redirectCounter = 3;

            function updateTimeElapsed() {
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                const minutes = Math.floor(elapsed / 60);
                const seconds = elapsed % 60;
                const timeText = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
                document.getElementById('time-elapsed').textContent = `Time elapsed: ${timeText}`;
            }

            function checkStatus() {
                fetch('/api/status')
                    .then(response => response.json())
                    .then(data => {
                        if (data.ready) {
                            // Hide loading section
                            document.getElementById('loading-section').style.display = 'none';

                            // Show ready message
                            document.getElementById('ready-message').classList.add('show');

                            // Start countdown
                            const countdown = setInterval(() => {
                                document.getElementById('redirect-counter').textContent = redirectCounter;
                                redirectCounter--;

                                if (redirectCounter < 0) {
                                    clearInterval(countdown);
                                    window.location.href = data.ready_url || 'https://localhost/';
                                }
                            }, 1000);

                        } else {
                            // Update status
                            document.getElementById('status').textContent = data.checking ?
                                'Checking if services are ready...' :
                                'Starting services...';
                        }
                    })
                    .catch(error => {
                        console.error('Status check failed:', error);
                        document.getElementById('status').textContent = 'Checking deployment status...';
                    });
            }

            // Update time every second
            setInterval(updateTimeElapsed, 1000);

            // Check status every 3 seconds
            setInterval(checkStatus, 3000);

            // Initial check
            checkStatus();
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template)

@app.route('/api/status')
def api_status():
    """API endpoint for deployment status"""
    return jsonify({
        'ready': deployment_status['ready'],
        'checking': deployment_status['checking'],
        'domain': deployment_status['domain'],
        'ready_url': deployment_status.get('ready_url'),
        'elapsed': int(time.time() - deployment_status['start_time']),
        'last_check': deployment_status['last_check']
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    print("🚀 Starting Simple Deployment Progress Monitor")
    print("📊 Access at: http://localhost:8000")
    print("🔄 Polling main application every 5 seconds")
    print("")

    app.run(host='0.0.0.0', port=8000, debug=False)