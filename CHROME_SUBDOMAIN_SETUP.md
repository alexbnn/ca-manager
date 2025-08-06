# Chrome Simulator Subdomain Configuration

## Overview

The Chrome certificate testing environment now uses a **subdomain approach** instead of path-based routing. This eliminates path handling issues and provides a cleaner architecture.

## Configuration

### Environment Variables

```bash
# Base domain for your deployment
DOMAIN=yourdomain.com

# Chrome simulator subdomain (results in chrome.yourdomain.com)
CHROME_SUBDOMAIN=chrome
```

### Resulting URLs

With the default configuration:
- **Main CA Manager**: `https://ca.yourdomain.com`
- **SCEP Server**: `https://ca.yourdomain.com/scep`
- **OCSP Responder**: `https://ca.yourdomain.com/ocsp`
- **Chrome Simulator**: `https://chrome.yourdomain.com` ✨ **NEW**

## Benefits of Subdomain Approach

1. **No Path Conflicts**: Each service gets its own subdomain
2. **Cleaner URLs**: `chrome.domain.com` vs `ca.domain.com/chromiumos`
3. **Better SSL/TLS**: Each subdomain can have its own certificate
4. **Simplified Routing**: No complex path prefix handling in Traefik
5. **Service Isolation**: Each service is completely independent

## DNS Setup

For production deployment, you'll need DNS records:

```dns
ca.yourdomain.com      A    YOUR_SERVER_IP
chrome.yourdomain.com  A    YOUR_SERVER_IP
```

Or use wildcard DNS:
```dns
*.yourdomain.com       A    YOUR_SERVER_IP
```

## SSL Certificates

Traefik will automatically obtain certificates for:
- `ca.yourdomain.com`
- `chrome.yourdomain.com`

## Local Testing

For local testing, add to your `/etc/hosts`:
```
127.0.0.1   ca.yourdomain.com
127.0.0.1   chrome.yourdomain.com
```

## Access Methods

The Chrome certificate testing environment supports three access methods:

1. **Direct VNC**: `localhost:5901` (password: `chromeosflex`)
2. **Web Interface**: `http://localhost:8082`
3. **Traefik Routing**: `https://chrome.yourdomain.com` ✨

## Customizable Subdomain

You can change the Chrome subdomain by modifying the environment variable:

```bash
# Use 'test' instead of 'chrome'
CHROME_SUBDOMAIN=test
# Results in: https://test.yourdomain.com
```

This makes the deployment flexible for different environments:
- **Production**: `chrome.company.com`
- **Staging**: `chrome-staging.company.com`
- **Development**: `chrome-dev.company.com`