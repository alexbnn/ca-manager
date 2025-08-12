# CA Manager v4.0.0 🛡️

**Modern PKI Certificate Authority Management System with SCEP Support**

A complete solution for managing your Public Key Infrastructure with a beautiful web interface, automated certificate management, and SCEP protocol support for device enrollment.

## ✨ Features

- **🌐 Modern Web Interface** - Clean, responsive dashboard for certificate management
- **🔐 PKI Certificate Authority** - Full-featured CA with certificate lifecycle management  
- **📱 SCEP Server** - Simple Certificate Enrollment Protocol for device auto-enrollment
- **🔍 OCSP Responder** - Online Certificate Status Protocol for real-time certificate validation
- **🧪 Testing Simulators** - Built-in iOS SCEP and OCSP testing environments
- **🚀 Traefik Integration** - Modern reverse proxy with automatic SSL/TLS
- **👥 Multi-User Support** - Role-based access control with audit logging
- **📊 Certificate Monitoring** - Expiry dashboard and automated alerts
- **🔒 Security First** - Built-in rate limiting, security headers, and audit trails
- **🐳 Container Ready** - Full Docker deployment with PostgreSQL and Redis

## 🚀 Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Port 8000 available for setup wizard
- Ports 80, 443, 8081, 8090 available for main application

### 1. Clone from GitHub

```bash
# Clone the CA Manager repository
git clone https://github.com/alexbnn/ca-manager.git
cd ca-manager/
```

Alternatively, download as ZIP:
```bash
# Download and extract ZIP file
wget https://github.com/alexbnn/ca-manager/archive/refs/heads/main.zip
unzip main.zip
cd ca-manager-main/
```

### 2. Run Setup Wizard

```bash
# Start the interactive setup wizard
./deploy.sh
```

This will:
- Start a beautiful web-based setup wizard at `http://localhost:8000`
- Guide you through domain, SSL, and organization configuration
- Generate all necessary configuration files

### 3. Complete Setup

1. **Open your browser** to `http://localhost:8000`
2. **Follow the 4-step wizard**:
   - 🌐 **Domain Configuration** - Set your domain name
   - 🔐 **SSL Certificate Setup** - Choose Let's Encrypt or self-signed
   - 🏢 **Organization Details** - Configure your PKI information  
   - 🔒 **Security Settings** - Set administrator credentials

3. **Download the generated configuration**
4. **Stop the setup wizard**: `docker-compose -f docker-compose.setup.yml down`
5. **Start CA Manager**: `./deploy.sh`

### 4. Access Your CA Manager

- **Main Application**: `https://your-domain/` (or `https://localhost/`)
- **Default Login**: `admin` / `admin` (change after first login)
- **Traefik Dashboard**: `http://localhost:8081/`
- **SCEP Endpoint**: `https://your-domain/scep/` (or `https://localhost/scep/`)
- **OCSP Responder**: `https://your-domain/ocsp` (or `https://localhost/ocsp`)
- **iOS SCEP Simulator**: `https://your-domain/simulator/`
- **OCSP Simulator**: `https://your-domain/ocsp-simulator/`

## 📋 Manual Configuration

If you prefer to configure manually instead of using the setup wizard:

### Environment Variables

Create a `.env` file:

```bash
# Domain Configuration
DOMAIN=your-domain.com
SCEP_SERVER_URL=https://ca.your-domain.com/scep

# OCSP Configuration
OCSP_RESPONDER_URL=http://ocsp-responder:8091
CA_MANAGER_BASE_URL=https://your-domain.com

# Security
SECRET_KEY=your-secret-key-here
ADMIN_PASSWORD_HASH=$2b$12$wL/BlaD//hyZhxY9PLQVbOujopj/XzjulFytrIs5ummKEvnM3TnGW  # bcrypt hash of 'admin'

# Database
POSTGRES_PASSWORD=secure-db-password
DATABASE_URL=postgresql://pkiuser:secure-db-password@postgres:5432/pkiauth

# PKI Settings
EASYRSA_REQ_COUNTRY=US
EASYRSA_REQ_PROVINCE=California
EASYRSA_REQ_CITY=San Francisco
EASYRSA_REQ_ORG=Your Organization
EASYRSA_REQ_EMAIL=admin@your-domain.com

# Application
AUTHENTICATION_ENABLED=true
MULTI_USER_MODE=true
LOG_LEVEL=INFO
```

### SSL Certificate Options

#### Option 1: Let's Encrypt (Automatic)

For production with a real domain:

1. Update `traefik.yml` to enable Let's Encrypt:
```yaml
certificatesResolvers:
  letsencrypt:
    acme:
      email: your-email@domain.com
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web
```

2. Update service labels in `docker-compose.yml`:
```yaml
labels:
  - "traefik.http.routers.web.tls.certResolver=letsencrypt"
```

#### Option 2: Self-Signed (Testing/Internal)

The included self-signed certificates work out of the box for testing and internal use.

### Start the Application

```bash
docker-compose up -d
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│                 │    │              │    │                 │
│   Traefik       │────│ Web Interface│────│   EasyRSA       │
│   (Port 80/443) │    │   (Flask)    │    │   Container     │
│                 │    │              │    │                 │
└─────────────────┘    └──────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│                 │    │              │    │                 │
│   SCEP Server   │    │  PostgreSQL  │────│     Redis       │
│   (Port 8090)   │    │  (Database)  │    │   (Sessions)    │
│                 │    │              │    │                 │
└─────────────────┘    └──────────────┘    └─────────────────┘
         │                       │
         │                       │
┌─────────────────┐    ┌──────────────┐    
│                 │    │              │    
│  OCSP Responder │    │  Simulators  │    
│   (Port 8091)   │    │ SCEP & OCSP  │    
│                 │    │              │    
└─────────────────┘    └──────────────┘    
```

## 📚 Usage Guide

### Initial PKI Setup

1. **Login** to the web interface
2. **Initialize PKI**: Go to Dashboard → Initialize PKI
3. **Build CA**: Configure and build your Certificate Authority
4. **Download CA Certificate**: Save the CA cert for distribution

### Certificate Management

- **Create Certificates**: Individual client/server certificates
- **Bulk Operations**: Generate multiple certificates
- **Monitor Expiry**: Dashboard shows expiring certificates
- **Revoke Certificates**: Maintain certificate revocation lists

### SCEP Device Enrollment

Configure devices to use: `https://ca.your-domain/scep/pki-{subdomain}`

**OCSP Configuration:**
- **OCSP URL**: `https://ca.your-domain/ocsp`
- **Certificate Status**: Real-time validation against EasyRSA index
- **Response Caching**: 24-hour validity for performance

- **iOS/macOS**: Use Apple Configurator or MDM
- **Windows**: Use certreq.exe or SCCM
- **Android**: Enterprise mobility management
- **Network Devices**: Router/switch SCEP clients

### 📱 Testing Simulators

**iOS SCEP Client Simulator:**
- **Access**: `https://your-domain/simulator/`
- **Features**: Simulates iPhone, iPad, Mac, and Apple Watch devices
- **Testing**: Complete SCEP enrollment workflow with real device profiles
- **Export**: Download enrollment results as JSON files

**🔍 OCSP Certificate Status Simulator:**
- **Access**: `https://your-domain/ocsp-simulator/`
- **Features**: Test OCSP certificate status checking
- **Real Protocols**: Uses actual ASN.1 OCSP requests/responses
- **Scenarios**: Test valid, revoked, and unknown certificate statuses
- **Debugging**: Detailed response analysis for troubleshooting

## 🔧 Configuration Reference

### Ports

| Port | Service | Description |
|------|---------|-------------|
| 80 | HTTP | Redirects to HTTPS |
| 443 | HTTPS | Main web interface |
| 8081 | Traefik | Dashboard (internal) |
| 8090 | SCEP | Certificate enrollment |
| 8091 | OCSP | Certificate status checking |
| 3000 | iOS Simulator | SCEP testing (internal) |
| 4000 | OCSP Simulator | OCSP testing (internal) |

### Volumes

| Volume | Purpose |
|--------|---------|
| `easyrsa-pki` | PKI certificates and keys |
| `postgres-data` | User database |
| `redis-data` | Session storage |
| `traefik-logs` | Access logs |
| `letsencrypt-data` | SSL certificates |

### Environment Variables

See the complete list in the setup wizard or example `.env` file.

## 🛠️ Maintenance

### Backup

```bash
# Backup PKI data
docker run --rm -v easyrsa-pki:/data -v $(pwd):/backup alpine tar czf /backup/pki-backup.tar.gz /data

# Backup database
docker-compose exec postgres pg_dump -U pkiuser pkiauth > backup.sql
```

### Updates

```bash
# Pull latest images
docker-compose pull

# Restart services
docker-compose up -d
```

### Logs

```bash
# View all logs
docker-compose logs -f

# Specific service logs
docker-compose logs -f web-interface
docker-compose logs -f traefik
```

## 🔍 Troubleshooting

### Common Issues

**Port conflicts:**
```bash
# Check what's using ports
lsof -i :80 -i :443 -i :8081 -i :8090
```

**Certificate errors:**
- For Let's Encrypt: Ensure domain points to your server
- For self-signed: Accept certificate in browser

**Database connection issues (admin/admin not working):**

If you get "password authentication failed" errors after running setup:
```bash
# The database volume may have an old password. Reset it:
docker-compose down
docker volume rm ca-manager-f_postgres-data  # Or: docker volume rm $(docker volume ls -q | grep postgres-data)
docker-compose up -d
```

This happens when the setup wizard generates a new database password but the PostgreSQL volume still has the old password. The database password is set only when the volume is first created.

```bash
# Check PostgreSQL logs for details
docker-compose logs postgres
```

**Traefik routing:**
```bash
# Check Traefik dashboard
curl http://localhost:8081/api/http/routers
```

### Debug Mode

Set `LOG_LEVEL=DEBUG` in your `.env` file for verbose logging.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

- **Issues**: Report bugs and feature requests
- **Documentation**: Full API documentation available in the web interface
- **Community**: Join our community for support and discussions

## 🎯 Roadmap

- [ ] REST API documentation
- [ ] Certificate templates
- [ ] LDAP integration
- [ ] HSM support
- [ ] Kubernetes deployment
- [ ] Advanced monitoring
- [ ] CRL Distribution Points
- [ ] EST (Enrollment over Secure Transport) support
- [ ] Certificate Transparency logging

---

**Made with ❤️ for secure certificate management**