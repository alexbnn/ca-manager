# 🛡️ CA Manager v4.0.0 Setup Requirements

## 📋 System Prerequisites

### 🐳 Docker Environment
- **Docker Engine** 20.10+ *(Required)*
- **Docker Compose** v2.0+ *(Required)*
- **Available Ports:**
  - `8000` - Setup Wizard *(Initial setup only)*
  - `80` - HTTP Traffic *(Production)*
  - `443` - HTTPS Traffic *(Production)*
  - `8081` - Traefik Dashboard *(Management)*
  - `8090` - SCEP Server *(Certificate enrollment)*
  - `5432` - PostgreSQL *(Internal database)*
  - `6379` - Redis *(Session storage)*

### 💻 Hardware Requirements
- **RAM:** 2GB minimum, 4GB recommended
- **CPU:** 2 cores minimum
- **Storage:** 5GB available disk space
- **Network:** Internet access for Let's Encrypt (optional)

---

## 🚀 Quick Start Process

### Step 1: Extract & Navigate
```bash
tar -xzf ca-manager-v4.0.0.tar.gz
cd ca-manager-v4.0.0/
```

### Step 2: Run Setup Script
```bash
./deploy.sh
```

### Step 3: Complete Web Wizard
🌐 **Open:** `http://localhost:8000`

---

## 🧙‍♂️ Setup Wizard Configuration

### 📄 Step 1: Domain Configuration
- **Domain Name** *(example.com or localhost)*
- **SSL Certificate Method:**
  - 🔄 Let's Encrypt (automatic, requires real domain)
  - 🔒 Self-signed (testing/internal use)

### 🏢 Step 2: Organization Details
- **Country Code** *(US, CA, UK, etc.)*
- **State/Province** *(California, Ontario, etc.)*
- **City** *(San Francisco, Toronto, etc.)*
- **Organization Name** *(Your Company Name)*
- **Department** *(IT Department)*
- **Email Address** *(admin@yourcompany.com)*

### 🔐 Step 3: Security Settings
- **Admin Username** *(default: admin)*
- **Admin Password** *(secure password)*
- **Secret Key** *(auto-generated)*
- **Certificate Validity:**
  - CA Certificate: 10 years (3650 days)
  - Client/Server Certificates: 1 year (365 days)

### ⚙️ Step 4: Advanced Settings
- **Key Size:** 2048-bit (recommended) or 4096-bit
- **Digest Algorithm:** SHA-256 (recommended)
- **Multi-user Mode:** Enabled/Disabled
- **Rate Limiting:** Enabled/Disabled

---

## 📦 What Gets Created

### 🔧 Configuration Files
- `.env` - Environment variables
- `traefik.yml` - Reverse proxy configuration
- `traefik-dynamic.yml` - Dynamic routing rules
- `setup_complete.flag` - Setup completion marker
- `deploy_ready.flag` - Deployment signal

### 🐳 Docker Containers
- **web-interface** - Main Flask application
- **easyrsa-container** - PKI certificate operations
- **postgres** - User database & audit logs
- **redis** - Session storage & caching
- **scep-server** - Device certificate enrollment
- **traefik** - Reverse proxy & SSL termination

### 💾 Docker Volumes
- `easyrsa-pki` - PKI certificates & keys
- `postgres-data` - User database
- `redis-data` - Session data
- `traefik-logs` - Access logs
- `letsencrypt-data` - SSL certificates
- `pki-logs`, `easyrsa-logs`, `scep-logs` - Application logs

---

## 🌐 Post-Setup Access

### 📊 Web Interfaces
- **Main Application:** `https://your-domain/` or `https://localhost/`
- **Traefik Dashboard:** `http://localhost:8081/`
- **Login:** admin / *your-chosen-password*

### 🔌 API Endpoints
- **PKI Operations:** `https://your-domain/api/*`
- **SCEP Enrollment:** `https://your-domain/scep/pkiclient`
- **Health Check:** `https://your-domain/health`

---

## ✅ Verification Checklist

### 🔍 Setup Complete When:
- [ ] All containers running (`docker-compose ps`)
- [ ] Web interface accessible at HTTPS URL
- [ ] Traefik dashboard shows all services
- [ ] SCEP endpoint responds to health checks
- [ ] Admin login works with chosen credentials
- [ ] PKI initialization wizard available

### 🛠️ Management Commands
```bash
# View all containers
docker-compose ps

# View logs
docker-compose logs -f web-interface

# Stop/Start services
docker-compose down
docker-compose up -d

# Update containers
docker-compose pull && docker-compose up -d
```

---

## 🔒 Security Features

### 🛡️ Built-in Security
- **HTTPS/TLS encryption** (Let's Encrypt or self-signed)
- **Role-based access control** (Admin, Operator, Viewer)
- **Audit logging** (all operations tracked)
- **Rate limiting** (prevents abuse)
- **Input validation** (SQL injection protection)
- **SCEP protocol** (secure device enrollment)

### 🔐 Certificate Authority Features
- **Full PKI lifecycle management**
- **Client & server certificate creation**
- **Certificate revocation lists (CRL)**
- **Expiry monitoring & alerts**
- **Bulk certificate operations**
- **Certificate validation tools**

---

## 📞 Support & Troubleshooting

### 🚨 Common Issues
- **Port conflicts:** Check `lsof -i :80 -i :443 -i :8000`
- **Docker permissions:** Ensure user in docker group
- **SSL certificate errors:** Verify domain DNS for Let's Encrypt
- **Database connection:** Check PostgreSQL container logs

### 📝 Log Locations
- **Application logs:** `docker-compose logs [service-name]`
- **Audit logs:** Inside web-interface container at `/app/logs/`
- **Traefik logs:** `traefik-logs` volume

---

*🎯 **Result:** A complete PKI Certificate Authority management system with web interface, automated certificate management, and SCEP support for device enrollment.*