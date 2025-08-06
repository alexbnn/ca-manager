# Security Policy

## 🛡️ Supported Versions

We actively maintain security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 4.0.x   | ✅ Active support |
| 3.x.x   | ⚠️ Security fixes only |
| < 3.0   | ❌ No longer supported |

## 🚨 Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

We take security seriously and appreciate responsible disclosure of security vulnerabilities. To report a security issue:

### Preferred Method
- **Email**: Send details to `security@camanager.dev`
- **Response Time**: We aim to acknowledge within 48 hours
- **Initial Assessment**: Within 7 days of report

### What to Include
Please include as much information as possible:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact and affected components
- **Reproduction**: Step-by-step reproduction instructions
- **Environment**: OS, Docker version, deployment method
- **Proof of Concept**: Code, screenshots, or logs (if safe to share)

### What to Expect

1. **Acknowledgment**: Confirmation of receipt within 48 hours
2. **Initial Assessment**: Severity and impact evaluation
3. **Investigation**: Detailed analysis and reproduction
4. **Resolution**: Fix development and testing
5. **Disclosure**: Coordinated public disclosure

## 🔒 Security Features

### Authentication & Authorization
- **Multi-user Support**: Role-based access control (RBAC)
- **Session Management**: Secure session handling with Redis
- **Password Security**: Strong password requirements
- **Audit Logging**: Comprehensive security event logging

### PKI Security
- **Key Protection**: Private keys stored securely in Docker volumes
- **Certificate Validation**: Proper certificate chain validation
- **Revocation Handling**: CRL and OCSP certificate status checking
- **Secure Enrollment**: SCEP with challenge passwords

### Network Security
- **TLS Everywhere**: HTTPS/TLS for all web traffic
- **Certificate Management**: Let's Encrypt or self-signed certificates
- **Reverse Proxy**: Traefik with security headers
- **Port Isolation**: Service-specific port exposure

### Container Security
- **Non-root Users**: Containers run as non-privileged users
- **Minimal Images**: Alpine-based images for reduced attack surface
- **Resource Limits**: CPU and memory constraints
- **Health Checks**: Service health monitoring

### Input Validation
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: Input sanitization and CSP headers
- **CSRF Protection**: Cross-site request forgery tokens
- **File Upload Security**: Restricted file types and validation

## 🛡️ Security Best Practices

### Deployment Security

#### Environment Configuration
```bash
# Use strong, unique passwords
POSTGRES_PASSWORD=use-strong-random-password
SECRET_KEY=generate-cryptographically-secure-key
ADMIN_PASSWORD_HASH=use-bcrypt-hashed-password

# Enable security features
AUTHENTICATION_ENABLED=true
MULTI_USER_MODE=true
LOG_LEVEL=INFO  # Avoid DEBUG in production
```

#### Network Security
```yaml
# docker-compose.yml security settings
services:
  web-interface:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=50m
```

#### Firewall Configuration
```bash
# Only expose necessary ports
ufw allow 80/tcp    # HTTP (redirects to HTTPS)
ufw allow 443/tcp   # HTTPS
ufw deny 8081/tcp   # Block external Traefik dashboard access
```

### Operational Security

#### Regular Updates
- **Container Images**: Regularly update base images
- **Dependencies**: Keep Python packages updated
- **Host System**: Apply security patches promptly

#### Monitoring & Alerting
- **Log Analysis**: Monitor for suspicious activities
- **Certificate Expiry**: Set up alerts for expiring certificates
- **Failed Logins**: Monitor authentication failures
- **Resource Usage**: Track unusual resource consumption

#### Backup Security
```bash
# Secure backup practices
# Encrypt backups
gpg --cipher-algo AES256 --compress-algo 2 --symmetric pki-backup.tar.gz

# Store backups securely
aws s3 cp pki-backup.tar.gz.gpg s3://secure-backup-bucket/
```

## 🔍 Security Scanning

### Automated Scanning
We use multiple security scanning tools:

- **Container Scanning**: Trivy for vulnerability detection
- **Dependency Scanning**: GitHub Dependabot for dependency vulnerabilities
- **Code Analysis**: Static analysis for security issues
- **SAST**: Static Application Security Testing

### Manual Security Reviews
Regular security reviews include:

- **Code Reviews**: Security-focused code reviews
- **Architecture Reviews**: Security architecture assessment
- **Penetration Testing**: Periodic security testing
- **Configuration Audits**: Security configuration validation

## 🚨 Incident Response

### Security Incident Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| **Critical** | Remote code execution, data breach | < 4 hours |
| **High** | Privilege escalation, authentication bypass | < 24 hours |
| **Medium** | Information disclosure, DoS | < 72 hours |
| **Low** | Minor information leak, configuration issue | < 1 week |

### Response Process

1. **Detection**: Identify and validate security incident
2. **Containment**: Isolate affected systems
3. **Investigation**: Determine scope and impact
4. **Mitigation**: Develop and deploy fixes
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Document and improve processes

## 📋 Security Checklist

### Pre-deployment Security Checklist

- [ ] **Strong Passwords**: All default passwords changed
- [ ] **TLS Configuration**: HTTPS enabled with strong ciphers
- [ ] **Access Control**: Proper user roles and permissions
- [ ] **Network Segmentation**: Services isolated appropriately
- [ ] **Logging Enabled**: Security events logged
- [ ] **Backups Configured**: Secure backup procedures in place
- [ ] **Updates Applied**: All components up to date
- [ ] **Firewall Rules**: Only necessary ports exposed
- [ ] **Monitoring Setup**: Security monitoring configured

### Runtime Security Monitoring

- [ ] **Failed Login Attempts**: Monitor authentication failures
- [ ] **Certificate Status**: Track certificate validity and revocation
- [ ] **Resource Usage**: Monitor for unusual resource consumption
- [ ] **Network Traffic**: Analyze network patterns for anomalies
- [ ] **File Integrity**: Monitor critical file changes
- [ ] **Service Health**: Track service availability and performance

## 📚 Security Resources

### PKI Security Standards
- **RFC 3647**: Certificate Policy and Certification Practices Framework
- **RFC 5280**: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- **RFC 8954**: Online Certificate Status Protocol (OCSP) Extensions

### Security Guidelines
- **NIST SP 800-57**: Cryptographic Key Management
- **OWASP Top 10**: Web Application Security Risks
- **CIS Controls**: Critical Security Controls

### Compliance Frameworks
- **SOC 2**: Service Organization Control 2
- **ISO 27001**: Information Security Management
- **FIPS 140-2**: Cryptographic Module Validation

## 📞 Contact Information

- **Security Team**: security@camanager.dev
- **General Support**: support@camanager.dev
- **GitHub Issues**: For non-security bugs and feature requests
- **Community Forum**: For general discussions and questions

---

**Security is everyone's responsibility. Thank you for helping keep CA Manager secure! 🛡️**