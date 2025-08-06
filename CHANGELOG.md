# Changelog

All notable changes to CA Manager will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2024-12-XX

### 🆕 Added

#### OCSP Support
- **OCSP Responder**: Complete Online Certificate Status Protocol implementation
- **Real-time Certificate Validation**: Certificate status checking against EasyRSA index
- **ASN.1 Protocol Support**: Full RFC 6960 compliant OCSP requests and responses
- **OCSP Simulator**: Web-based testing tool for OCSP certificate status checking
- **OCSP API Endpoints**: `/api/ocsp/info` and `/api/ocsp/health` for monitoring

#### Enhanced User Interface
- **OCSP Section**: New Section 6 in main interface for OCSP management
- **Certificate Status Display**: Real-time certificate status in tracking section
- **OCSP URL Configuration**: Display of external OCSP responder URLs
- **Enhanced Navigation**: Updated section numbering and organization

#### Improved Setup Wizard
- **v4.0.0 Features**: Updated wizard to include OCSP configuration
- **Domain Handling**: Automatic `ca.` subdomain for SCEP and OCSP services
- **Traefik Routing**: Priority-based routing for all services
- **Environment Variables**: OCSP-specific configuration in generated .env files

#### Testing & Development
- **Automated Test Scenarios**: Valid, revoked, and unknown certificate testing
- **Enhanced Simulators**: Both SCEP and OCSP simulators with real protocols
- **Improved Error Handling**: Better error messages and debugging information

### 🔧 Changed

#### Architecture Updates
- **Service Routing**: Updated Traefik routing with priorities and subdomain handling
- **Docker Networking**: Enhanced container communication and DNS resolution
- **Port Configuration**: Added OCSP responder on port 8091
- **Database Schema**: New OCSP-related tables and configurations

#### API Improvements
- **Certificate Status API**: Enhanced certificate status checking
- **SCEP URL Generation**: Dynamic subdomain handling for SCEP endpoints
- **Error Response Format**: Standardized error responses across all APIs

#### Security Enhancements
- **Input Validation**: Improved validation for certificate serial numbers
- **Error Handling**: Better error handling without information disclosure
- **Access Control**: Proper permissions for OCSP operations

### 🐛 Fixed

#### SCEP Server Issues
- **Subdomain Handling**: Fixed SCEP URL generation for bonner.com and other domains
- **DNS Resolution**: Dynamic Traefik IP discovery for simulator containers
- **Certificate Delivery**: Improved SCEP certificate enrollment workflow

#### OCSP Implementation
- **Cryptography Library**: Fixed compatibility with cryptography 45+ API changes
- **Response Building**: Proper OCSP response construction with all required fields
- **Certificate Serial Handling**: Improved serial number parsing and validation

#### General Bug Fixes
- **Container Networking**: Fixed inter-container communication issues
- **URL Generation**: Corrected internal vs external URL handling
- **Database Connections**: Improved database connection stability

### 🔒 Security

#### Enhanced Security Measures
- **Certificate Validation**: Stricter certificate chain validation
- **Input Sanitization**: Enhanced input validation across all endpoints
- **Audit Logging**: Comprehensive logging of OCSP operations
- **Access Controls**: Proper RBAC for certificate status operations

### 📝 Documentation

#### Updated Documentation
- **README**: Comprehensive update with OCSP features and architecture diagrams
- **API Documentation**: New OCSP endpoints and updated examples
- **Setup Guide**: Enhanced setup instructions with OCSP configuration
- **Troubleshooting**: New troubleshooting section for OCSP issues

### 🏗️ Infrastructure

#### Deployment Updates
- **Docker Compose**: Updated with all new services and proper networking
- **Traefik Configuration**: Enhanced routing rules and SSL handling
- **Environment Configuration**: New environment variables for OCSP services
- **Health Checks**: Improved health monitoring for all services

## [3.1.2] - 2024-11-XX

### 🐛 Fixed
- Minor bug fixes and stability improvements
- Updated dependencies for security patches

### 🔧 Changed
- Improved error handling in certificate generation
- Enhanced logging for debugging purposes

## [3.1.1] - 2024-10-XX

### 🐛 Fixed
- Fixed certificate expiry monitoring
- Resolved Traefik routing issues
- Database connection improvements

## [3.1.0] - 2024-09-XX

### 🆕 Added
- Enhanced certificate monitoring dashboard
- Bulk certificate operations
- Improved audit logging

### 🔧 Changed
- Updated Docker base images for security
- Improved web interface responsiveness
- Enhanced SCEP server performance

## [3.0.0] - 2024-08-XX

### 🆕 Added
- Complete web-based setup wizard
- Modern responsive user interface
- Role-based access control (RBAC)
- Multi-user support with authentication
- SCEP server for device enrollment
- Certificate expiry monitoring
- Audit logging system

### 🔧 Changed
- **Breaking Change**: New database schema requiring migration
- Modernized Docker deployment with Traefik
- Redesigned web interface with improved UX
- Enhanced security with session management

### 🗑️ Deprecated
- Legacy command-line only interface
- Direct database access methods

## [2.x.x] - Legacy Versions

Previous versions focused on basic PKI functionality without web interface.
See git history for detailed changes in legacy versions.

---

## Version Support

| Version | Support Level | End of Life |
|---------|---------------|-------------|
| 4.0.x | ✅ Active | TBD |
| 3.x.x | 🔄 Security fixes only | 2025-12-31 |
| 2.x.x | ❌ Unsupported | 2024-12-31 |
| 1.x.x | ❌ Unsupported | 2024-06-30 |

## Migration Guides

### Upgrading from 3.x to 4.0

1. **Backup Current Installation**:
   ```bash
   docker-compose down
   docker run --rm -v easyrsa-pki:/data -v $(pwd):/backup alpine tar czf /backup/pki-backup-v3.tar.gz /data
   ```

2. **Update Configuration**:
   - Add OCSP environment variables to `.env`
   - Update Traefik routing labels
   - Update docker-compose.yml with new services

3. **Database Migration**:
   ```bash
   # Database schema will be automatically updated on startup
   docker-compose up -d postgres
   docker-compose logs postgres  # Check for migration completion
   ```

4. **Start New Services**:
   ```bash
   docker-compose pull  # Get latest images
   docker-compose up -d
   ```

5. **Verify OCSP Functionality**:
   - Check OCSP responder at `https://ca.yourdomain.com/ocsp`
   - Test OCSP simulator at `https://yourdomain.com/ocsp-simulator/`

### Breaking Changes in 4.0

- **SCEP URLs**: Now use `ca.` subdomain (e.g., `https://ca.example.com/scep/`)
- **New Services**: OCSP responder and simulator require additional Docker services
- **Port Changes**: OCSP responder uses port 8091
- **Database Schema**: New OCSP-related tables added

For detailed migration instructions, see the [Migration Guide](docs/migration.md).