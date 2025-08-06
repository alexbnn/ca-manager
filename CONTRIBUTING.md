# Contributing to CA Manager

Thank you for your interest in contributing to CA Manager! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Python 3.9+ (for development)
- Git

### Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/yourusername/ca-manager.git
   cd ca-manager
   ```

2. **Set up development environment:**
   ```bash
   # Create Python virtual environment
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   
   # Install development dependencies
   pip install -r requirements-dev.txt
   ```

3. **Start development services:**
   ```bash
   # Start setup wizard for configuration
   ./deploy.sh
   
   # Or start main services directly
   docker-compose up -d
   ```

## 📝 Development Guidelines

### Code Style

- **Python**: Follow PEP 8 standards
- **HTML/CSS**: Use semantic HTML5 and modern CSS
- **JavaScript**: Use ES6+ features, avoid jQuery
- **Docker**: Multi-stage builds, minimal base images

### Project Structure

```
ca-manager/
├── app.py                 # Main Flask application
├── templates/             # Jinja2 templates
├── static/               # CSS, JS, images
├── setup-wizard/         # First-time setup wizard
├── ios-scep-simulator/   # SCEP testing simulator
├── ocsp-simulator/       # OCSP testing simulator
├── ocsp-responder/       # OCSP certificate status service
├── terminal-program/     # EasyRSA API wrapper
├── database/            # SQL schema files
├── easyrsa-config/      # PKI configuration
└── docker-compose.yml   # Service orchestration
```

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Build process or auxiliary tool changes

**Examples:**
```bash
feat(scep): add device enrollment validation
fix(ocsp): handle certificate status edge cases
docs(readme): update installation instructions
```

## 🧪 Testing

### Running Tests

```bash
# Lint code
flake8 . --max-line-length=127

# Test Docker builds
docker-compose config
docker build -t ca-manager:test .

# Integration tests
python -m pytest tests/
```

### Test Coverage Areas

- **Setup Wizard**: Configuration generation and validation
- **SCEP Server**: Device enrollment workflows
- **OCSP Responder**: Certificate status checking
- **Web Interface**: User management and certificate operations
- **Security**: Authentication, authorization, input validation

### Manual Testing

1. **Setup Wizard Flow:**
   - Complete 4-step configuration
   - Test both Let's Encrypt and self-signed SSL
   - Verify generated configuration files

2. **Certificate Operations:**
   - Create client/server certificates
   - Test certificate revocation
   - Verify expiry monitoring

3. **SCEP Enrollment:**
   - Use iOS simulator for device testing
   - Test various device profiles
   - Verify certificate delivery

4. **OCSP Validation:**
   - Test valid certificate status
   - Test revoked certificate detection
   - Verify response caching

## 📋 Issue Guidelines

### Bug Reports

Include the following information:

- **Environment**: OS, Docker version, browser
- **Steps to reproduce**: Clear, numbered steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Logs**: Relevant application logs
- **Screenshots**: If applicable

### Feature Requests

Provide:

- **Use case**: Why is this feature needed?
- **Proposed solution**: How should it work?
- **Alternatives**: Other solutions considered
- **Additional context**: Screenshots, examples

## 🔒 Security

### Security Issues

**Do not create public issues for security vulnerabilities.**

Instead:
1. Email security issues to: [security@yourproject.com]
2. Include detailed description and steps to reproduce
3. Allow time for investigation before public disclosure

### Security Guidelines

- **Secrets**: Never commit secrets, keys, or passwords
- **Input validation**: Always validate and sanitize user input
- **Authentication**: Use secure session management
- **Encryption**: Use strong encryption for sensitive data
- **Dependencies**: Keep dependencies updated

## 🏗️ Architecture Guidelines

### Service Design

- **Microservices**: Each component should be independently deployable
- **API Design**: RESTful APIs with proper error handling
- **Database**: Normalize data, use appropriate indexes
- **Caching**: Implement caching for performance-critical operations

### Docker Best Practices

- **Multi-stage builds**: Minimize final image size
- **Non-root users**: Run containers with non-privileged users
- **Health checks**: Include health check endpoints
- **Resource limits**: Set appropriate CPU/memory limits

### Security Architecture

- **Principle of least privilege**: Minimal required permissions
- **Defense in depth**: Multiple security layers
- **Audit logging**: Log security-relevant events
- **Certificate management**: Proper key storage and rotation

## 📦 Release Process

### Version Numbering

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Release Checklist

1. **Update version numbers**:
   - `app.py`: `APP_VERSION`
   - `manifest.json`: `version`
   - `README.md`: Version references

2. **Update documentation**:
   - README.md with new features
   - CHANGELOG.md with release notes
   - API documentation if changed

3. **Test thoroughly**:
   - All automated tests pass
   - Manual testing of key workflows
   - Security scan results reviewed

4. **Create release**:
   - Tag release: `git tag -a v4.1.0 -m "Release v4.1.0"`
   - Push tags: `git push origin --tags`
   - GitHub Actions will create release artifacts

## 🤝 Community

### Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- **Be respectful**: Treat everyone with respect
- **Be inclusive**: Welcome newcomers and diverse perspectives  
- **Be constructive**: Provide helpful feedback
- **Be patient**: Remember everyone was a beginner once

### Getting Help

- **Documentation**: Check README and inline documentation
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions
- **Community**: Join our community chat/forum

### Recognition

Contributors will be recognized in:

- **CONTRIBUTORS.md**: All contributors listed
- **Release notes**: Major contributions highlighted
- **Documentation**: Contributors credited where appropriate

## 📋 Development Roadmap

### Current Priorities

1. **API Documentation**: OpenAPI/Swagger documentation
2. **Certificate Templates**: Predefined certificate profiles
3. **LDAP Integration**: Enterprise authentication support
4. **Kubernetes Deployment**: Helm charts and operators

### Future Enhancements

- Hardware Security Module (HSM) support
- Certificate Transparency integration
- Advanced monitoring and alerting
- REST API for automation
- Multi-tenant architecture

---

**Thank you for contributing to CA Manager! 🛡️**

Your contributions help make secure certificate management accessible to everyone.