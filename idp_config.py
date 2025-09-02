"""
IDP Configuration for CA Manager 6.0.0
Supports Google Workspace and Microsoft Entra ID (Azure AD)
"""

import os
from typing import Dict, Any

class IDPConfig:
    """Identity Provider Configuration"""
    
    # IDP Feature Enable/Disable
    IDP_ENABLED = os.getenv('IDP_ENABLED', 'false').lower() == 'true'
    
    # Google OAuth2 Configuration
    GOOGLE_OAUTH_ENABLED = os.getenv('GOOGLE_OAUTH_ENABLED', 'false').lower() == 'true'
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '')
    GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    
    # Google Workspace domain restriction (optional)
    GOOGLE_HOSTED_DOMAIN = os.getenv('GOOGLE_HOSTED_DOMAIN', '')  # e.g., 'company.com'
    
    # Microsoft Entra ID (Azure AD) Configuration
    MICROSOFT_OAUTH_ENABLED = os.getenv('MICROSOFT_OAUTH_ENABLED', 'false').lower() == 'true'
    MICROSOFT_CLIENT_ID = os.getenv('MICROSOFT_CLIENT_ID', '')
    MICROSOFT_CLIENT_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET', '')
    MICROSOFT_TENANT_ID = os.getenv('MICROSOFT_TENANT_ID', '')  # Can be 'common', 'organizations', or specific tenant ID
    MICROSOFT_AUTHORITY = f'https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}'
    
    # OAuth2 Redirect URIs (must be registered with IDP)
    OAUTH_REDIRECT_URI_BASE = os.getenv('OAUTH_REDIRECT_URI_BASE', 'https://localhost')
    GOOGLE_REDIRECT_URI = f'{OAUTH_REDIRECT_URI_BASE}/auth/google/callback'
    MICROSOFT_REDIRECT_URI = f'{OAUTH_REDIRECT_URI_BASE}/auth/microsoft/callback'
    
    # Certificate Generation Settings for IDP Users
    IDP_CERT_AUTO_GENERATE = os.getenv('IDP_CERT_AUTO_GENERATE', 'true').lower() == 'true'
    IDP_CERT_VALIDITY_DAYS = int(os.getenv('IDP_CERT_VALIDITY_DAYS', '365'))
    IDP_CERT_KEY_SIZE = int(os.getenv('IDP_CERT_KEY_SIZE', '2048'))
    
    # Certificate Template Mapping based on IDP groups/roles
    IDP_CERT_TEMPLATE_MAPPING = {
        'default': {
            'cert_type': 'client',
            'validity_days': 365,
            'key_size': 2048,
            'key_usage': ['digitalSignature', 'keyEncipherment'],
            'extended_key_usage': ['clientAuth', 'emailProtection']
        },
        'admin': {
            'cert_type': 'client',
            'validity_days': 730,
            'key_size': 4096,
            'key_usage': ['digitalSignature', 'keyEncipherment', 'nonRepudiation'],
            'extended_key_usage': ['clientAuth', 'emailProtection', 'codeSigning']
        },
        'server': {
            'cert_type': 'server',
            'validity_days': 365,
            'key_size': 2048,
            'key_usage': ['digitalSignature', 'keyEncipherment'],
            'extended_key_usage': ['serverAuth']
        }
    }
    
    # Email Delivery Settings
    IDP_CERT_EMAIL_DELIVERY = os.getenv('IDP_CERT_EMAIL_DELIVERY', 'true').lower() == 'true'
    IDP_CERT_EMAIL_SUBJECT = os.getenv('IDP_CERT_EMAIL_SUBJECT', 'Your PKI Certificate is Ready')
    IDP_CERT_EMAIL_TEMPLATE = os.getenv('IDP_CERT_EMAIL_TEMPLATE', 'cert_delivery')
    
    # Self-Service Portal Settings
    IDP_SELF_SERVICE_ENABLED = os.getenv('IDP_SELF_SERVICE_ENABLED', 'true').lower() == 'true'
    IDP_SELF_SERVICE_ALLOW_RENEWAL = os.getenv('IDP_SELF_SERVICE_ALLOW_RENEWAL', 'true').lower() == 'true'
    IDP_SELF_SERVICE_RENEWAL_DAYS = int(os.getenv('IDP_SELF_SERVICE_RENEWAL_DAYS', '30'))  # Days before expiry
    
    # User Attribute Mapping
    IDP_USER_ATTRIBUTE_MAPPING = {
        'google': {
            'email': 'email',
            'name': 'name',
            'given_name': 'given_name',
            'family_name': 'family_name',
            'picture': 'picture',
            'locale': 'locale',
            'hd': 'hosted_domain'  # Google Workspace domain
        },
        'microsoft': {
            'email': 'userPrincipalName',
            'name': 'displayName',
            'given_name': 'givenName',
            'family_name': 'surname',
            'job_title': 'jobTitle',
            'department': 'department',
            'office': 'officeLocation'
        }
    }
    
    # Session Configuration
    IDP_SESSION_LIFETIME = int(os.getenv('IDP_SESSION_LIFETIME', '3600'))  # 1 hour
    IDP_SESSION_COOKIE_SECURE = os.getenv('IDP_SESSION_COOKIE_SECURE', 'true').lower() == 'true'
    IDP_SESSION_COOKIE_HTTPONLY = True
    IDP_SESSION_COOKIE_SAMESITE = 'Lax'
    
    @classmethod
    def get_enabled_providers(cls) -> list:
        """Get list of enabled IDP providers"""
        providers = []
        if cls.GOOGLE_OAUTH_ENABLED:
            providers.append('google')
        if cls.MICROSOFT_OAUTH_ENABLED:
            providers.append('microsoft')
        return providers
    
    @classmethod
    def get_provider_config(cls, provider: str) -> Dict[str, Any]:
        """Get configuration for specific provider"""
        if provider == 'google':
            return {
                'enabled': cls.GOOGLE_OAUTH_ENABLED,
                'client_id': cls.GOOGLE_CLIENT_ID,
                'client_secret': cls.GOOGLE_CLIENT_SECRET,
                'redirect_uri': cls.GOOGLE_REDIRECT_URI,
                'discovery_url': cls.GOOGLE_DISCOVERY_URL,
                'hosted_domain': cls.GOOGLE_HOSTED_DOMAIN,
                'scope': ['openid', 'email', 'profile'],
                'attribute_mapping': cls.IDP_USER_ATTRIBUTE_MAPPING['google']
            }
        elif provider == 'microsoft':
            return {
                'enabled': cls.MICROSOFT_OAUTH_ENABLED,
                'client_id': cls.MICROSOFT_CLIENT_ID,
                'client_secret': cls.MICROSOFT_CLIENT_SECRET,
                'redirect_uri': cls.MICROSOFT_REDIRECT_URI,
                'authority': cls.MICROSOFT_AUTHORITY,
                'tenant_id': cls.MICROSOFT_TENANT_ID,
                'scope': ['User.Read', 'email', 'profile', 'openid'],
                'attribute_mapping': cls.IDP_USER_ATTRIBUTE_MAPPING['microsoft']
            }
        return {}
    
    @classmethod
    def validate_config(cls) -> Dict[str, Any]:
        """Validate IDP configuration"""
        errors = []
        warnings = []
        
        if cls.IDP_ENABLED:
            if not cls.GOOGLE_OAUTH_ENABLED and not cls.MICROSOFT_OAUTH_ENABLED:
                errors.append("IDP is enabled but no providers are configured")
            
            if cls.GOOGLE_OAUTH_ENABLED:
                if not cls.GOOGLE_CLIENT_ID or not cls.GOOGLE_CLIENT_SECRET:
                    errors.append("Google OAuth enabled but client ID/secret not configured")
                if cls.GOOGLE_HOSTED_DOMAIN:
                    warnings.append(f"Google login restricted to domain: {cls.GOOGLE_HOSTED_DOMAIN}")
            
            if cls.MICROSOFT_OAUTH_ENABLED:
                if not cls.MICROSOFT_CLIENT_ID or not cls.MICROSOFT_CLIENT_SECRET:
                    errors.append("Microsoft OAuth enabled but client ID/secret not configured")
                if not cls.MICROSOFT_TENANT_ID:
                    errors.append("Microsoft OAuth enabled but tenant ID not configured")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }