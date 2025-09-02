"""
IDP Configuration for CA Manager 6.0.0
Supports Google Workspace and Microsoft Entra ID (Azure AD)
Now uses database configuration instead of environment variables for GUI management
"""

import os
import psycopg2
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class IDPConfig:
    """Identity Provider Configuration - Database-driven"""
    
    _db_connection = None
    _config_cache = {}
    _cache_timestamp = 0
    
    @classmethod
    def set_db_connection(cls, connection):
        """Set database connection for configuration retrieval"""
        cls._db_connection = connection
    
    @classmethod
    def _get_config_from_db(cls, key: str, default: Any = None, config_type: str = 'string') -> Any:
        """Get configuration value from database"""
        if not cls._db_connection:
            logger.warning(f"No database connection available for config key: {key}")
            return default
        
        try:
            with cls._db_connection.cursor() as cursor:
                cursor.execute("""
                    SELECT config_value, config_type 
                    FROM system_config 
                    WHERE config_key = %s
                """, (key,))
                
                result = cursor.fetchone()
                if not result:
                    return default
                
                value, db_type = result
                
                # Type conversion based on config_type
                if db_type == 'boolean':
                    return str(value).lower() in ('true', '1', 'yes', 'on')
                elif db_type == 'integer':
                    try:
                        return int(value)
                    except (ValueError, TypeError):
                        return default
                else:
                    return value or default
                    
        except Exception as e:
            logger.error(f"Error getting config {key} from database: {str(e)}")
            return default
    
    @classmethod
    def _set_config_in_db(cls, key: str, value: Any, updated_by: int = 1) -> bool:
        """Set configuration value in database"""
        if not cls._db_connection:
            logger.warning(f"No database connection available for setting config key: {key}")
            return False
        
        try:
            # Determine config type based on value
            if isinstance(value, bool):
                config_type = 'boolean'
            elif isinstance(value, int):
                config_type = 'integer'
            else:
                config_type = 'string'
            
            with cls._db_connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO system_config (config_key, config_value, config_type, updated_at)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (config_key) 
                    DO UPDATE SET 
                        config_value = EXCLUDED.config_value,
                        config_type = EXCLUDED.config_type,
                        updated_at = EXCLUDED.updated_at
                """, (key, str(value), config_type))
                
                cls._db_connection.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error setting config {key} in database: {str(e)}")
            cls._db_connection.rollback()
            return False
    
    @classmethod
    def get_all_config(cls) -> Dict[str, Any]:
        """Get all IDP configuration as a dictionary"""
        config = {}
        
        # IDP General Settings
        config['idp_enabled'] = cls._get_config_from_db('idp_enabled', False, 'boolean')
        config['redirect_uri_base'] = cls._get_config_from_db('idp_redirect_uri_base', 'https://localhost')
        
        # Google OAuth Settings
        config['google_enabled'] = cls._get_config_from_db('google_oauth_enabled', False, 'boolean')
        config['google_client_id'] = cls._get_config_from_db('google_client_id', '')
        config['google_client_secret'] = cls._get_config_from_db('google_client_secret', '')
        config['google_hosted_domain'] = cls._get_config_from_db('google_hosted_domain', '')
        
        # Microsoft OAuth Settings
        config['microsoft_enabled'] = cls._get_config_from_db('microsoft_oauth_enabled', False, 'boolean')
        config['microsoft_client_id'] = cls._get_config_from_db('microsoft_client_id', '')
        config['microsoft_client_secret'] = cls._get_config_from_db('microsoft_client_secret', '')
        config['microsoft_tenant_id'] = cls._get_config_from_db('microsoft_tenant_id', 'common')
        
        # Certificate Settings
        config['auto_generate_certs'] = cls._get_config_from_db('idp_cert_auto_generate', True, 'boolean')
        config['cert_validity_days'] = cls._get_config_from_db('idp_cert_validity_days', 365, 'integer')
        config['cert_key_size'] = cls._get_config_from_db('idp_cert_key_size', 2048, 'integer')
        config['email_delivery'] = cls._get_config_from_db('idp_cert_email_delivery', True, 'boolean')
        config['email_subject'] = cls._get_config_from_db('idp_cert_email_subject', 'Your PKI Certificate is Ready')
        
        # Self-Service Settings
        config['self_service_enabled'] = cls._get_config_from_db('idp_self_service_enabled', True, 'boolean')
        config['renewal_days'] = cls._get_config_from_db('idp_self_service_renewal_days', 30, 'integer')
        
        # Session Settings
        config['session_lifetime'] = cls._get_config_from_db('idp_session_lifetime', 3600, 'integer')
        config['session_cookie_secure'] = cls._get_config_from_db('idp_session_cookie_secure', True, 'boolean')
        
        return config
    
    @classmethod
    def update_config(cls, config_dict: Dict[str, Any], updated_by: int = 1) -> bool:
        """Update multiple configuration values"""
        success = True
        
        # Map frontend keys to database keys
        key_mapping = {
            'idp_enabled': 'idp_enabled',
            'google_enabled': 'google_oauth_enabled',
            'google_client_id': 'google_client_id',
            'google_client_secret': 'google_client_secret',
            'google_hosted_domain': 'google_hosted_domain',
            'microsoft_enabled': 'microsoft_oauth_enabled',
            'microsoft_client_id': 'microsoft_client_id',
            'microsoft_client_secret': 'microsoft_client_secret',
            'microsoft_tenant_id': 'microsoft_tenant_id',
            'auto_generate_certs': 'idp_cert_auto_generate',
            'cert_validity_days': 'idp_cert_validity_days',
            'email_delivery': 'idp_cert_email_delivery',
            'renewal_days': 'idp_self_service_renewal_days'
        }
        
        for frontend_key, value in config_dict.items():
            db_key = key_mapping.get(frontend_key)
            if db_key:
                if not cls._set_config_in_db(db_key, value, updated_by):
                    success = False
                    logger.error(f"Failed to update config: {frontend_key}")
        
        return success
    
    # Properties for backward compatibility
    @property
    def IDP_ENABLED(cls):
        return cls._get_config_from_db('idp_enabled', False, 'boolean')
    
    @property
    def GOOGLE_OAUTH_ENABLED(cls):
        return cls._get_config_from_db('google_oauth_enabled', False, 'boolean')
    
    @property
    def GOOGLE_CLIENT_ID(cls):
        return cls._get_config_from_db('google_client_id', '')
    
    @property
    def GOOGLE_CLIENT_SECRET(cls):
        return cls._get_config_from_db('google_client_secret', '')
    
    @property
    def GOOGLE_HOSTED_DOMAIN(cls):
        return cls._get_config_from_db('google_hosted_domain', '')
    
    @property
    def MICROSOFT_OAUTH_ENABLED(cls):
        return cls._get_config_from_db('microsoft_oauth_enabled', False, 'boolean')
    
    @property
    def MICROSOFT_CLIENT_ID(cls):
        return cls._get_config_from_db('microsoft_client_id', '')
    
    @property
    def MICROSOFT_CLIENT_SECRET(cls):
        return cls._get_config_from_db('microsoft_client_secret', '')
    
    @property
    def MICROSOFT_TENANT_ID(cls):
        return cls._get_config_from_db('microsoft_tenant_id', 'common')
    
    @property
    def MICROSOFT_AUTHORITY(cls):
        tenant_id = cls.MICROSOFT_TENANT_ID
        return f'https://login.microsoftonline.com/{tenant_id}'
    
    # OAuth2 Redirect URIs (must be registered with IDP)
    @classmethod
    def get_redirect_uri_base(cls):
        return cls._get_config_from_db('idp_redirect_uri_base', 'https://localhost')
    
    @classmethod  
    def get_google_redirect_uri(cls):
        return f'{cls.get_redirect_uri_base()}/auth/google/callback'
    
    @classmethod
    def get_microsoft_redirect_uri(cls):
        return f'{cls.get_redirect_uri_base()}/auth/microsoft/callback'
    
    # Certificate Generation Settings for IDP Users - Database-driven
    @classmethod
    def get_cert_auto_generate(cls):
        return cls._get_config_from_db('idp_cert_auto_generate', True, 'boolean')
    
    @classmethod
    def get_cert_validity_days(cls):
        return cls._get_config_from_db('idp_cert_validity_days', 365, 'integer')
    
    @classmethod
    def get_cert_key_size(cls):
        return cls._get_config_from_db('idp_cert_key_size', 2048, 'integer')
    
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
    
    # Email Delivery Settings - Database-driven
    @classmethod
    def get_cert_email_delivery(cls):
        return cls._get_config_from_db('idp_cert_email_delivery', True, 'boolean')
    
    @classmethod
    def get_cert_email_subject(cls):
        return cls._get_config_from_db('idp_cert_email_subject', 'Your PKI Certificate is Ready')
    
    # Email template configuration (static for now)
    IDP_CERT_EMAIL_TEMPLATE = 'cert_delivery'
    
    # Self-Service Portal Settings - Database-driven
    @classmethod
    def get_self_service_enabled(cls):
        return cls._get_config_from_db('idp_self_service_enabled', True, 'boolean')
    
    @classmethod
    def get_self_service_renewal_days(cls):
        return cls._get_config_from_db('idp_self_service_renewal_days', 30, 'integer')
    
    # Self-service renewal is enabled by default when self-service is enabled
    @classmethod
    def get_self_service_allow_renewal(cls):
        return cls.get_self_service_enabled()
    
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
    
    # Session Configuration - Database-driven
    @classmethod
    def get_session_lifetime(cls):
        return cls._get_config_from_db('idp_session_lifetime', 3600, 'integer')
    
    @classmethod
    def get_session_cookie_secure(cls):
        return cls._get_config_from_db('idp_session_cookie_secure', True, 'boolean')
    
    # Static session settings
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