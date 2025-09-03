-- System Configuration Table
-- CA Manager 6.0.0 - For GUI-based configuration management

-- Create system_config table for storing all system settings
CREATE TABLE IF NOT EXISTS system_config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(255) UNIQUE NOT NULL,
    config_value TEXT,
    config_type VARCHAR(50) DEFAULT 'string', -- string, boolean, integer, json
    description TEXT,
    category VARCHAR(100) DEFAULT 'general', -- general, idp, email, security, etc.
    is_encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255)
);

-- Insert default IDP configuration values
INSERT INTO system_config (config_key, config_value, config_type, description, category) VALUES 
    -- IDP General Settings
    ('idp_enabled', 'false', 'boolean', 'Enable Identity Provider authentication', 'idp'),
    ('idp_redirect_uri_base', 'https://localhost', 'string', 'Base URL for OAuth redirect URIs', 'idp'),
    
    -- Google OAuth Settings
    ('google_oauth_enabled', 'false', 'boolean', 'Enable Google OAuth authentication', 'idp'),
    ('google_client_id', '', 'string', 'Google OAuth Client ID', 'idp'),
    ('google_client_secret', '', 'string', 'Google OAuth Client Secret', 'idp'),
    ('google_hosted_domain', '', 'string', 'Restrict Google login to specific domain', 'idp'),
    
    -- Microsoft OAuth Settings
    ('microsoft_oauth_enabled', 'false', 'boolean', 'Enable Microsoft OAuth authentication', 'idp'),
    ('microsoft_client_id', '', 'string', 'Microsoft Application (Client) ID', 'idp'),
    ('microsoft_client_secret', '', 'string', 'Microsoft Client Secret', 'idp'),
    ('microsoft_tenant_id', 'common', 'string', 'Microsoft Tenant ID', 'idp'),
    
    -- Certificate Management Settings
    ('idp_cert_auto_generate', 'true', 'boolean', 'Auto-generate certificates for IDP users', 'idp'),
    ('idp_cert_validity_days', '365', 'integer', 'Default certificate validity in days', 'idp'),
    ('idp_cert_key_size', '2048', 'integer', 'Certificate key size in bits', 'idp'),
    ('idp_cert_email_delivery', 'true', 'boolean', 'Email certificates to users', 'idp'),
    ('idp_cert_email_subject', 'Your PKI Certificate is Ready', 'string', 'Email subject for certificate delivery', 'idp'),
    
    -- Self-Service Portal Settings
    ('idp_self_service_enabled', 'true', 'boolean', 'Enable self-service certificate portal', 'idp'),
    ('idp_self_service_renewal_days', '30', 'integer', 'Days before expiry to allow renewal', 'idp'),
    
    -- Session Settings
    ('idp_session_lifetime', '3600', 'integer', 'IDP session lifetime in seconds', 'idp'),
    ('idp_session_cookie_secure', 'true', 'boolean', 'Use secure cookies for IDP sessions', 'idp')

ON CONFLICT (config_key) DO NOTHING;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_system_config_category ON system_config(category);
CREATE INDEX IF NOT EXISTS idx_system_config_key ON system_config(config_key);

-- Function to get configuration value with type casting
CREATE OR REPLACE FUNCTION get_config(key_name VARCHAR, default_value TEXT DEFAULT NULL)
RETURNS TEXT AS $$
DECLARE
    result TEXT;
BEGIN
    SELECT config_value INTO result
    FROM system_config 
    WHERE config_key = key_name;
    
    IF result IS NULL THEN
        RETURN default_value;
    END IF;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Function to get boolean configuration value
CREATE OR REPLACE FUNCTION get_config_bool(key_name VARCHAR, default_value BOOLEAN DEFAULT FALSE)
RETURNS BOOLEAN AS $$
DECLARE
    result TEXT;
BEGIN
    SELECT config_value INTO result
    FROM system_config 
    WHERE config_key = key_name;
    
    IF result IS NULL THEN
        RETURN default_value;
    END IF;
    
    RETURN result::BOOLEAN;
END;
$$ LANGUAGE plpgsql;

-- Function to get integer configuration value
CREATE OR REPLACE FUNCTION get_config_int(key_name VARCHAR, default_value INTEGER DEFAULT 0)
RETURNS INTEGER AS $$
DECLARE
    result TEXT;
BEGIN
    SELECT config_value INTO result
    FROM system_config 
    WHERE config_key = key_name;
    
    IF result IS NULL THEN
        RETURN default_value;
    END IF;
    
    RETURN result::INTEGER;
END;
$$ LANGUAGE plpgsql;

-- Function to set configuration value
CREATE OR REPLACE FUNCTION set_config(key_name VARCHAR, value TEXT, updated_by_user VARCHAR DEFAULT 'system')
RETURNS VOID AS $$
BEGIN
    INSERT INTO system_config (config_key, config_value, updated_by, updated_at)
    VALUES (key_name, value, updated_by_user, CURRENT_TIMESTAMP)
    ON CONFLICT (config_key) 
    DO UPDATE SET 
        config_value = EXCLUDED.config_value,
        updated_by = EXCLUDED.updated_by,
        updated_at = EXCLUDED.updated_at;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_system_config_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER system_config_update_timestamp
    BEFORE UPDATE ON system_config
    FOR EACH ROW
    EXECUTE FUNCTION update_system_config_timestamp();

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON system_config TO ca_manager_user;
GRANT USAGE, SELECT ON SEQUENCE system_config_id_seq TO ca_manager_user;