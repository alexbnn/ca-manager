-- IDP Certificate Management Schema
-- CA Manager 6.0.0

-- Table for IDP authenticated users
CREATE TABLE IF NOT EXISTS idp_users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    idp_provider VARCHAR(50) NOT NULL, -- 'google' or 'microsoft'
    idp_user_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    given_name VARCHAR(100),
    family_name VARCHAR(100),
    department VARCHAR(100),
    job_title VARCHAR(100),
    office_location VARCHAR(100),
    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB,
    UNIQUE(idp_provider, idp_user_id)
);

-- Table for IDP user certificates
CREATE TABLE IF NOT EXISTS idp_certificates (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    idp_provider VARCHAR(50),
    idp_user_id VARCHAR(255),
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT, -- Encrypted storage
    serial_number VARCHAR(100) UNIQUE NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    status VARCHAR(50) DEFAULT 'active', -- active, revoked, expired
    revoked_at TIMESTAMP,
    revocation_reason VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    renewed_from_id INTEGER REFERENCES idp_certificates(id),
    metadata JSONB,
    FOREIGN KEY (email) REFERENCES idp_users(email) ON DELETE CASCADE
);

-- Table for certificate download tracking
CREATE TABLE IF NOT EXISTS idp_cert_downloads (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES idp_certificates(id),
    email VARCHAR(255) NOT NULL,
    download_format VARCHAR(20), -- pem, pkcs12, der
    download_ip VARCHAR(45),
    user_agent TEXT,
    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for IDP session tracking
CREATE TABLE IF NOT EXISTS idp_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    idp_provider VARCHAR(50) NOT NULL,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSONB
);

-- Table for certificate templates
CREATE TABLE IF NOT EXISTS cert_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    cert_type VARCHAR(20) DEFAULT 'client', -- client, server
    validity_days INTEGER DEFAULT 365,
    key_size INTEGER DEFAULT 2048,
    key_usage VARCHAR[] DEFAULT ARRAY['digitalSignature', 'keyEncipherment'],
    extended_key_usage VARCHAR[] DEFAULT ARRAY['clientAuth'],
    subject_template JSONB,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default certificate templates
INSERT INTO cert_templates (name, description, cert_type, validity_days, key_size, key_usage, extended_key_usage, is_default)
VALUES 
    ('default', 'Default user certificate template', 'client', 365, 2048, 
     ARRAY['digitalSignature', 'keyEncipherment'], 
     ARRAY['clientAuth', 'emailProtection'], true),
    
    ('admin', 'Administrator certificate template', 'client', 730, 4096,
     ARRAY['digitalSignature', 'keyEncipherment', 'nonRepudiation'],
     ARRAY['clientAuth', 'emailProtection', 'codeSigning'], false),
    
    ('server', 'Server certificate template', 'server', 365, 2048,
     ARRAY['digitalSignature', 'keyEncipherment'],
     ARRAY['serverAuth'], false),
    
    ('vpn', 'VPN client certificate template', 'client', 365, 2048,
     ARRAY['digitalSignature', 'keyAgreement'],
     ARRAY['clientAuth'], false),
    
    ('email', 'Email encryption certificate template', 'client', 365, 2048,
     ARRAY['digitalSignature', 'keyEncipherment', 'dataEncipherment'],
     ARRAY['emailProtection'], false)
ON CONFLICT (name) DO NOTHING;

-- Function to automatically expire certificates
CREATE OR REPLACE FUNCTION expire_certificates()
RETURNS void AS $$
BEGIN
    UPDATE idp_certificates
    SET status = 'expired'
    WHERE status = 'active' 
    AND valid_until < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM idp_sessions
    WHERE expires_at < CURRENT_TIMESTAMP
    AND logout_time IS NULL;
END;
$$ LANGUAGE plpgsql;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_idp_users_email ON idp_users(email);
CREATE INDEX IF NOT EXISTS idx_idp_users_provider ON idp_users(idp_provider);
CREATE INDEX IF NOT EXISTS idx_idp_cert_email ON idp_certificates(email);
CREATE INDEX IF NOT EXISTS idx_idp_cert_status ON idp_certificates(status);
CREATE INDEX IF NOT EXISTS idx_idp_cert_valid_until ON idp_certificates(valid_until);
CREATE INDEX IF NOT EXISTS idx_idp_cert_email_status ON idp_certificates(email, status);
CREATE INDEX IF NOT EXISTS idx_idp_cert_expiry ON idp_certificates(valid_until) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_idp_session_email ON idp_sessions(email);
CREATE INDEX IF NOT EXISTS idx_idp_session_expires ON idp_sessions(expires_at);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON idp_users TO ca_manager_user;
GRANT SELECT, INSERT, UPDATE ON idp_certificates TO ca_manager_user;
GRANT SELECT, INSERT ON idp_cert_downloads TO ca_manager_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON idp_sessions TO ca_manager_user;
GRANT SELECT ON cert_templates TO ca_manager_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ca_manager_user;