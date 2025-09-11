-- IDP User Certificates Schema
-- Store and manage certificates issued to IDP-authenticated users

-- Table to track certificates issued to IDP users
CREATE TABLE IF NOT EXISTS idp_certificates (
    id SERIAL PRIMARY KEY,
    
    -- IDP User identification
    idp_user_id VARCHAR(255) NOT NULL,
    idp_email VARCHAR(255) NOT NULL,
    idp_provider VARCHAR(50) NOT NULL, -- 'google' or 'microsoft'
    
    -- Certificate details
    certificate_serial VARCHAR(100) NOT NULL UNIQUE,
    certificate_cn VARCHAR(255) NOT NULL,
    certificate_subject TEXT,
    certificate_issuer TEXT,
    
    -- Certificate content
    certificate_pem TEXT NOT NULL,
    private_key_encrypted TEXT, -- Encrypted with user's session key
    
    -- Certificate status
    status VARCHAR(50) DEFAULT 'active', -- 'active', 'revoked', 'expired'
    revocation_reason VARCHAR(255),
    revoked_at TIMESTAMP,
    
    -- Validity period
    issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    
    -- Device/Purpose tracking
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    purpose VARCHAR(100), -- 'wifi', 'vpn', 'email', 'general'
    
    -- Metadata
    request_ip VARCHAR(50),
    user_agent TEXT,
    notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for lookups
CREATE INDEX idx_idp_cert_user ON idp_certificates (idp_user_id, idp_provider);
CREATE INDEX idx_idp_cert_email ON idp_certificates (idp_email);
CREATE INDEX idx_idp_cert_serial ON idp_certificates (certificate_serial);
CREATE INDEX idx_idp_cert_status ON idp_certificates (status);
CREATE INDEX idx_idp_cert_expires ON idp_certificates (expires_at);

-- Trigger to update the updated_at timestamp
CREATE TRIGGER update_idp_certificates_updated_at 
    BEFORE UPDATE ON idp_certificates
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert sample data for testing (optional)
-- This will be populated when IDP users request certificates