-- OCSP and Certificate Revocation Database Schema
-- Tables for managing certificate revocation and OCSP responses

-- Certificates table - tracks all issued certificates
CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    serial_number VARCHAR(255) UNIQUE NOT NULL,  -- Certificate serial number (hex)
    subject_dn TEXT NOT NULL,                    -- Subject Distinguished Name
    issuer_dn TEXT NOT NULL,                     -- Issuer Distinguished Name  
    not_before TIMESTAMP NOT NULL,              -- Certificate validity start
    not_after TIMESTAMP NOT NULL,               -- Certificate validity end
    certificate_pem TEXT NOT NULL,              -- Full certificate in PEM format
    certificate_der BYTEA,                      -- Certificate in DER format (optional)
    key_usage TEXT[],                           -- Key usage extensions
    extended_key_usage TEXT[],                  -- Extended key usage extensions
    sans TEXT[],                                -- Subject Alternative Names
    status VARCHAR(20) DEFAULT 'valid',          -- valid, revoked, expired, suspended
    issued_by VARCHAR(100),                     -- System/user that issued cert
    certificate_type VARCHAR(50) DEFAULT 'client', -- client, server, ca, code_signing, etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Certificate revocation table - tracks revoked certificates
CREATE TABLE IF NOT EXISTS certificate_revocations (
    id SERIAL PRIMARY KEY,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    serial_number VARCHAR(255) NOT NULL,        -- Redundant but useful for quick lookups
    revocation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revocation_reason INTEGER DEFAULT 0,        -- RFC 5280 reason codes (0=unspecified, 1=keyCompromise, etc.)
    revocation_reason_text VARCHAR(50),         -- Human readable reason
    revoked_by VARCHAR(100),                    -- User who revoked the certificate
    revoked_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    invalidation_date TIMESTAMP,               -- When cert became invalid (optional)
    additional_info JSONB,                      -- Additional revocation details
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- OCSP requests log - for monitoring and debugging
CREATE TABLE IF NOT EXISTS ocsp_requests (
    id SERIAL PRIMARY KEY,
    serial_number VARCHAR(255) NOT NULL,
    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    client_ip INET,
    user_agent TEXT,
    request_size INTEGER,
    response_status VARCHAR(20),                -- good, revoked, unknown
    response_time_ms INTEGER,                   -- Response time in milliseconds
    nonce_present BOOLEAN DEFAULT FALSE,
    error_message TEXT                          -- If any error occurred
);

-- OCSP responder configuration
CREATE TABLE IF NOT EXISTS ocsp_config (
    id SERIAL PRIMARY KEY,
    parameter_name VARCHAR(100) UNIQUE NOT NULL,
    parameter_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(100)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_subject ON certificates USING gin(to_tsvector('english', subject_dn));

CREATE INDEX IF NOT EXISTS idx_revocations_serial ON certificate_revocations(serial_number);
CREATE INDEX IF NOT EXISTS idx_revocations_cert_id ON certificate_revocations(certificate_id);
CREATE INDEX IF NOT EXISTS idx_revocations_time ON certificate_revocations(revocation_time);
CREATE INDEX IF NOT EXISTS idx_revocations_reason ON certificate_revocations(revocation_reason);

CREATE INDEX IF NOT EXISTS idx_ocsp_requests_serial ON ocsp_requests(serial_number);
CREATE INDEX IF NOT EXISTS idx_ocsp_requests_time ON ocsp_requests(request_time);
CREATE INDEX IF NOT EXISTS idx_ocsp_requests_status ON ocsp_requests(response_status);

-- Add OCSP-related permissions
INSERT INTO permissions (name, description, resource, action) VALUES 
    ('ocsp_read', 'View OCSP configuration and requests', 'ocsp', 'read'),
    ('ocsp_config', 'Configure OCSP responder settings', 'ocsp', 'update'),
    ('cert_status', 'Check certificate status via OCSP', 'certificates', 'read')
ON CONFLICT (name) DO NOTHING;

-- Assign OCSP permissions to roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'admin' AND p.name IN ('ocsp_read', 'ocsp_config', 'cert_status')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'operator' AND p.name IN ('ocsp_read', 'cert_status')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'viewer' AND p.name IN ('cert_status')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Insert default OCSP configuration
INSERT INTO ocsp_config (parameter_name, parameter_value, description) VALUES 
    ('response_validity_hours', '24', 'OCSP response validity period in hours'),
    ('responder_url', 'https://localhost/ocsp', 'Public OCSP responder URL'),
    ('signing_algorithm', 'SHA256', 'Algorithm used to sign OCSP responses'),
    ('enable_nonce', 'true', 'Whether to support nonce extension in requests'),
    ('max_request_size', '8192', 'Maximum size of OCSP request in bytes'),
    ('enable_request_logging', 'true', 'Whether to log OCSP requests')
ON CONFLICT (parameter_name) DO NOTHING;

-- Trigger to update certificates.updated_at
CREATE TRIGGER update_certificates_updated_at BEFORE UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger to automatically update certificate status when revoked
CREATE OR REPLACE FUNCTION update_certificate_status_on_revocation()
RETURNS TRIGGER AS $$
BEGIN
    -- Update certificate status to revoked
    UPDATE certificates 
    SET status = 'revoked', updated_at = CURRENT_TIMESTAMP
    WHERE serial_number = NEW.serial_number;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_cert_status_on_revoke 
    AFTER INSERT ON certificate_revocations
    FOR EACH ROW EXECUTE FUNCTION update_certificate_status_on_revocation();