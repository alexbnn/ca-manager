-- Intermediate CA Management Schema
-- Supports multiple intermediate CAs with hierarchy tracking

-- Table for storing intermediate CAs
CREATE TABLE IF NOT EXISTS intermediate_cas (
    id SERIAL PRIMARY KEY,
    ca_name VARCHAR(100) UNIQUE NOT NULL,
    ca_common_name VARCHAR(255) NOT NULL,
    parent_ca_id INTEGER REFERENCES intermediate_cas(id) ON DELETE CASCADE,
    ca_level INTEGER DEFAULT 1, -- 0=root, 1=first intermediate, 2=second level, etc
    certificate TEXT,
    private_key TEXT, -- Encrypted
    certificate_chain TEXT,
    serial_number VARCHAR(100),
    valid_from TIMESTAMP,
    valid_until TIMESTAMP,
    key_algorithm VARCHAR(50) DEFAULT 'RSA',
    key_size INTEGER DEFAULT 4096,
    signature_algorithm VARCHAR(50) DEFAULT 'sha256',
    path_length_constraint INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    can_issue_ca BOOLEAN DEFAULT FALSE, -- Can this CA issue other intermediate CAs
    allowed_extensions JSONB, -- Which extensions this CA can include in certs
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for certificate request workflow
CREATE TABLE IF NOT EXISTS certificate_requests (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(100) UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
    requester_name VARCHAR(100) NOT NULL,
    requester_email VARCHAR(255) NOT NULL,
    department VARCHAR(100),
    common_name VARCHAR(255) NOT NULL,
    san_dns_names TEXT[], -- Subject Alternative Names - DNS
    san_ip_addresses TEXT[], -- Subject Alternative Names - IPs
    san_emails TEXT[], -- Subject Alternative Names - Emails
    certificate_type VARCHAR(50) NOT NULL, -- 'server', 'client', 'email', 'code_signing'
    key_algorithm VARCHAR(50) DEFAULT 'RSA',
    key_size INTEGER DEFAULT 2048,
    validity_days INTEGER DEFAULT 365,
    certificate_template VARCHAR(100), -- Reference to a template
    issuing_ca_id INTEGER REFERENCES intermediate_cas(id),
    
    -- CSR and certificate data
    csr_pem TEXT,
    certificate_pem TEXT,
    private_key_pem TEXT, -- Encrypted, only if we generate the key
    
    -- Workflow fields
    status VARCHAR(50) DEFAULT 'pending', -- pending, approved, rejected, issued, revoked, expired
    approval_required BOOLEAN DEFAULT TRUE,
    approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP,
    rejection_reason TEXT,
    
    -- Certificate details after issuance
    serial_number VARCHAR(100),
    issued_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    revocation_reason VARCHAR(100),
    
    -- Metadata
    request_metadata JSONB, -- Additional request data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Certificate templates table
CREATE TABLE IF NOT EXISTS certificate_templates (
    id SERIAL PRIMARY KEY,
    template_name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    certificate_type VARCHAR(50) NOT NULL,
    default_validity_days INTEGER DEFAULT 365,
    max_validity_days INTEGER DEFAULT 730,
    key_algorithm VARCHAR(50) DEFAULT 'RSA',
    min_key_size INTEGER DEFAULT 2048,
    required_extensions JSONB,
    optional_extensions JSONB,
    allowed_sans JSONB, -- What types of SANs are allowed
    requires_approval BOOLEAN DEFAULT TRUE,
    auto_approve_domains TEXT[], -- Domains that can be auto-approved
    allowed_roles INTEGER[], -- Which roles can use this template
    issuing_ca_id INTEGER REFERENCES intermediate_cas(id),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- CA chain tracking
CREATE TABLE IF NOT EXISTS ca_chains (
    id SERIAL PRIMARY KEY,
    ca_id INTEGER REFERENCES intermediate_cas(id) ON DELETE CASCADE,
    chain_order INTEGER NOT NULL, -- Order in chain (0=root, 1=intermediate, etc)
    certificate_pem TEXT NOT NULL,
    UNIQUE(ca_id, chain_order)
);

-- Request approval history
CREATE TABLE IF NOT EXISTS request_approvals (
    id SERIAL PRIMARY KEY,
    request_id INTEGER REFERENCES certificate_requests(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL, -- 'approved', 'rejected', 'requested_info', 'commented'
    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_name VARCHAR(100),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Download tracking for audit
CREATE TABLE IF NOT EXISTS certificate_downloads (
    id SERIAL PRIMARY KEY,
    request_id INTEGER REFERENCES certificate_requests(id) ON DELETE CASCADE,
    downloaded_by_email VARCHAR(255),
    download_format VARCHAR(50), -- 'pem', 'der', 'p12', 'jks'
    download_ip INET,
    download_method VARCHAR(50), -- 'web', 'api', 'email', 'qr'
    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_intermediate_cas_active ON intermediate_cas(is_active);
CREATE INDEX IF NOT EXISTS idx_intermediate_cas_parent ON intermediate_cas(parent_ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_requests_status ON certificate_requests(status);
CREATE INDEX IF NOT EXISTS idx_cert_requests_requester ON certificate_requests(requester_email);
CREATE INDEX IF NOT EXISTS idx_cert_requests_serial ON certificate_requests(serial_number);
CREATE INDEX IF NOT EXISTS idx_cert_requests_expires ON certificate_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_templates_active ON certificate_templates(is_active);
CREATE INDEX IF NOT EXISTS idx_templates_type ON certificate_templates(certificate_type);

-- Insert default certificate templates
INSERT INTO certificate_templates (template_name, display_name, description, certificate_type, default_validity_days, max_validity_days, requires_approval) VALUES
    ('web_server', 'Web Server Certificate', 'TLS/SSL certificate for web servers', 'server', 365, 825, true),
    ('web_server_internal', 'Internal Web Server', 'TLS/SSL certificate for internal web servers', 'server', 730, 1095, false),
    ('client_auth', 'Client Authentication', 'Certificate for client authentication', 'client', 365, 730, true),
    ('email_signing', 'Email Signing (S/MIME)', 'Certificate for email encryption and signing', 'email', 365, 1095, true),
    ('code_signing', 'Code Signing', 'Certificate for signing code and executables', 'code_signing', 730, 1095, true),
    ('vpn_client', 'VPN Client', 'Certificate for VPN client authentication', 'client', 365, 730, false),
    ('wifi_8021x', '802.1X WiFi Authentication', 'Certificate for WiFi EAP-TLS authentication', 'client', 730, 1095, false)
ON CONFLICT (template_name) DO NOTHING;

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_intermediate_ca_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers
CREATE TRIGGER update_intermediate_cas_updated_at 
    BEFORE UPDATE ON intermediate_cas
    FOR EACH ROW EXECUTE FUNCTION update_intermediate_ca_updated_at();

CREATE TRIGGER update_cert_requests_updated_at 
    BEFORE UPDATE ON certificate_requests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Permissions for the new tables
GRANT ALL ON intermediate_cas TO pkiuser;
GRANT ALL ON certificate_requests TO pkiuser;
GRANT ALL ON certificate_templates TO pkiuser;
GRANT ALL ON ca_chains TO pkiuser;
GRANT ALL ON request_approvals TO pkiuser;
GRANT ALL ON certificate_downloads TO pkiuser;
GRANT ALL ON intermediate_cas_id_seq TO pkiuser;
GRANT ALL ON certificate_requests_id_seq TO pkiuser;
GRANT ALL ON certificate_templates_id_seq TO pkiuser;
GRANT ALL ON ca_chains_id_seq TO pkiuser;
GRANT ALL ON request_approvals_id_seq TO pkiuser;
GRANT ALL ON certificate_downloads_id_seq TO pkiuser;