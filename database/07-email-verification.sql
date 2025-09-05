-- Email Verification System for Certificate Requests
-- This ensures users can only request certificates for email addresses they control

-- Store email verification tokens
CREATE TABLE IF NOT EXISTS email_verifications (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    verification_code VARCHAR(6) NOT NULL,  -- 6-digit code
    token VARCHAR(64) UNIQUE NOT NULL,      -- URL token for verification link
    request_data JSONB,                     -- Store the certificate request data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,          -- Token expires after 15 minutes
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Create indexes for email_verifications table
CREATE INDEX IF NOT EXISTS idx_email_verifications_email ON email_verifications(email);
CREATE INDEX IF NOT EXISTS idx_email_verifications_token ON email_verifications(token);
CREATE INDEX IF NOT EXISTS idx_email_verifications_expires ON email_verifications(expires_at);

-- Store allowed email domains for self-service registration
CREATE TABLE IF NOT EXISTS allowed_email_domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    allow_subdomains BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

-- Create index for allowed_email_domains table
CREATE INDEX IF NOT EXISTS idx_allowed_domains_enabled ON allowed_email_domains(enabled);

-- Add verification status to certificate_requests
ALTER TABLE certificate_requests 
ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS verification_token VARCHAR(64),
ADD COLUMN IF NOT EXISTS verification_completed_at TIMESTAMP;

-- Add a default example domain (should be configured by admin)
INSERT INTO allowed_email_domains (domain, description, allow_subdomains, created_by) 
VALUES 
    ('example.com', 'Example domain - replace with your organization domain', false, 'system')
ON CONFLICT (domain) DO NOTHING;

-- Function to clean up expired verification tokens
CREATE OR REPLACE FUNCTION cleanup_expired_verifications() RETURNS void AS $$
BEGIN
    DELETE FROM email_verifications 
    WHERE expires_at < CURRENT_TIMESTAMP 
    AND verified_at IS NULL;
END;
$$ LANGUAGE plpgsql;

-- Create an index for faster cleanup
CREATE INDEX IF NOT EXISTS idx_email_verifications_cleanup 
ON email_verifications(expires_at, verified_at) 
WHERE verified_at IS NULL;