-- SMTP Configuration Table
-- Stores email server settings for sending notifications

CREATE TABLE IF NOT EXISTS smtp_config (
    id SERIAL PRIMARY KEY,
    smtp_server VARCHAR(255) NOT NULL,
    smtp_port INTEGER DEFAULT 587,
    smtp_username VARCHAR(255),
    smtp_password VARCHAR(255),
    sender_email VARCHAR(255) NOT NULL,
    sender_name VARCHAR(255),
    use_tls BOOLEAN DEFAULT true,
    last_test_status VARCHAR(50),
    last_test_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create an index for faster lookups
CREATE INDEX IF NOT EXISTS idx_smtp_config_updated ON smtp_config(updated_at DESC);

-- Add a trigger to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_smtp_config_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_smtp_config_timestamp
    BEFORE UPDATE ON smtp_config
    FOR EACH ROW
    EXECUTE FUNCTION update_smtp_config_timestamp();

-- Add comment for documentation
COMMENT ON TABLE smtp_config IS 'Stores SMTP email server configuration for sending notifications';
COMMENT ON COLUMN smtp_config.smtp_server IS 'SMTP server hostname or IP address';
COMMENT ON COLUMN smtp_config.smtp_port IS 'SMTP server port (usually 25, 465, 587, or 2525)';
COMMENT ON COLUMN smtp_config.smtp_username IS 'Username for SMTP authentication';
COMMENT ON COLUMN smtp_config.smtp_password IS 'Password for SMTP authentication (should be encrypted in production)';
COMMENT ON COLUMN smtp_config.sender_email IS 'Email address to use as the sender';
COMMENT ON COLUMN smtp_config.sender_name IS 'Display name for the sender';
COMMENT ON COLUMN smtp_config.use_tls IS 'Whether to use TLS/STARTTLS for encryption';
COMMENT ON COLUMN smtp_config.last_test_status IS 'Status of the last SMTP test (success/failure)';
COMMENT ON COLUMN smtp_config.last_test_message IS 'Message from the last SMTP test';