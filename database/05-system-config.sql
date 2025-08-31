-- System configuration table for persistent settings
-- This table stores system-wide configuration that needs to persist across restarts

CREATE TABLE IF NOT EXISTS system_config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    config_type VARCHAR(50) DEFAULT 'string', -- string, integer, boolean, json
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Create index for fast key lookups
CREATE INDEX IF NOT EXISTS idx_system_config_key ON system_config(config_key);

-- Insert default SCEP password configuration
INSERT INTO system_config (config_key, config_value, config_type, description) VALUES 
    ('scep_password', 'MySecretSCEPPassword123', 'string', 'SCEP challenge password for device enrollment')
ON CONFLICT (config_key) DO NOTHING;

-- Create trigger to update updated_at timestamp
CREATE TRIGGER update_system_config_updated_at BEFORE UPDATE ON system_config
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions to admin role
INSERT INTO permissions (name, description, resource, action) VALUES 
    ('config_manage', 'Manage system configuration', 'config', 'update')
ON CONFLICT (name) DO NOTHING;

-- Assign config management permission to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'admin' AND p.name = 'config_manage'
ON CONFLICT (role_id, permission_id) DO NOTHING;