-- Tenant Management Database Schema

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(16) PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    subdomain VARCHAR(63) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'creating',
    config JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL
);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenants_subdomain ON tenants(subdomain);
CREATE INDEX IF NOT EXISTS idx_tenants_created_at ON tenants(created_at);

-- Tenant audit logs
CREATE TABLE IF NOT EXISTS tenant_audit_logs (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(16) REFERENCES tenants(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    performed_by VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add index for audit logs
CREATE INDEX IF NOT EXISTS idx_tenant_audit_logs_tenant_id ON tenant_audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_audit_logs_action ON tenant_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_tenant_audit_logs_created_at ON tenant_audit_logs(created_at);

-- Tenant settings table
CREATE TABLE IF NOT EXISTS tenant_settings (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(16) REFERENCES tenants(id) ON DELETE CASCADE,
    setting_key VARCHAR(100) NOT NULL,
    setting_value JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, setting_key)
);

-- Add index for settings
CREATE INDEX IF NOT EXISTS idx_tenant_settings_tenant_id ON tenant_settings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_settings_key ON tenant_settings(setting_key);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to automatically update updated_at
CREATE TRIGGER update_tenants_updated_at 
    BEFORE UPDATE ON tenants 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_settings_updated_at 
    BEFORE UPDATE ON tenant_settings 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default admin user (you should change this password!)
INSERT INTO tenants (id, name, subdomain, status, config) 
VALUES (
    'admin000', 
    'System Admin', 
    'admin', 
    'system',
    '{"type": "admin", "system": true}'::jsonb
) ON CONFLICT (id) DO NOTHING;