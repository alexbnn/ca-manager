-- Multi-user authentication database schema
-- This schema supports users, roles, and permissions for PKI operations

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL, -- e.g., 'pki', 'certificates', 'ca'
    action VARCHAR(20) NOT NULL, -- e.g., 'create', 'read', 'update', 'delete'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User-Role mapping (many-to-many)
CREATE TABLE IF NOT EXISTS user_roles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, role_id)
);

-- Role-Permission mapping (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

-- User sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(50),
    operation VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'success' -- success, failed, error
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation);

-- Insert default roles
INSERT INTO roles (name, description) VALUES 
    ('admin', 'Full administrative access to all PKI operations'),
    ('operator', 'Standard PKI operations (create, read, update certificates)'),
    ('viewer', 'Read-only access to PKI resources')
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (name, description, resource, action) VALUES 
    ('pki_init', 'Initialize PKI infrastructure', 'pki', 'create'),
    ('pki_read', 'View PKI configuration and status', 'pki', 'read'),
    ('ca_build', 'Build Certificate Authority', 'ca', 'create'),
    ('ca_read', 'View Certificate Authority details', 'ca', 'read'),
    ('cert_create', 'Create new certificates', 'certificates', 'create'),
    ('cert_read', 'View certificate details', 'certificates', 'read'),
    ('cert_revoke', 'Revoke certificates', 'certificates', 'delete'),
    ('cert_renew', 'Renew certificates', 'certificates', 'update'),
    ('crl_generate', 'Generate Certificate Revocation Lists', 'crl', 'create'),
    ('crl_read', 'View Certificate Revocation Lists', 'crl', 'read'),
    ('user_manage', 'Manage user accounts', 'users', 'create'),
    ('user_read', 'View user accounts', 'users', 'read'),
    ('user_update', 'Update user accounts', 'users', 'update'),
    ('user_delete', 'Delete user accounts', 'users', 'delete'),
    ('role_manage', 'Manage roles and permissions', 'roles', 'create'),
    ('audit_read', 'View audit logs', 'audit', 'read'),
    ('system_config', 'Modify system configuration', 'system', 'update')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to default roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'admin' -- Admin gets all permissions
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'operator' AND p.name IN (
    'pki_read', 'ca_read', 'cert_create', 'cert_read', 'cert_revoke', 'cert_renew', 'crl_generate', 'crl_read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p 
WHERE r.name = 'viewer' AND p.name IN (
    'pki_read', 'ca_read', 'cert_read', 'crl_read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Create default admin user (no password required for initial setup)
-- Admin can login with default password 'admin'
-- Password hash is bcrypt hash of 'admin' with cost factor 12
INSERT INTO users (username, email, password_hash, full_name, is_active, is_admin) VALUES 
    ('admin', 'admin@example.com', '$2b$12$wL/BlaD//hyZhxY9PLQVbOujopj/XzjulFytrIs5ummKEvnM3TnGW', 'System Administrator', TRUE, TRUE)
ON CONFLICT (username) DO NOTHING;

-- Assign admin role to default admin user
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r 
WHERE u.username = 'admin' AND r.name = 'admin'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();