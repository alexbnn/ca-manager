-- Initial data setup for PKI multi-user system
-- This script creates default roles and users

-- Create default roles
INSERT INTO roles (name, description) VALUES
    ('admin', 'Full administrative access to all PKI operations'),
    ('operator', 'Standard PKI operations (create, read, update certificates)'),
    ('viewer', 'Read-only access to PKI resources')
ON CONFLICT (name) DO NOTHING;

-- Create default permissions
INSERT INTO permissions (name, description, resource, action) VALUES
    ('pki_init', 'Initialize PKI system', 'pki', 'create'),
    ('pki_read', 'View PKI status and information', 'pki', 'read'),
    ('ca_build', 'Build Certificate Authority', 'ca', 'create'),
    ('ca_read', 'View Certificate Authority details', 'ca', 'read'),
    ('cert_create', 'Create new certificates', 'certificates', 'create'),
    ('cert_read', 'View certificate details', 'certificates', 'read'),
    ('cert_revoke', 'Revoke certificates', 'certificates', 'delete'),
    ('cert_renew', 'Renew certificates', 'certificates', 'update'),
    ('crl_generate', 'Generate Certificate Revocation Lists', 'crl', 'create'),
    ('crl_read', 'View Certificate Revocation Lists', 'crl', 'read'),
    ('user_read', 'View user information', 'users', 'read'),
    ('user_manage', 'Create and update users', 'users', 'create'),
    ('user_update', 'Update user information', 'users', 'update'),
    ('user_delete', 'Delete users', 'users', 'delete'),
    ('audit_read', 'View audit logs', 'audit', 'read'),
    ('system_config', 'Configure system settings', 'system', 'update')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to roles
-- Admin role gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Operator role gets standard PKI operations (no user management or PKI init)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'operator'
AND p.name IN (
    'pki_read', 'ca_build', 'ca_read', 'cert_create', 'cert_read', 
    'cert_revoke', 'cert_renew', 'crl_generate', 'crl_read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Viewer role gets read-only permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'viewer'
AND p.name IN ('pki_read', 'ca_read', 'cert_read', 'crl_read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Create default users with bcrypt hashed passwords
-- Password for all users: admin -> admin, operator -> operator, viewer -> viewer
-- These are bcrypt hashes with cost factor 12

-- Admin user (password: admin)
INSERT INTO users (username, email, password_hash, full_name, is_admin, is_active)
VALUES (
    'admin',
    'admin@example.com',
    '$2b$12$wL/BlaD//hyZhxY9PLQVbOujopj/XzjulFytrIs5ummKEvnM3TnGW',
    'System Administrator',
    true,
    true
) ON CONFLICT (username) DO UPDATE SET
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    full_name = EXCLUDED.full_name,
    is_admin = EXCLUDED.is_admin,
    is_active = EXCLUDED.is_active;

-- Operator user (password: operator)
INSERT INTO users (username, email, password_hash, full_name, is_admin, is_active)
VALUES (
    'operator',
    'operator@example.com',
    '$2b$12$sFL7IeQXUz/TWS/KlL/lOubnYLZlywB32uDt50M4mZocZAk5vmrJy',
    'PKI Operator',
    false,
    true
) ON CONFLICT (username) DO NOTHING;

-- Viewer user (password: viewer)
INSERT INTO users (username, email, password_hash, full_name, is_admin, is_active)
VALUES (
    'viewer',
    'viewer@example.com',
    '$2b$12$rozW9arRLoDNx8fUzZw0Fuapa8DxwzFPyjX91YntSHYWYd9T6keiu',
    'PKI Viewer',
    false,
    true
) ON CONFLICT (username) DO NOTHING;

-- Assign roles to users
-- Admin user gets admin role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'admin'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Operator user gets operator role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'operator' AND r.name = 'operator'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Viewer user gets viewer role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'viewer' AND r.name = 'viewer'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Insert initial audit log entry
INSERT INTO audit_logs (username, operation, details, status)
VALUES (
    'system',
    'database_initialized',
    '{"message": "Initial database setup completed", "users_created": 3, "roles_created": 3}',
    'success'
);