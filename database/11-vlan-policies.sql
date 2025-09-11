-- VLAN Assignment Policy Engine Schema
-- Enables dynamic VLAN assignment based on user attributes, groups, and conditions

-- VLAN definitions table
CREATE TABLE IF NOT EXISTS vlans (
    id SERIAL PRIMARY KEY,
    vlan_id INTEGER NOT NULL UNIQUE,
    vlan_name VARCHAR(100) NOT NULL,
    description TEXT,
    subnet VARCHAR(50),
    gateway VARCHAR(50),
    dns_servers TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Policy rules for VLAN assignment
CREATE TABLE IF NOT EXISTS vlan_policies (
    id SERIAL PRIMARY KEY,
    policy_name VARCHAR(100) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 100, -- Lower number = higher priority
    is_active BOOLEAN DEFAULT true,
    
    -- Policy conditions (JSON format for flexibility)
    -- Example: {"username": "john*", "group": "engineering", "auth_type": "eap-tls"}
    conditions JSONB NOT NULL DEFAULT '{}',
    
    -- Policy actions
    vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
    
    -- Additional RADIUS attributes to return (JSON)
    -- Example: {"Session-Timeout": 3600, "Acct-Interim-Interval": 300}
    radius_attributes JSONB DEFAULT '{}',
    
    -- Access control
    allow_access BOOLEAN DEFAULT true,
    reject_reason VARCHAR(255),
    
    -- Tracking
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- User-VLAN static assignments (overrides policies)
CREATE TABLE IF NOT EXISTS user_vlan_assignments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(100), -- For external users not in users table
    vlan_id INTEGER REFERENCES vlans(id) ON DELETE CASCADE,
    expires_at TIMESTAMP,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    
    UNIQUE(user_id, vlan_id),
    UNIQUE(username, vlan_id)
);

-- Group-based VLAN assignments
CREATE TABLE IF NOT EXISTS group_vlan_assignments (
    id SERIAL PRIMARY KEY,
    group_name VARCHAR(100) NOT NULL,
    vlan_id INTEGER REFERENCES vlans(id) ON DELETE CASCADE,
    priority INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(group_name, vlan_id)
);

-- IDP-RADIUS authentication mapping
CREATE TABLE IF NOT EXISTS idp_radius_auth (
    id SERIAL PRIMARY KEY,
    idp_user_id VARCHAR(255) NOT NULL, -- Google/Microsoft user ID
    idp_email VARCHAR(255) NOT NULL,
    idp_provider VARCHAR(50) NOT NULL, -- 'google' or 'microsoft'
    
    -- RADIUS credentials (can be auto-generated or custom)
    radius_username VARCHAR(100) NOT NULL UNIQUE,
    radius_password_hash VARCHAR(255), -- For PAP/CHAP
    
    -- Certificate binding for EAP-TLS (optional)
    certificate_cn VARCHAR(255),
    
    -- Default VLAN assignment
    default_vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
    
    -- Access control
    is_active BOOLEAN DEFAULT true,
    last_auth_at TIMESTAMP,
    auth_count INTEGER DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(idp_user_id, idp_provider)
);

-- VLAN assignment audit log
CREATE TABLE IF NOT EXISTS vlan_assignment_log (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    auth_type VARCHAR(50), -- 'eap-tls', 'eap-peap', 'pap', 'idp-google', 'idp-microsoft'
    
    -- Assignment details
    assigned_vlan_id INTEGER,
    assignment_reason VARCHAR(255), -- 'policy:policy_name', 'static', 'group', 'default'
    policy_id INTEGER REFERENCES vlan_policies(id) ON DELETE SET NULL,
    
    -- RADIUS details
    nas_ip VARCHAR(50),
    nas_port VARCHAR(50),
    calling_station_id VARCHAR(50), -- MAC address
    
    -- Result
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_vlan_policies_active ON vlan_policies(is_active, priority);
CREATE INDEX idx_vlan_policies_conditions ON vlan_policies USING gin(conditions);
CREATE INDEX idx_user_vlan_assignments_user ON user_vlan_assignments(user_id, username);
CREATE INDEX idx_group_vlan_assignments_group ON group_vlan_assignments(group_name, is_active);
CREATE INDEX idx_idp_radius_auth_email ON idp_radius_auth(idp_email, is_active);
CREATE INDEX idx_vlan_assignment_log_username ON vlan_assignment_log(username, timestamp);

-- Default VLANs
INSERT INTO vlans (vlan_id, vlan_name, description, subnet) VALUES
    (1, 'Default', 'Default network', '192.168.1.0/24'),
    (10, 'Management', 'Management network', '10.0.10.0/24'),
    (20, 'Corporate', 'Corporate users', '10.0.20.0/24'),
    (30, 'Guest', 'Guest network', '10.0.30.0/24'),
    (40, 'IoT', 'IoT devices', '10.0.40.0/24'),
    (100, 'Quarantine', 'Quarantine network', '10.0.100.0/24')
ON CONFLICT (vlan_id) DO NOTHING;

-- Example policies
INSERT INTO vlan_policies (policy_name, description, priority, conditions, vlan_id, radius_attributes) VALUES
    ('Guest Policy', 'Assign guest VLAN to unknown users', 1000, 
     '{"auth_type": "pap"}', 
     (SELECT id FROM vlans WHERE vlan_id = 30),
     '{"Session-Timeout": 3600, "Acct-Interim-Interval": 300}'),
    
    ('Corporate EAP-TLS', 'Corporate VLAN for certificate auth', 100,
     '{"auth_type": "eap-tls", "certificate_valid": true}',
     (SELECT id FROM vlans WHERE vlan_id = 20),
     '{"Session-Timeout": 28800}'),
     
    ('IoT Devices', 'IoT VLAN for MAC-based auth', 200,
     '{"calling_station_id": ["00:11:22:*", "AA:BB:CC:*"]}',
     (SELECT id FROM vlans WHERE vlan_id = 40),
     '{}')
ON CONFLICT DO NOTHING;

-- Function to get VLAN assignment for a user
CREATE OR REPLACE FUNCTION get_user_vlan_assignment(
    p_username VARCHAR,
    p_auth_type VARCHAR,
    p_attributes JSONB
) RETURNS TABLE (
    vlan_id INTEGER,
    vlan_name VARCHAR,
    assignment_reason VARCHAR,
    radius_attributes JSONB
) AS $$
DECLARE
    v_result RECORD;
BEGIN
    -- 1. Check static user assignment
    SELECT v.vlan_id, v.vlan_name, 'static' as reason, '{}'::jsonb as attrs
    INTO v_result
    FROM user_vlan_assignments uva
    JOIN vlans v ON v.id = uva.vlan_id
    WHERE (uva.username = p_username OR uva.user_id = (SELECT id FROM users WHERE username = p_username))
        AND (uva.expires_at IS NULL OR uva.expires_at > NOW())
    LIMIT 1;
    
    IF FOUND THEN
        RETURN QUERY SELECT v_result.vlan_id, v_result.vlan_name, v_result.reason, v_result.attrs;
        RETURN;
    END IF;
    
    -- 2. Check policy-based assignment
    FOR v_result IN
        SELECT v.vlan_id, v.vlan_name, 
               'policy:' || vp.policy_name as reason,
               vp.radius_attributes as attrs,
               vp.priority
        FROM vlan_policies vp
        JOIN vlans v ON v.id = vp.vlan_id
        WHERE vp.is_active = true
            AND vp.allow_access = true
            AND v.is_active = true
        ORDER BY vp.priority ASC
    LOOP
        -- Check if conditions match (simplified - would need more complex JSON matching)
        -- This is a placeholder for actual condition matching logic
        RETURN QUERY SELECT v_result.vlan_id, v_result.vlan_name, v_result.reason, v_result.attrs;
        RETURN;
    END LOOP;
    
    -- 3. Return default VLAN
    RETURN QUERY 
    SELECT v.vlan_id, v.vlan_name, 'default' as reason, '{}'::jsonb as attrs
    FROM vlans v
    WHERE v.vlan_id = 1
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Update triggers
CREATE TRIGGER update_vlans_updated_at BEFORE UPDATE ON vlans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vlan_policies_updated_at BEFORE UPDATE ON vlan_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_vlan_assignments_updated_at BEFORE UPDATE ON user_vlan_assignments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_idp_radius_auth_updated_at BEFORE UPDATE ON idp_radius_auth
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();