-- Enhanced VLAN Policy System Schema
-- Separates user classification, conditions, and actions for enterprise-grade policy management

-- User Classification System
CREATE TABLE IF NOT EXISTS user_classification_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 100, -- Lower number = higher priority
    is_active BOOLEAN DEFAULT true,
    
    -- Classification criteria (how to identify users)
    classification_type VARCHAR(50) NOT NULL, -- 'domain', 'subdomain', 'attribute', 'group', 'certificate', 'regex'
    classification_value TEXT NOT NULL, -- '@company.com', '*.engineering.company.com', 'department=IT', etc.
    
    -- What group/category this rule assigns
    user_group VARCHAR(100) NOT NULL, -- 'employees', 'contractors', 'guests', 'iot-devices', 'management'
    user_category VARCHAR(100), -- 'corporate', 'byod', 'infrastructure', etc.
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    
    UNIQUE(rule_name)
);

-- Enhanced VLAN Policies (now properly structured)
CREATE TABLE IF NOT EXISTS vlan_policies_v2 (
    id SERIAL PRIMARY KEY,
    policy_name VARCHAR(100) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 100, -- Lower number = higher priority
    is_active BOOLEAN DEFAULT true,
    
    -- Target Users (who this policy applies to)
    target_user_groups TEXT[], -- ['employees', 'contractors'] 
    target_user_categories TEXT[], -- ['corporate', 'byod']
    target_users TEXT[], -- Specific usernames/emails
    
    -- Policy Conditions (when this policy applies)
    time_conditions JSONB DEFAULT '{}', -- Business hours, weekends, etc.
    location_conditions JSONB DEFAULT '{}', -- NAS IP ranges, specific locations
    device_conditions JSONB DEFAULT '{}', -- MAC patterns, device types
    auth_conditions JSONB DEFAULT '{}', -- EAP-TLS, certificates, etc.
    
    -- Policy Actions (what to do)
    default_vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
    fallback_vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
    radius_attributes JSONB DEFAULT '{}',
    access_control VARCHAR(20) DEFAULT 'allow', -- 'allow', 'deny', 'quarantine'
    
    -- Bandwidth/QoS settings
    bandwidth_limit INTEGER, -- Mbps
    qos_class VARCHAR(50), -- 'high', 'medium', 'low', 'critical'
    
    -- Session settings
    session_timeout INTEGER, -- seconds
    idle_timeout INTEGER, -- seconds
    reauthentication_interval INTEGER, -- seconds
    
    -- Logging and monitoring
    enable_logging BOOLEAN DEFAULT true,
    enable_monitoring BOOLEAN DEFAULT true,
    alert_on_violation BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    
    UNIQUE(policy_name)
);

-- VLAN Assignment Rules (more granular than policies)
CREATE TABLE IF NOT EXISTS vlan_assignment_rules (
    id SERIAL PRIMARY KEY,
    policy_id INTEGER REFERENCES vlan_policies_v2(id) ON DELETE CASCADE,
    rule_name VARCHAR(100) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT true,
    
    -- Specific conditions for this rule
    conditions JSONB NOT NULL DEFAULT '{}',
    
    -- Specific VLAN assignment
    assigned_vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
    assignment_reason VARCHAR(255),
    
    -- Rule-specific overrides
    radius_attributes JSONB DEFAULT '{}',
    session_settings JSONB DEFAULT '{}',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User Group Definitions (predefined groups)
CREATE TABLE IF NOT EXISTS user_groups (
    id SERIAL PRIMARY KEY,
    group_name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(200),
    description TEXT,
    group_type VARCHAR(50) NOT NULL, -- 'role-based', 'department', 'location', 'device-type'
    
    -- Default settings for this group
    default_vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
    default_policy_id INTEGER REFERENCES vlan_policies_v2(id) ON DELETE SET NULL,
    
    -- Group hierarchy
    parent_group_id INTEGER REFERENCES user_groups(id) ON DELETE SET NULL,
    
    -- Auto-assignment rules
    auto_assign_rules JSONB DEFAULT '{}', -- Rules for automatic group membership
    
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Enhanced VLAN Assignment Log
CREATE TABLE IF NOT EXISTS vlan_assignment_log_v2 (
    id SERIAL PRIMARY KEY,
    
    -- User identification
    username VARCHAR(100) NOT NULL,
    user_group VARCHAR(100),
    user_category VARCHAR(100),
    
    -- Authentication details  
    auth_type VARCHAR(50),
    certificate_cn VARCHAR(255),
    idp_provider VARCHAR(50),
    
    -- Network details
    nas_ip VARCHAR(50),
    nas_port VARCHAR(50),
    calling_station_id VARCHAR(50), -- MAC address
    nas_identifier VARCHAR(100),
    
    -- Policy matching results
    matched_classification_rule_id INTEGER REFERENCES user_classification_rules(id),
    matched_policy_id INTEGER REFERENCES vlan_policies_v2(id),
    matched_assignment_rule_id INTEGER REFERENCES vlan_assignment_rules(id),
    
    -- Assignment results
    assigned_vlan_id INTEGER,
    assignment_reason VARCHAR(255),
    fallback_reason VARCHAR(255),
    
    -- Policy enforcement
    applied_radius_attributes JSONB DEFAULT '{}',
    session_timeout INTEGER,
    bandwidth_limit INTEGER,
    qos_class VARCHAR(50),
    
    -- Result
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    warning_messages TEXT[],
    
    -- Performance metrics
    processing_time_ms INTEGER,
    
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_vlan_log_v2_username (username),
    INDEX idx_vlan_log_v2_timestamp (timestamp),
    INDEX idx_vlan_log_v2_success (success),
    INDEX idx_vlan_log_v2_vlan (assigned_vlan_id)
);

-- Create indexes
CREATE INDEX idx_user_classification_active ON user_classification_rules(is_active, priority);
CREATE INDEX idx_user_classification_type ON user_classification_rules(classification_type);
CREATE INDEX idx_vlan_policies_v2_active ON vlan_policies_v2(is_active, priority);
CREATE INDEX idx_vlan_policies_v2_groups ON vlan_policies_v2 USING gin(target_user_groups);
CREATE INDEX idx_vlan_assignment_rules_policy ON vlan_assignment_rules(policy_id, is_active);

-- Insert default user groups
INSERT INTO user_groups (group_name, display_name, description, group_type) VALUES
    ('employees', 'Corporate Employees', 'Full-time and part-time employees', 'role-based'),
    ('contractors', 'External Contractors', 'Temporary contractors and consultants', 'role-based'),
    ('guests', 'Guest Users', 'Temporary guest access', 'role-based'),
    ('iot-devices', 'IoT Devices', 'Internet of Things devices', 'device-type'),
    ('management', 'Management Team', 'Executive and senior management', 'role-based'),
    ('it-staff', 'IT Staff', 'IT department members', 'department'),
    ('byod', 'BYOD Devices', 'Bring Your Own Device users', 'device-type')
ON CONFLICT (group_name) DO NOTHING;

-- Insert example user classification rules
INSERT INTO user_classification_rules (rule_name, classification_type, classification_value, user_group, user_category, description, priority) VALUES
    ('Corporate Email Domain', 'domain', '@company.com', 'employees', 'corporate', 'Employees with company email addresses', 10),
    ('Engineering Subdomain', 'subdomain', '*.engineering.company.com', 'employees', 'corporate', 'Engineering department users', 20),
    ('Contractor Email Pattern', 'regex', '.*\.contractor@.*', 'contractors', 'external', 'External contractor email pattern', 30),
    ('Guest Domain', 'domain', '@guest.company.com', 'guests', 'temporary', 'Guest user accounts', 40),
    ('IoT Device MAC Pattern', 'regex', '^(00:11:22|AA:BB:CC):.*', 'iot-devices', 'infrastructure', 'Known IoT device MAC prefixes', 50),
    ('Management Group', 'attribute', 'department=management', 'management', 'corporate', 'Management team members', 5)
ON CONFLICT (rule_name) DO NOTHING;

-- Insert example enhanced policies
INSERT INTO vlan_policies_v2 (
    policy_name, description, priority,
    target_user_groups, target_user_categories,
    time_conditions, location_conditions, auth_conditions,
    default_vlan_id, fallback_vlan_id,
    radius_attributes, session_timeout, bandwidth_limit
) VALUES
    ('Corporate Employee Policy', 'Standard policy for corporate employees', 100,
     ARRAY['employees'], ARRAY['corporate'],
     '{"business_hours": true, "weekends": false}',
     '{"allowed_locations": ["office", "remote"]}',
     '{"required_auth": ["eap-tls", "idp-sso"]}',
     (SELECT id FROM vlans WHERE vlan_id = 20),
     (SELECT id FROM vlans WHERE vlan_id = 1),
     '{"Session-Timeout": 28800, "Acct-Interim-Interval": 300}',
     28800, 100),
     
    ('Guest Access Policy', 'Restricted access for guest users', 200,
     ARRAY['guests'], ARRAY['temporary'],
     '{"business_hours": true, "max_duration": 86400}',
     '{"allowed_locations": ["office"]}', 
     '{"required_auth": ["pap", "chap"]}',
     (SELECT id FROM vlans WHERE vlan_id = 30),
     (SELECT id FROM vlans WHERE vlan_id = 100),
     '{"Session-Timeout": 3600, "Idle-Timeout": 1800}',
     3600, 10),
     
    ('IoT Device Policy', 'Policy for Internet of Things devices', 150,
     ARRAY['iot-devices'], ARRAY['infrastructure'],
     '{"always_active": true}',
     '{"allowed_locations": ["office", "datacenter"]}',
     '{"required_auth": ["mac-auth", "certificate"]}',
     (SELECT id FROM vlans WHERE vlan_id = 40),
     (SELECT id FROM vlans WHERE vlan_id = 100),
     '{}',
     NULL, 50)
ON CONFLICT (policy_name) DO NOTHING;

-- Enhanced VLAN assignment function
CREATE OR REPLACE FUNCTION get_enhanced_vlan_assignment(
    p_username VARCHAR,
    p_auth_type VARCHAR,
    p_attributes JSONB
) RETURNS TABLE (
    vlan_id INTEGER,
    vlan_name VARCHAR,
    assignment_reason VARCHAR,
    radius_attributes JSONB,
    user_group VARCHAR,
    user_category VARCHAR,
    session_timeout INTEGER,
    bandwidth_limit INTEGER
) AS $$
DECLARE
    v_user_group VARCHAR;
    v_user_category VARCHAR;
    v_policy RECORD;
    v_rule RECORD;
BEGIN
    -- Step 1: Classify the user
    SELECT ucr.user_group, ucr.user_category
    INTO v_user_group, v_user_category
    FROM user_classification_rules ucr
    WHERE ucr.is_active = true
        AND (
            (ucr.classification_type = 'domain' AND p_username LIKE '%' || ucr.classification_value)
            OR (ucr.classification_type = 'regex' AND p_username ~ ucr.classification_value)
            OR (ucr.classification_type = 'attribute' AND p_attributes ? split_part(ucr.classification_value, '=', 1))
        )
    ORDER BY ucr.priority ASC
    LIMIT 1;
    
    -- Step 2: Find matching policy
    SELECT vp.*
    INTO v_policy
    FROM vlan_policies_v2 vp
    WHERE vp.is_active = true
        AND (v_user_group = ANY(vp.target_user_groups) OR v_user_category = ANY(vp.target_user_categories))
    ORDER BY vp.priority ASC
    LIMIT 1;
    
    -- Step 3: Check for specific assignment rules
    IF v_policy.id IS NOT NULL THEN
        SELECT var.*, v.vlan_id as var_vlan_id, v.vlan_name as var_vlan_name
        INTO v_rule
        FROM vlan_assignment_rules var
        JOIN vlans v ON v.id = var.assigned_vlan_id
        WHERE var.policy_id = v_policy.id
            AND var.is_active = true
        ORDER BY var.priority ASC
        LIMIT 1;
        
        IF v_rule.id IS NOT NULL THEN
            -- Return specific rule assignment
            RETURN QUERY SELECT 
                v_rule.var_vlan_id,
                v_rule.var_vlan_name,
                'rule:' || v_rule.rule_name,
                COALESCE(v_rule.radius_attributes, v_policy.radius_attributes, '{}'::jsonb),
                v_user_group,
                v_user_category,
                v_policy.session_timeout,
                v_policy.bandwidth_limit;
            RETURN;
        END IF;
        
        -- Return policy default assignment
        RETURN QUERY SELECT 
            v.vlan_id, v.vlan_name,
            'policy:' || v_policy.policy_name,
            COALESCE(v_policy.radius_attributes, '{}'::jsonb),
            v_user_group,
            v_user_category,
            v_policy.session_timeout,
            v_policy.bandwidth_limit
        FROM vlans v 
        WHERE v.id = v_policy.default_vlan_id;
        RETURN;
    END IF;
    
    -- Step 4: Return default VLAN
    RETURN QUERY SELECT 
        v.vlan_id, v.vlan_name, 'default',
        '{}'::jsonb, v_user_group, v_user_category,
        NULL::integer, NULL::integer
    FROM vlans v 
    WHERE v.vlan_id = 1 
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Update triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_user_classification_rules_updated_at 
    BEFORE UPDATE ON user_classification_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vlan_policies_v2_updated_at 
    BEFORE UPDATE ON vlan_policies_v2
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_groups_updated_at 
    BEFORE UPDATE ON user_groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();