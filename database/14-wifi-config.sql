-- WiFi Network Configuration Schema
-- Store WiFi network settings for mobile configuration profiles

-- Add WiFi configuration to system_config table
INSERT INTO system_config (config_key, config_value, description, updated_at)
VALUES 
    ('wifi_ssid', 'CorporateWiFi', 'WiFi network SSID for mobile configuration', CURRENT_TIMESTAMP),
    ('wifi_security_type', 'WPA2', 'WiFi security type (WPA2/WPA3)', CURRENT_TIMESTAMP),
    ('wifi_hidden_network', 'false', 'Whether the WiFi network is hidden', CURRENT_TIMESTAMP),
    ('wifi_auto_join', 'true', 'Whether devices should auto-join this network', CURRENT_TIMESTAMP),
    ('wifi_proxy_type', 'None', 'Proxy configuration (None/Manual/Auto)', CURRENT_TIMESTAMP),
    ('organization_name', 'Your Organization', 'Organization name for mobile profiles', CURRENT_TIMESTAMP),
    ('profile_description', 'WiFi configuration for secure network access', 'Description shown in mobile profile', CURRENT_TIMESTAMP)
ON CONFLICT (config_key) DO UPDATE 
SET config_value = EXCLUDED.config_value,
    description = EXCLUDED.description,
    updated_at = CURRENT_TIMESTAMP;