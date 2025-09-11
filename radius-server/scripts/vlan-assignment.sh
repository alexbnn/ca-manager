#!/bin/bash

# VLAN Assignment Script for CA Manager Integration
# This script queries the CA Manager for VLAN assignment policies
# and returns appropriate RADIUS attributes

# Environment variables
CA_MANAGER_URL="${CA_MANAGER_URL:-http://web-interface:5000}"
EASYRSA_CONTAINER_URL="${EASYRSA_CONTAINER_URL:-http://easyrsa-container:8080}"

# Input parameters from FreeRADIUS
USERNAME="$1"
NAS_IP="$2"
NAS_PORT="$3"
CALLING_STATION_ID="$4"
AUTH_TYPE="$5"
CERT_CN="$6"

# Default values
DEFAULT_VLAN="1"
LOG_FILE="/var/log/radius/vlan-assignment.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Function to log messages
log_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> "$LOG_FILE"
}

# Function to get VLAN assignment from CA Manager
get_vlan_assignment() {
    local username="$1"
    local auth_type="$2"
    local nas_ip="$3"
    local nas_port="$4"
    local calling_station_id="$5"
    local cert_cn="$6"
    
    # Prepare JSON payload with additional attributes
    local json_payload=$(cat << EOF
{
    "username": "$username",
    "auth_type": "$auth_type",
    "attributes": {
        "nas_ip": "$nas_ip",
        "nas_port": "$nas_port",
        "calling_station_id": "$calling_station_id",
        "certificate_cn": "$cert_cn"
    }
}
EOF
)
    
    log_message "Requesting VLAN assignment for user: $username, auth_type: $auth_type"
    
    # Query CA Manager enhanced VLAN assignment API
    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        --connect-timeout 10 \
        --max-time 30 \
        "$CA_MANAGER_URL/api/enhanced-vlan-assignment" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        # Parse JSON response
        local status=$(echo "$response" | jq -r '.status // "error"')
        if [ "$status" = "success" ]; then
            local vlan_id=$(echo "$response" | jq -r '.vlan_id // ""')
            local vlan_name=$(echo "$response" | jq -r '.vlan_name // ""')
            local reason=$(echo "$response" | jq -r '.assignment_reason // ""')
            local user_group=$(echo "$response" | jq -r '.user_group // ""')
            local user_category=$(echo "$response" | jq -r '.user_category // ""')
            local session_timeout=$(echo "$response" | jq -r '.session_timeout // ""')
            local bandwidth_limit=$(echo "$response" | jq -r '.bandwidth_limit // ""')
            local radius_attrs=$(echo "$response" | jq -r '.radius_attributes // "{}"')
            
            log_message "Enhanced VLAN assignment successful: VLAN=$vlan_id ($vlan_name), Group=$user_group, Category=$user_category, Reason=$reason"
            
            # Output RADIUS attributes for FreeRADIUS
            if [ -n "$vlan_id" ]; then
                echo "Tunnel-Type = VLAN"
                echo "Tunnel-Medium-Type = IEEE-802"
                echo "Tunnel-Private-Group-Id = \"$vlan_id\""
                
                # Add session timeout if specified
                if [ -n "$session_timeout" ] && [ "$session_timeout" != "null" ]; then
                    echo "Session-Timeout = $session_timeout"
                fi
                
                # Add bandwidth limits if specified (using standard RADIUS attributes)
                if [ -n "$bandwidth_limit" ] && [ "$bandwidth_limit" != "null" ]; then
                    # Convert Mbps to bps for RADIUS attributes
                    local download_bps=$((bandwidth_limit * 1000000))
                    local upload_bps=$((bandwidth_limit * 1000000))
                    echo "WISPr-Bandwidth-Max-Down = $download_bps"
                    echo "WISPr-Bandwidth-Max-Up = $upload_bps"
                fi
                
                # Add additional RADIUS attributes if specified in policy
                if [ "$radius_attrs" != "{}" ] && [ "$radius_attrs" != "null" ] && [ -n "$radius_attrs" ]; then
                    echo "$radius_attrs" | jq -r 'to_entries[] | "\(.key) = \(.value)"'
                fi
            else
                log_message "No VLAN assigned, using default VLAN $DEFAULT_VLAN"
                echo "Tunnel-Type = VLAN"
                echo "Tunnel-Medium-Type = IEEE-802"
                echo "Tunnel-Private-Group-Id = \"$DEFAULT_VLAN\""
            fi
            
            # Log the assignment to CA Manager's audit log
            log_assignment "$username" "$auth_type" "$vlan_id" "$reason" "true" ""
            
            return 0
        else
            local error_msg=$(echo "$response" | jq -r '.message // "Unknown error"')
            log_message "VLAN assignment failed: $error_msg"
            
            # Log the failed assignment
            log_assignment "$username" "$auth_type" "" "" "false" "$error_msg"
            
            # Return default VLAN on error
            echo "Tunnel-Type = VLAN"
            echo "Tunnel-Medium-Type = IEEE-802"
            echo "Tunnel-Private-Group-Id = \"$DEFAULT_VLAN\""
            return 1
        fi
    else
        log_message "Failed to connect to CA Manager API"
        
        # Log the failed assignment
        log_assignment "$username" "$auth_type" "" "" "false" "API connection failed"
        
        # Return default VLAN on connection error
        echo "Tunnel-Type = VLAN"
        echo "Tunnel-Medium-Type = IEEE-802"
        echo "Tunnel-Private-Group-Id = \"$DEFAULT_VLAN\""
        return 1
    fi
}

# Function to log assignment to CA Manager audit log
log_assignment() {
    local username="$1"
    local auth_type="$2"
    local vlan_id="$3"
    local reason="$4"
    local success="$5"
    local error_msg="$6"
    
    local audit_payload=$(cat << EOF
{
    "username": "$username",
    "auth_type": "$auth_type",
    "assigned_vlan_id": "$vlan_id",
    "assignment_reason": "$reason",
    "nas_ip": "$NAS_IP",
    "nas_port": "$NAS_PORT",
    "calling_station_id": "$CALLING_STATION_ID",
    "success": $success,
    "error_message": "$error_msg"
}
EOF
)
    
    # Send audit log to CA Manager (fire and forget)
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$audit_payload" \
        --connect-timeout 5 \
        --max-time 10 \
        "$CA_MANAGER_URL/api/vlan-assignment-log" >/dev/null 2>&1 &
}

# Input validation
if [ -z "$USERNAME" ]; then
    log_message "Error: USERNAME parameter is required"
    exit 1
fi

# Determine auth type if not provided
if [ -z "$AUTH_TYPE" ]; then
    if [ -n "$CERT_CN" ]; then
        AUTH_TYPE="eap-tls"
    else
        AUTH_TYPE="unknown"
    fi
fi

log_message "Processing VLAN assignment request: User=$USERNAME, NAS=$NAS_IP, AuthType=$AUTH_TYPE"

# Get VLAN assignment
get_vlan_assignment "$USERNAME" "$AUTH_TYPE" "$NAS_IP" "$NAS_PORT" "$CALLING_STATION_ID" "$CERT_CN"

exit 0