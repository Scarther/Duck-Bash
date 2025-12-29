# WiFi Pineapple Blue Team Countermeasures

## Overview

This guide provides detection and defense techniques against WiFi attacks including Evil Twin, deauthentication, and rogue AP attacks.

---

## Defense Architecture

```
WIRELESS DEFENSE LAYERS
├── Detection
│   ├── Rogue AP Detection
│   ├── Deauth Detection
│   └── Evil Twin Detection
├── Prevention
│   ├── 802.1X Authentication
│   ├── WPA3 Deployment
│   └── Client Configuration
├── Response
│   ├── Alert Generation
│   ├── Automated Blocking
│   └── Incident Handling
└── Monitoring
    ├── WIDS/WIPS
    ├── Continuous Scanning
    └── Baseline Comparison
```

---

## Rogue AP Detection

### Active Scanner

```bash
#!/bin/bash
#######################################
# Rogue AP Scanner
# Detect unauthorized access points
#######################################

INTERFACE="${1:-wlan0}"
KNOWN_APS="/etc/wireless/known_aps.txt"
LOG_FILE="/var/log/rogue_ap.log"
ALERT_THRESHOLD=1

# Create known APs file if not exists
if [ ! -f "$KNOWN_APS" ]; then
    echo "# Known authorized APs (BSSID SSID)" > "$KNOWN_APS"
    echo "# Example: AA:BB:CC:DD:EE:FF CorporateWiFi" >> "$KNOWN_APS"
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

alert() {
    log "[ALERT] $1"
    # Add notification method here (email, slack, etc.)
}

scan_aps() {
    # Scan for all visible APs
    iwlist "$INTERFACE" scan 2>/dev/null | \
        grep -E "Cell|ESSID|Address" | \
        paste - - - | \
        awk '{
            gsub(/.*Address: /, "", $0)
            gsub(/ *ESSID:/, " ", $0)
            print
        }'
}

check_rogue() {
    local bssid="$1"
    local ssid="$2"

    # Check if this is a known AP
    if grep -qi "$bssid" "$KNOWN_APS" 2>/dev/null; then
        return 0  # Known AP
    fi

    # Check for SSID spoofing (known SSID, unknown BSSID)
    if grep -qi "$ssid" "$KNOWN_APS" 2>/dev/null; then
        alert "SSID SPOOFING: $ssid from unknown BSSID $bssid"
        return 1
    fi

    # Unknown AP with unknown SSID
    log "[INFO] Unknown AP: $bssid ($ssid)"
    return 0
}

log "════════════════════════════════════════════════════"
log "         Rogue AP Scanner Started"
log "════════════════════════════════════════════════════"

while true; do
    log "[*] Scanning for wireless networks..."

    scan_aps | while read line; do
        BSSID=$(echo "$line" | awk '{print $1}')
        SSID=$(echo "$line" | cut -d'"' -f2)

        check_rogue "$BSSID" "$SSID"
    done

    sleep 60
done
```

### Evil Twin Detector

```bash
#!/bin/bash
#######################################
# Evil Twin Detector
# Detect duplicate SSIDs with different BSSIDs
#######################################

INTERFACE="${1:-wlan0}"
LOG_FILE="/var/log/evil_twin.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

alert() {
    log "[CRITICAL] $1"
    # Notification here
}

detect_evil_twin() {
    # Get all visible APs
    SCAN_RESULT=$(iwlist "$INTERFACE" scan 2>/dev/null)

    # Extract SSID and BSSID pairs
    echo "$SCAN_RESULT" | grep -E "Cell|ESSID" | paste - - | \
        awk -F'[:"]' '{print $4, $8}' | sort | while read BSSID SSID; do
        echo "$SSID $BSSID"
    done > /tmp/ap_scan.txt

    # Find duplicate SSIDs
    cut -d' ' -f1 /tmp/ap_scan.txt | sort | uniq -d | while read dup_ssid; do
        BSSIDS=$(grep "^$dup_ssid " /tmp/ap_scan.txt | awk '{print $2}')
        COUNT=$(echo "$BSSIDS" | wc -l)

        if [ "$COUNT" -gt 1 ]; then
            alert "EVIL TWIN DETECTED: SSID '$dup_ssid' seen from multiple APs:"
            echo "$BSSIDS" | while read bssid; do
                log "  - $bssid"
            done
        fi
    done
}

log "════════════════════════════════════════════════════"
log "         Evil Twin Detector Started"
log "════════════════════════════════════════════════════"

while true; do
    log "[*] Scanning for evil twins..."
    detect_evil_twin
    sleep 30
done
```

---

## Deauthentication Detection

### Deauth Monitor

```bash
#!/bin/bash
#######################################
# Deauthentication Attack Detector
# Monitor for deauth/disassoc frames
#######################################

INTERFACE="${1:-wlan0mon}"
LOG_FILE="/var/log/deauth_attacks.log"
ALERT_THRESHOLD=10
TIME_WINDOW=60

# Ensure monitor mode
if ! iwconfig "$INTERFACE" 2>/dev/null | grep -q "Monitor"; then
    echo "[*] Setting up monitor mode..."
    ORIGINAL_IFACE="${INTERFACE%mon}"
    airmon-ng start "$ORIGINAL_IFACE" &>/dev/null
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "════════════════════════════════════════════════════"
log "    Deauthentication Attack Monitor"
log "════════════════════════════════════════════════════"

# Use tcpdump to capture deauth frames
tcpdump -i "$INTERFACE" -e -s 0 'type mgt subtype deauth or type mgt subtype disassoc' 2>/dev/null | \
while read line; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    SRC_MAC=$(echo "$line" | grep -oP '(?<=SA:)[0-9a-f:]+')
    DST_MAC=$(echo "$line" | grep -oP '(?<=DA:)[0-9a-f:]+')
    BSSID=$(echo "$line" | grep -oP '(?<=BSSID:)[0-9a-f:]+')

    log "[DEAUTH] SRC: $SRC_MAC -> DST: $DST_MAC (BSSID: $BSSID)"

    # Count deauths per source in time window
    RECENT_COUNT=$(grep "$SRC_MAC" "$LOG_FILE" | grep "$(date -d "-$TIME_WINDOW seconds" '+%Y-%m-%d %H:%M')" | wc -l)

    if [ "$RECENT_COUNT" -gt "$ALERT_THRESHOLD" ]; then
        log "[CRITICAL] DEAUTH ATTACK DETECTED from $SRC_MAC ($RECENT_COUNT frames in ${TIME_WINDOW}s)"
    fi
done
```

### Client Protection Script

```bash
#!/bin/bash
#######################################
# Client-Side WiFi Protection
# Detect attacks against this client
#######################################

INTERFACE="${1:-wlan0}"
CONNECTED_BSSID=""
LOG_FILE="/var/log/wifi_protection.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

get_connection_info() {
    iwconfig "$INTERFACE" 2>/dev/null | grep -oP 'Access Point: \K[0-9A-F:]+' || echo "Not connected"
}

monitor_connection() {
    local previous_bssid=""

    while true; do
        current_bssid=$(get_connection_info)

        if [ "$current_bssid" != "$previous_bssid" ]; then
            if [ "$previous_bssid" != "" ] && [ "$previous_bssid" != "Not connected" ]; then
                log "[WARNING] Disconnected from $previous_bssid"

                # Check if we reconnected to same SSID but different BSSID
                if [ "$current_bssid" != "Not connected" ]; then
                    current_ssid=$(iwconfig "$INTERFACE" 2>/dev/null | grep -oP 'ESSID:"\K[^"]+')
                    log "[ALERT] Connected to new BSSID: $current_bssid ($current_ssid)"
                    log "[!] Verify this is the legitimate AP!"
                fi
            fi

            previous_bssid="$current_bssid"
        fi

        sleep 5
    done
}

log "════════════════════════════════════════════════════"
log "         WiFi Client Protection Active"
log "════════════════════════════════════════════════════"

monitor_connection
```

---

## WIDS/WIPS Implementation

### Simple Wireless IDS

```bash
#!/bin/bash
#######################################
# Simple Wireless Intrusion Detection
# Multi-threat monitoring
#######################################

INTERFACE="${1:-wlan0mon}"
LOG_DIR="/var/log/wids"
mkdir -p "$LOG_DIR"

KNOWN_APS="$LOG_DIR/known_aps.txt"
ALERT_LOG="$LOG_DIR/alerts.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$ALERT_LOG"
}

# Initialize known APs if needed
if [ ! -f "$KNOWN_APS" ]; then
    touch "$KNOWN_APS"
fi

echo "════════════════════════════════════════════════════"
echo "         Simple Wireless IDS"
echo "════════════════════════════════════════════════════"
echo ""

# Start multiple detection modules
echo "[*] Starting detection modules..."

# Module 1: Deauth detection
(
    tcpdump -i "$INTERFACE" -e -s 0 'type mgt subtype deauth' 2>/dev/null | while read line; do
        log "[DEAUTH] $line"
    done
) &
DEAUTH_PID=$!

# Module 2: Probe request monitoring
(
    tcpdump -i "$INTERFACE" -e -s 0 'type mgt subtype probe-req' 2>/dev/null | while read line; do
        SSID=$(echo "$line" | grep -oP 'Probe Request \(\K[^)]+')
        if [ -n "$SSID" ] && [ "$SSID" != "Broadcast" ]; then
            echo "[PROBE] Device probing for: $SSID" >> "$LOG_DIR/probes.log"
        fi
    done
) &
PROBE_PID=$!

# Module 3: New AP detection
(
    while true; do
        iwlist "${INTERFACE%mon}" scan 2>/dev/null | \
            grep -E "Cell|ESSID|Address" | \
            paste - - - | while read line; do
            BSSID=$(echo "$line" | grep -oP 'Address: \K[0-9A-F:]+')
            SSID=$(echo "$line" | grep -oP 'ESSID:"\K[^"]+')

            if ! grep -q "$BSSID" "$KNOWN_APS" 2>/dev/null; then
                log "[NEW AP] $BSSID ($SSID)"
                echo "$BSSID $SSID $(date)" >> "$KNOWN_APS"
            fi
        done
        sleep 60
    done
) &
AP_PID=$!

echo "[+] Detection modules running:"
echo "    Deauth Monitor: PID $DEAUTH_PID"
echo "    Probe Monitor: PID $PROBE_PID"
echo "    AP Scanner: PID $AP_PID"
echo ""
echo "[*] Logs: $LOG_DIR"
echo "[*] Press Ctrl+C to stop"

# Cleanup on exit
cleanup() {
    kill $DEAUTH_PID $PROBE_PID $AP_PID 2>/dev/null
    echo ""
    echo "[*] WIDS stopped"
}
trap cleanup EXIT

wait
```

---

## Client Configuration Hardening

### WiFi Hardening Script

```bash
#!/bin/bash
#######################################
# Client WiFi Security Hardening
#######################################

echo "════════════════════════════════════════════════════"
echo "         WiFi Client Hardening"
echo "════════════════════════════════════════════════════"
echo ""

# 1. Disable auto-connect to open networks
echo "[*] Disabling auto-connect to open networks..."
if command -v nmcli &>/dev/null; then
    # NetworkManager
    nmcli connection show | grep wifi | awk '{print $1}' | while read conn; do
        nmcli connection modify "$conn" 802-11-wireless-security.key-mgmt wpa-psk 2>/dev/null
    done
fi

# 2. Clear saved networks (optional)
echo "[*] Current saved networks:"
nmcli connection show | grep wifi

# 3. Disable WiFi when not needed
echo ""
echo "[*] WiFi power management:"
echo "    To disable WiFi: nmcli radio wifi off"
echo "    To enable WiFi:  nmcli radio wifi on"

# 4. MAC address randomization
echo ""
echo "[*] Enabling MAC address randomization..."
if [ -d /etc/NetworkManager/conf.d ]; then
    cat > /etc/NetworkManager/conf.d/99-random-mac.conf << 'EOF'
[device-mac-randomization]
wifi.scan-rand-mac-address=yes

[connection-mac-randomization]
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random
EOF
    echo "[+] MAC randomization configured"
fi

# 5. Disable unnecessary protocols
echo ""
echo "[*] Protocol recommendations:"
echo "    - Disable WPS on all APs"
echo "    - Use WPA3 where available"
echo "    - Use 802.1X for enterprise"

# 6. VPN reminder
echo ""
echo "[*] VPN Configuration:"
echo "    Always use VPN on untrusted networks!"

echo ""
echo "[+] Hardening recommendations applied"
```

---

## Automated Response

### Attack Response Script

```bash
#!/bin/bash
#######################################
# Automated WiFi Attack Response
#######################################

LOG_FILE="/var/log/wids/alerts.log"
RESPONSE_LOG="/var/log/wids/responses.log"

respond() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] RESPONSE: $1" >> "$RESPONSE_LOG"
}

# Monitor alert log for attacks
tail -F "$LOG_FILE" 2>/dev/null | while read line; do

    # Deauth attack response
    if echo "$line" | grep -q "\[DEAUTH\]"; then
        ATTACKER_MAC=$(echo "$line" | grep -oP '(?<=SA:)[0-9a-f:]+')

        if [ -n "$ATTACKER_MAC" ]; then
            respond "Deauth attack from $ATTACKER_MAC"

            # Log attacker
            echo "$ATTACKER_MAC $(date)" >> /var/log/wids/attackers.txt

            # Could add firewall block if on managed network
            # iptables -A INPUT -m mac --mac-source "$ATTACKER_MAC" -j DROP
        fi
    fi

    # Evil twin response
    if echo "$line" | grep -q "\[EVIL TWIN\]"; then
        ROGUE_BSSID=$(echo "$line" | grep -oP '[0-9A-Fa-f:]{17}')

        respond "Evil twin detected: $ROGUE_BSSID"

        # Alert security team
        # mail -s "Evil Twin Alert" security@company.com < /dev/null

        # Disconnect affected clients (if we control the network)
        # hostapd_cli deauthenticate $CLIENT_MAC
    fi

    # New AP response
    if echo "$line" | grep -q "\[NEW AP\]"; then
        NEW_BSSID=$(echo "$line" | grep -oP '[0-9A-Fa-f:]{17}')
        respond "New AP detected: $NEW_BSSID - manual review required"
    fi

done
```

---

## Blue Team Checklist

```
WIRELESS SECURITY BASELINE:
☐ All APs documented with BSSID/SSID
☐ Rogue AP detection deployed
☐ Deauth monitoring active
☐ Evil twin detection configured
☐ Client devices hardened

MONITORING:
☐ WIDS alerts reviewed daily
☐ New AP alerts investigated
☐ Deauth patterns analyzed
☐ Probe requests logged

RESPONSE PROCEDURES:
☐ Evil twin response documented
☐ Deauth attack response documented
☐ Rogue AP response documented
☐ Escalation procedures defined

REGULAR TASKS:
☐ Weekly wireless scan
☐ Monthly baseline review
☐ Quarterly penetration test
☐ Annual policy review
```

---

[← Back to Chapter 02](../README.md)
