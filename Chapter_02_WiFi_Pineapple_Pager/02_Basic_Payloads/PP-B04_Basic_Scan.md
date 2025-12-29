# PP-B04: Basic Scan

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B04 |
| **Name** | Basic Scan |
| **Difficulty** | Basic |
| **Type** | Recon |
| **Purpose** | Scan nearby wireless networks |
| **MITRE ATT&CK** | T1595 (Active Scanning), T1040 (Network Sniffing) |

## What This Payload Does

Performs a comprehensive scan of nearby wireless networks, gathering SSIDs, BSSIDs, channels, encryption types, signal strength, and connected clients.

---

## Understanding Wireless Scanning

```
┌─────────────────────────────────────────────────────────────┐
│              WIRELESS SCANNING MODES                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   MANAGED MODE (Normal)           MONITOR MODE              │
│   ─────────────────────           ────────────               │
│   • Connected to AP               • Not connected            │
│   • Can only see beacons          • Sees ALL frames          │
│   • Limited scanning              • Full packet capture      │
│   • Uses iwlist scan              • Uses airodump-ng         │
│                                                              │
│   PASSIVE SCANNING                ACTIVE SCANNING           │
│   ─────────────────               ─────────────────          │
│   • Listen for beacons            • Send probe requests      │
│   • Undetectable                  • Faster results           │
│   • May miss hidden SSIDs         • Can reveal hidden SSIDs  │
│   • Takes longer                  • Can be detected          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B04
# Name: Basic Scan
# Description: Comprehensive wireless network scanner
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan1"
SCAN_TIME=30                    # seconds to scan
OUTPUT_DIR="/sd/loot/scans"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTPUT_FILE="$OUTPUT_DIR/scan_$TIMESTAMP"

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-b04.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Cleaning up..."
    # Kill airodump if running
    pkill -f airodump-ng 2>/dev/null
    # Disable monitor mode
    airmon-ng stop "${INTERFACE}mon" 2>/dev/null
    ip link set "$INTERFACE" up 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# ============================================
# INITIALIZATION
# ============================================
log "Starting PP-B04: Basic Scan"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check for required tools
for cmd in airmon-ng airodump-ng iw; do
    command -v $cmd >/dev/null 2>&1 || {
        log "ERROR: $cmd not found"
        exit 1
    }
done

# ============================================
# QUICK SCAN (MANAGED MODE)
# ============================================
log "Phase 1: Quick scan in managed mode..."

{
    echo "=============================================="
    echo "        WIRELESS NETWORK SCAN REPORT"
    echo "=============================================="
    echo "Scan Time: $(date)"
    echo "Interface: $INTERFACE"
    echo ""
    echo "=== QUICK SCAN (Managed Mode) ==="
    echo ""
} > "${OUTPUT_FILE}_report.txt"

# Use iw for quick scan
iw dev "$INTERFACE" scan 2>/dev/null | awk '
    /^BSS/ {bssid=$2; gsub(/\(.*/, "", bssid)}
    /SSID:/ {ssid=$2}
    /signal:/ {signal=$2}
    /primary channel:/ {channel=$3}
    /RSN:/ {encryption="WPA2"}
    /WPA:/ {encryption="WPA"}
    /capability:.*Privacy/ {if(!encryption) encryption="WEP"}
    /^$/ || /^BSS/ {
        if(bssid && ssid) {
            printf "%-32s %-18s Ch:%-3s Sig:%-4s %s\n", ssid, bssid, channel, signal, encryption
        }
        encryption=""
    }
' >> "${OUTPUT_FILE}_report.txt"

# ============================================
# ENABLE MONITOR MODE
# ============================================
log "Phase 2: Enabling monitor mode..."

# Kill interfering processes
airmon-ng check kill 2>/dev/null

# Start monitor mode
airmon-ng start "$INTERFACE" 2>/dev/null

# Determine monitor interface name
if ip link show "${INTERFACE}mon" >/dev/null 2>&1; then
    MON_INTERFACE="${INTERFACE}mon"
else
    MON_INTERFACE="${INTERFACE}"
fi

log "Monitor interface: $MON_INTERFACE"

# ============================================
# COMPREHENSIVE SCAN (MONITOR MODE)
# ============================================
log "Phase 3: Comprehensive scan for $SCAN_TIME seconds..."

echo "" >> "${OUTPUT_FILE}_report.txt"
echo "=== COMPREHENSIVE SCAN (Monitor Mode) ===" >> "${OUTPUT_FILE}_report.txt"
echo "" >> "${OUTPUT_FILE}_report.txt"

# Run airodump-ng
airodump-ng \
    --write "$OUTPUT_FILE" \
    --output-format csv,netxml \
    --write-interval 5 \
    "$MON_INTERFACE" &

AIRODUMP_PID=$!

# Wait for scan duration
sleep $SCAN_TIME

# Stop airodump
kill $AIRODUMP_PID 2>/dev/null
wait $AIRODUMP_PID 2>/dev/null

# ============================================
# PARSE AND FORMAT RESULTS
# ============================================
log "Phase 4: Processing results..."

CSV_FILE="${OUTPUT_FILE}-01.csv"

if [ -f "$CSV_FILE" ]; then
    # Parse access points
    echo "--- ACCESS POINTS ---" >> "${OUTPUT_FILE}_report.txt"
    printf "%-32s %-18s %-5s %-6s %-8s %-10s\n" \
        "SSID" "BSSID" "CH" "POWER" "ENC" "CLIENTS" >> "${OUTPUT_FILE}_report.txt"
    echo "--------------------------------------------------------------------------------" >> "${OUTPUT_FILE}_report.txt"

    # Process CSV (skip header, stop at empty line which separates APs from clients)
    awk -F',' '
        NR>2 && /^[0-9A-Fa-f:]/ && !/Station/ {
            bssid=$1
            channel=$4
            speed=$5
            power=$9
            privacy=$6
            cipher=$7
            auth=$8
            ssid=$14

            # Clean up fields
            gsub(/^ +| +$/, "", bssid)
            gsub(/^ +| +$/, "", ssid)
            gsub(/^ +| +$/, "", power)
            gsub(/^ +| +$/, "", privacy)

            if(bssid ~ /^[0-9A-Fa-f]/) {
                printf "%-32s %-18s %-5s %-6s %-8s\n", ssid, bssid, channel, power, privacy
            }
        }
    ' "$CSV_FILE" >> "${OUTPUT_FILE}_report.txt"

    # Parse clients
    echo "" >> "${OUTPUT_FILE}_report.txt"
    echo "--- CONNECTED CLIENTS ---" >> "${OUTPUT_FILE}_report.txt"
    printf "%-18s %-18s %-6s %-20s\n" \
        "CLIENT MAC" "AP BSSID" "POWER" "PROBES" >> "${OUTPUT_FILE}_report.txt"
    echo "--------------------------------------------------------------------------------" >> "${OUTPUT_FILE}_report.txt"

    # Find line number where client section starts
    client_start=$(grep -n "Station MAC" "$CSV_FILE" | cut -d: -f1)

    if [ -n "$client_start" ]; then
        tail -n +$((client_start + 1)) "$CSV_FILE" | awk -F',' '
            /^[0-9A-Fa-f:]/ {
                client=$1
                power=$4
                bssid=$6
                probes=$7

                gsub(/^ +| +$/, "", client)
                gsub(/^ +| +$/, "", bssid)
                gsub(/^ +| +$/, "", probes)

                if(client ~ /^[0-9A-Fa-f]/) {
                    printf "%-18s %-18s %-6s %-20s\n", client, bssid, power, substr(probes,1,20)
                }
            }
        ' >> "${OUTPUT_FILE}_report.txt"
    fi
fi

# ============================================
# STATISTICS
# ============================================
echo "" >> "${OUTPUT_FILE}_report.txt"
echo "=== SCAN STATISTICS ===" >> "${OUTPUT_FILE}_report.txt"

# Count networks
if [ -f "$CSV_FILE" ]; then
    TOTAL_APS=$(grep -c "^[0-9A-Fa-f][0-9A-Fa-f]:" "$CSV_FILE" | head -1)
    OPEN_APS=$(grep -i "OPN" "$CSV_FILE" | wc -l)
    WEP_APS=$(grep -i "WEP" "$CSV_FILE" | wc -l)
    WPA_APS=$(grep -i "WPA" "$CSV_FILE" | wc -l)
    CLIENTS=$(grep -c "Station MAC" "$CSV_FILE" 2>/dev/null || echo 0)

    echo "Total Access Points: $TOTAL_APS" >> "${OUTPUT_FILE}_report.txt"
    echo "Open Networks: $OPEN_APS" >> "${OUTPUT_FILE}_report.txt"
    echo "WEP Networks: $WEP_APS" >> "${OUTPUT_FILE}_report.txt"
    echo "WPA/WPA2 Networks: $WPA_APS" >> "${OUTPUT_FILE}_report.txt"
    echo "Total Clients Seen: $CLIENTS" >> "${OUTPUT_FILE}_report.txt"
fi

# ============================================
# DISPLAY AND SAVE
# ============================================
log "Scan complete!"
echo ""
cat "${OUTPUT_FILE}_report.txt"

echo ""
log "Results saved to:"
log "  Report: ${OUTPUT_FILE}_report.txt"
log "  CSV: ${OUTPUT_FILE}-01.csv"
log "  XML: ${OUTPUT_FILE}-01.kismet.netxml"

# Restore interface
cleanup
```

---

## Line-by-Line Breakdown

### Phase 1: Quick Scan (Managed Mode)
```bash
iw dev "$INTERFACE" scan
```
- Uses `iw` for quick wireless scan
- Works without monitor mode
- Returns beacon frames only

### Phase 2: Monitor Mode Setup
```bash
airmon-ng check kill
airmon-ng start "$INTERFACE"
```
| Command | Purpose |
|---------|---------|
| `check kill` | Stops processes that interfere with monitor mode |
| `start` | Enables monitor mode, creates wlanXmon interface |

### Phase 3: Comprehensive Scan
```bash
airodump-ng \
    --write "$OUTPUT_FILE" \
    --output-format csv,netxml \
    --write-interval 5 \
    "$MON_INTERFACE"
```
| Option | Purpose |
|--------|---------|
| `--write` | Output file prefix |
| `--output-format` | CSV and Kismet XML formats |
| `--write-interval` | Save every 5 seconds |

---

## Understanding the Output

### CSV File Format
```
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:DD:EE:FF, 2025-12-28 10:00:00, 2025-12-28 10:30:00, 6, 54, WPA2, CCMP, PSK, -50, 100, 0, 0.0.0.0, 8, HomeNetwork,
```

| Field | Description |
|-------|-------------|
| BSSID | Access point MAC address |
| channel | WiFi channel (1-14 for 2.4GHz) |
| Speed | Maximum supported speed |
| Privacy | Encryption type (OPN/WEP/WPA/WPA2) |
| Cipher | Encryption cipher (TKIP/CCMP) |
| Power | Signal strength (dBm, closer to 0 = stronger) |
| # beacons | Beacon frames captured |
| ESSID | Network name |

### Signal Strength Guide
| dBm | Quality |
|-----|---------|
| -30 to -50 | Excellent |
| -50 to -60 | Good |
| -60 to -70 | Fair |
| -70 to -80 | Weak |
| -80+ | Unusable |

---

## Channel Hopping

By default, airodump-ng hops through channels. Control this:

```bash
# Scan only channel 6
airodump-ng -c 6 wlan1mon

# Scan channels 1, 6, 11 only
airodump-ng -c 1,6,11 wlan1mon

# Scan 5GHz band
airodump-ng --band a wlan1mon

# Scan both bands
airodump-ng --band abg wlan1mon
```

---

## Enhanced Version: Targeted Scan

```bash
#!/bin/bash
# Targeted scan for specific network

TARGET_SSID="CorpNetwork"
TARGET_CHANNEL=""

# Find target channel first
echo "Searching for $TARGET_SSID..."
airodump-ng --write /tmp/search -o csv wlan1mon &
sleep 10
pkill airodump-ng

# Extract channel
TARGET_CHANNEL=$(grep "$TARGET_SSID" /tmp/search-01.csv | cut -d',' -f4 | tr -d ' ')

if [ -n "$TARGET_CHANNEL" ]; then
    echo "Found $TARGET_SSID on channel $TARGET_CHANNEL"

    # Focused scan on that channel
    airodump-ng -c "$TARGET_CHANNEL" \
        --essid "$TARGET_SSID" \
        --write "/sd/loot/$TARGET_SSID" \
        wlan1mon
else
    echo "Network not found"
fi
```

---

## Identifying Interesting Targets

### High-Value Networks
```bash
# Corporate networks often use these patterns
grep -iE "(corp|office|enterprise|business|internal)" scan.csv

# Guest networks (potential pivot point)
grep -iE "(guest|visitor|public)" scan.csv

# Default/unconfigured (potential vulns)
grep -iE "(linksys|netgear|dlink|default)" scan.csv
```

### Vulnerable Configurations
```bash
# Open networks
grep "OPN" scan.csv

# WEP networks (easily crackable)
grep "WEP" scan.csv

# WPS enabled (may be vulnerable)
# Check with wash tool
wash -i wlan1mon -C
```

---

## Red Team Perspective

### Scan Strategy
1. **Passive first** - Identify all networks without detection
2. **Note channels** - Map 2.4GHz and 5GHz usage
3. **Identify targets** - Corporate, guest, default names
4. **Client analysis** - Understand device population
5. **Hidden networks** - Probe for hidden SSIDs

### Maximizing Intelligence
```bash
# Long-duration passive scan
airodump-ng --write /sd/loot/survey \
    --output-format csv,netxml,pcap \
    wlan1mon

# Running for 24 hours captures:
# - All networks in range
# - Usage patterns
# - Client behaviors
# - Probe requests (reveal user's home networks)
```

---

## Blue Team Perspective

### Detection Methods

```bash
# Detect scanning activity
# Look for rapid channel changes
iw dev wlan0 info | grep channel

# Monitor for unusual probe requests
tshark -i wlan0 -Y "wlan.fc.type_subtype == 0x04" -T fields -e wlan.sa -e wlan_mgt.ssid
```

### Indicators of Scanning
1. **Interface in monitor mode** - Not connected to any AP
2. **Rapid channel hopping** - Covering all channels quickly
3. **No data transmission** - Only receiving
4. **Unknown MAC addresses** - New devices appearing briefly

### Sigma Rule
```yaml
title: Wireless Network Scanning Activity
status: experimental
description: Detects wireless scanning tools
logsource:
    product: linux
    service: syslog
detection:
    selection_tools:
        - 'airodump-ng'
        - 'wash'
        - 'iwlist scan'
        - 'monitor mode'
    condition: selection_tools
level: medium
tags:
    - attack.discovery
    - attack.t1595
```

---

## Practice Exercises

### Exercise 1: Channel Analysis
Create a script that shows which channels are most congested.

### Exercise 2: Signal Mapping
Plot signal strength of target network over time.

### Exercise 3: Client Profiling
Parse probe requests to build profiles of nearby devices.

---

## Payload File

Save as `PP-B04_Basic_Scan.sh`:

```bash
#!/bin/bash
# PP-B04: Basic Scan (Compact)
airmon-ng check kill && airmon-ng start wlan1
airodump-ng --write /tmp/scan -o csv wlan1mon &
sleep 30 && pkill airodump-ng
cat /tmp/scan-01.csv
airmon-ng stop wlan1mon
```

---

[← PP-B03 Client Alert](PP-B03_Client_Alert.md) | [Back to Basic Payloads](README.md) | [Next: PP-B05 Deauth Test →](PP-B05_Deauth_Test.md)
