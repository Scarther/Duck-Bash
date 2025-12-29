# Recon Suite Reference

## Overview

The Recon suite provides comprehensive wireless reconnaissance capabilities for the WiFi Pineapple. It enables passive and active scanning, client discovery, probe harvesting, and network mapping for intelligence gathering.

---

## Recon Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RECON ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────────────────────────────────────────┐       │
│   │                 RECON ENGINE                     │       │
│   │      (Coordinates all scanning operations)       │       │
│   └───────────────────┬─────────────────────────────┘       │
│                       │                                      │
│   ┌───────────────────┴─────────────────────────────┐       │
│   │                                                   │       │
│   ▼                   ▼                   ▼          │       │
│ ┌─────────┐     ┌─────────┐       ┌─────────────┐   │       │
│ │ Passive │     │ Active  │       │   Client    │   │       │
│ │  Scan   │     │  Scan   │       │  Discovery  │   │       │
│ └─────────┘     └─────────┘       └─────────────┘   │       │
│                                                              │
│   CAPABILITIES:                                              │
│   ├── AP Discovery - Find access points                     │
│   ├── Client Discovery - Find wireless clients              │
│   ├── Probe Harvesting - Collect SSID requests              │
│   ├── Channel Hopping - Multi-channel scanning              │
│   ├── Signal Analysis - RSSI tracking                       │
│   └── Network Mapping - Relationship visualization          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Scanning Modes

### 1. Passive Scanning

Monitor traffic without transmitting.

```bash
#!/bin/bash
# Passive wireless reconnaissance

INTERFACE="wlan1"
OUTPUT="/sd/loot/recon_$(date +%s)"
DURATION="${1:-300}"  # 5 minutes default

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# Setup monitor mode
log "Enabling monitor mode on $INTERFACE"
airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

# Verify
if ! iw dev "$MON" info >/dev/null 2>&1; then
    log "ERROR: Failed to enable monitor mode"
    exit 1
fi

log "Starting passive scan for $DURATION seconds"
log "Output: $OUTPUT"

# Passive scan - no probes sent
timeout "$DURATION" airodump-ng \
    --output-format csv,kismet,pcap \
    --write "$OUTPUT" \
    --write-interval 30 \
    "$MON" 2>/dev/null

# Cleanup
airmon-ng stop "$MON" >/dev/null 2>&1

log "Scan complete"

# Parse results
if [ -f "${OUTPUT}-01.csv" ]; then
    log "Networks found: $(grep -c "^[0-9A-F]" "${OUTPUT}-01.csv" 2>/dev/null || echo 0)"
    log "Clients found: $(grep -c "Station MAC" "${OUTPUT}-01.csv" 2>/dev/null || echo 0)"
fi
```

### 2. Active Scanning

Send probe requests to discover hidden networks.

```bash
#!/bin/bash
# Active wireless scanning with probes

INTERFACE="wlan1"
OUTPUT="/sd/loot/active_scan_$(date +%s)"

# Setup
airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

# Active scan with probes
airodump-ng \
    --band abg \
    --output-format csv \
    --write "$OUTPUT" \
    "$MON" &
SCAN_PID=$!

# Wait then stop
sleep 120
kill $SCAN_PID 2>/dev/null

# Also scan with iw (sends probes)
iw dev wlan0 scan > "${OUTPUT}_iw.txt" 2>/dev/null

airmon-ng stop "$MON" >/dev/null 2>&1
```

### 3. Targeted Scanning

Focus on specific networks or channels.

```bash
#!/bin/bash
# Targeted channel/BSSID scan

TARGET_CHANNEL="${1:-6}"
TARGET_BSSID="${2:-}"
INTERFACE="wlan1"
OUTPUT="/sd/loot/targeted_$(date +%s)"

airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

# Build command
CMD="airodump-ng -c $TARGET_CHANNEL"

if [ -n "$TARGET_BSSID" ]; then
    CMD="$CMD --bssid $TARGET_BSSID"
fi

CMD="$CMD -w $OUTPUT $MON"

# Run scan
timeout 300 $CMD 2>/dev/null

airmon-ng stop "$MON" >/dev/null 2>&1
```

---

## Client Discovery

### Connected Client Monitor

```bash
#!/bin/bash
# Monitor connected clients in real-time

INTERVAL="${1:-10}"
LOG="/sd/loot/clients/$(date +%Y%m%d).log"

mkdir -p "$(dirname $LOG)"

echo "Monitoring clients every ${INTERVAL}s..."
echo "Log: $LOG"

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    echo "=== $TIMESTAMP ===" >> "$LOG"

    # DHCP leases
    if [ -f /tmp/dnsmasq.leases ]; then
        while read ts mac ip hostname clientid; do
            # Get OUI vendor (first 3 octets)
            OUI=$(echo "$mac" | cut -d: -f1-3 | tr ':' '-' | tr 'a-f' 'A-F')

            echo "CLIENT: $mac | $ip | $hostname | OUI: $OUI" >> "$LOG"
            echo "  MAC: $mac  IP: $ip  Host: $hostname"
        done < /tmp/dnsmasq.leases
    fi

    # hostapd stations
    if command -v hostapd_cli >/dev/null 2>&1; then
        hostapd_cli -i wlan0 all_sta 2>/dev/null | grep -E "^[0-9a-f]" >> "$LOG"
    fi

    # ARP table
    arp -n 2>/dev/null | grep -v "incomplete" >> "$LOG"

    echo "" >> "$LOG"
    sleep "$INTERVAL"
done
```

### Wireless Client Detection

```bash
#!/bin/bash
# Detect wireless clients via probe requests

INTERFACE="wlan1"
OUTPUT="/sd/loot/clients_$(date +%s).txt"
DURATION="${1:-300}"

airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

echo "Capturing client probe requests for ${DURATION}s..."

# Capture only probe requests (type 0, subtype 4)
timeout "$DURATION" tcpdump -i "$MON" -n -e \
    'type mgt subtype probe-req' 2>/dev/null | \
    tee "$OUTPUT" | while read line; do
        # Extract client MAC and SSID
        MAC=$(echo "$line" | grep -oE "[0-9a-f:]{17}" | head -1)
        SSID=$(echo "$line" | grep -oE "Probe Request \([^)]+\)" | sed 's/.*(\(.*\))/\1/')

        if [ -n "$MAC" ]; then
            echo "[$(date '+%H:%M:%S')] $MAC probing for: $SSID"
        fi
    done

airmon-ng stop "$MON" >/dev/null 2>&1
echo "Results saved to: $OUTPUT"
```

---

## Probe Harvesting

### Collect Probe Requests

```bash
#!/bin/bash
# Harvest probe requests for SSID intelligence

INTERFACE="wlan1"
PROBE_LOG="/sd/loot/probes/$(date +%Y%m%d).log"
SSID_LIST="/sd/loot/probes/ssids.txt"

mkdir -p "$(dirname $PROBE_LOG)"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# Setup
airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

log "Starting probe harvester on $MON"

# Capture and parse probe requests
tcpdump -i "$MON" -n -e -l \
    'type mgt subtype probe-req' 2>/dev/null | while read line; do

    # Extract data
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    MAC=$(echo "$line" | grep -oE "[0-9a-f:]{17}" | head -1)
    SIGNAL=$(echo "$line" | grep -oE "[-][0-9]+dBm" | head -1)

    # Extract SSID (between parentheses after "Probe Request")
    SSID=$(echo "$line" | sed -n 's/.*Probe Request (\([^)]*\)).*/\1/p')

    if [ -n "$MAC" ] && [ -n "$SSID" ] && [ "$SSID" != "Broadcast" ]; then
        # Log probe
        echo "$TIMESTAMP,$MAC,$SSID,$SIGNAL" >> "$PROBE_LOG"

        # Add to unique SSID list
        if ! grep -qF "$SSID" "$SSID_LIST" 2>/dev/null; then
            echo "$SSID" >> "$SSID_LIST"
            log "NEW SSID: $SSID (from $MAC)"
        fi
    fi
done
```

### Probe Analysis Script

```bash
#!/bin/bash
# Analyze harvested probes

PROBE_LOG="${1:-/sd/loot/probes/*.log}"
OUTPUT="/sd/loot/probes/analysis_$(date +%s).txt"

{
    echo "=========================================="
    echo "Probe Request Analysis"
    echo "Generated: $(date)"
    echo "=========================================="

    # Count total probes
    TOTAL=$(cat $PROBE_LOG 2>/dev/null | wc -l)
    echo -e "\nTotal probe requests: $TOTAL"

    # Unique clients
    echo -e "\n=== Unique Clients (by MAC) ==="
    cat $PROBE_LOG 2>/dev/null | cut -d',' -f2 | sort -u | while read mac; do
        COUNT=$(grep -c "$mac" $PROBE_LOG 2>/dev/null)
        SSIDS=$(grep "$mac" $PROBE_LOG 2>/dev/null | cut -d',' -f3 | sort -u | tr '\n' ',' | sed 's/,$//')
        echo "  $mac ($COUNT probes) - Networks: $SSIDS"
    done

    # Top SSIDs
    echo -e "\n=== Top 20 Requested SSIDs ==="
    cat $PROBE_LOG 2>/dev/null | cut -d',' -f3 | sort | uniq -c | sort -rn | head -20 | \
        while read count ssid; do
            echo "  $count - $ssid"
        done

    # Potential corporate networks
    echo -e "\n=== Potential Corporate/Sensitive Networks ==="
    cat $PROBE_LOG 2>/dev/null | cut -d',' -f3 | sort -u | \
        grep -iE "(corp|secure|vpn|internal|private|admin|employee)" | \
        while read ssid; do
            COUNT=$(grep -c "$ssid" $PROBE_LOG 2>/dev/null)
            echo "  $ssid ($COUNT requests)"
        done

    # Activity timeline
    echo -e "\n=== Activity by Hour ==="
    cat $PROBE_LOG 2>/dev/null | cut -d',' -f1 | cut -d' ' -f2 | cut -d':' -f1 | \
        sort | uniq -c | while read count hour; do
            BAR=$(printf '%*s' "$((count/10))" '' | tr ' ' '#')
            printf "  %s:00 - %5d %s\n" "$hour" "$count" "$BAR"
        done

} | tee "$OUTPUT"

echo -e "\nAnalysis saved to: $OUTPUT"
```

---

## Network Discovery

### Comprehensive Network Scan

```bash
#!/bin/bash
# Full network reconnaissance

INTERFACE="wlan1"
LOOT_DIR="/sd/loot/recon_$(date +%Y%m%d_%H%M%S)"
SCAN_TIME="${1:-600}"  # 10 minutes

mkdir -p "$LOOT_DIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOOT_DIR/scan.log"
}

# Setup
log "Starting comprehensive network scan"
airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

# Scan all bands
log "Scanning 2.4GHz and 5GHz bands..."
timeout "$SCAN_TIME" airodump-ng \
    --band abg \
    --manufacturer \
    --wps \
    --output-format csv,kismet,pcap \
    --write "$LOOT_DIR/scan" \
    "$MON" 2>/dev/null &
SCAN_PID=$!

# Wait for scan
wait $SCAN_PID

# Cleanup
airmon-ng stop "$MON" >/dev/null 2>&1

# Process results
log "Processing results..."

if [ -f "$LOOT_DIR/scan-01.csv" ]; then
    # Parse APs
    log "Parsing access points..."
    grep -E "^[0-9A-F]" "$LOOT_DIR/scan-01.csv" 2>/dev/null | \
        awk -F',' '{print $1","$4","$6","$14}' | \
        sed 's/^ *//;s/ *$//' > "$LOOT_DIR/access_points.csv"

    # Parse clients
    log "Parsing clients..."
    grep "Station MAC" -A 10000 "$LOOT_DIR/scan-01.csv" 2>/dev/null | \
        grep -E "^[0-9A-F]" | \
        awk -F',' '{print $1","$6","$7}' > "$LOOT_DIR/clients.csv"

    # Count results
    AP_COUNT=$(wc -l < "$LOOT_DIR/access_points.csv")
    CLIENT_COUNT=$(wc -l < "$LOOT_DIR/clients.csv")

    log "Found $AP_COUNT access points and $CLIENT_COUNT clients"
fi

# Generate summary
cat > "$LOOT_DIR/summary.txt" << EOF
Network Reconnaissance Summary
==============================
Scan Duration: $SCAN_TIME seconds
Timestamp: $(date)
Interface: $INTERFACE

Results:
- Access Points: $AP_COUNT
- Wireless Clients: $CLIENT_COUNT

Files:
- scan-01.csv (raw airodump output)
- access_points.csv (parsed APs)
- clients.csv (parsed clients)
- scan-01.cap (packet capture)

Top Networks by Signal:
$(cat "$LOOT_DIR/access_points.csv" | sort -t',' -k2 -rn | head -10)
EOF

log "Scan complete. Results in: $LOOT_DIR"
```

### Hidden Network Detection

```bash
#!/bin/bash
# Detect hidden (non-broadcasting) networks

INTERFACE="wlan1"
OUTPUT="/sd/loot/hidden_$(date +%s).txt"

airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

echo "Scanning for hidden networks..."
echo "Hidden networks detected:" > "$OUTPUT"
echo "=========================" >> "$OUTPUT"

# Scan and look for empty SSID fields
timeout 300 airodump-ng --output-format csv --write /tmp/hidden_scan "$MON" 2>/dev/null &
SCAN_PID=$!

sleep 300
kill $SCAN_PID 2>/dev/null

# Parse for hidden networks (empty ESSID)
if [ -f /tmp/hidden_scan-01.csv ]; then
    grep -E "^[0-9A-F].*,\s*," /tmp/hidden_scan-01.csv | while read line; do
        BSSID=$(echo "$line" | cut -d',' -f1)
        CHANNEL=$(echo "$line" | cut -d',' -f4)
        SIGNAL=$(echo "$line" | cut -d',' -f9)

        echo "BSSID: $BSSID | Channel: $CHANNEL | Signal: $SIGNAL dBm" >> "$OUTPUT"
        echo "Found hidden network: $BSSID"
    done
fi

airmon-ng stop "$MON" >/dev/null 2>&1
rm -f /tmp/hidden_scan*

echo "Results saved to: $OUTPUT"
```

---

## Signal Analysis

### RSSI Tracking

```bash
#!/bin/bash
# Track signal strength over time

TARGET_BSSID="${1:?Usage: $0 BSSID}"
INTERFACE="wlan1"
OUTPUT="/sd/loot/rssi_$(echo $TARGET_BSSID | tr ':' '_')_$(date +%s).csv"
DURATION="${2:-300}"

airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

echo "Tracking RSSI for $TARGET_BSSID..."
echo "timestamp,rssi" > "$OUTPUT"

END_TIME=$(($(date +%s) + DURATION))

while [ $(date +%s) -lt $END_TIME ]; do
    # Get current RSSI from quick scan
    RSSI=$(iw dev "$MON" scan 2>/dev/null | \
           grep -A 5 "$TARGET_BSSID" | \
           grep "signal:" | \
           awk '{print $2}')

    if [ -n "$RSSI" ]; then
        echo "$(date +%s),$RSSI" >> "$OUTPUT"
        echo "[$(date '+%H:%M:%S')] $TARGET_BSSID: $RSSI dBm"
    fi

    sleep 5
done

airmon-ng stop "$MON" >/dev/null 2>&1
echo "RSSI data saved to: $OUTPUT"
```

### Signal Strength Heatmap Data

```bash
#!/bin/bash
# Collect signal data for heatmap generation

INTERFACE="wlan1"
OUTPUT_DIR="/sd/loot/heatmap_$(date +%Y%m%d)"
INTERVAL="${1:-30}"

mkdir -p "$OUTPUT_DIR"

airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

echo "Collecting heatmap data every ${INTERVAL}s..."
echo "Press Ctrl+C when ready to move to new position"

POSITION=0

while true; do
    POSITION=$((POSITION + 1))
    TIMESTAMP=$(date +%s)

    echo -e "\n=== Position $POSITION ($(date)) ==="
    echo "Scanning..."

    # Quick scan
    iw dev "$MON" scan 2>/dev/null | \
        grep -E "BSS |signal:" | \
        paste - - | \
        awk -v pos="$POSITION" -v ts="$TIMESTAMP" \
        '{gsub(/BSS /,"",$1); gsub(/signal: /,"",$3); print ts","pos","$1","$3}' \
        >> "$OUTPUT_DIR/heatmap_data.csv"

    echo "Position $POSITION captured. Move to next position and wait..."
    sleep "$INTERVAL"
done
```

---

## API Integration

### Recon API Endpoints

```bash
# Base URL
API="http://172.16.42.1:1471/api"

# Start recon scan
curl -s -X POST "$API/recon/start" -d "duration=300"

# Stop scan
curl -s -X POST "$API/recon/stop"

# Get scan status
curl -s "$API/recon/status"

# Get results
curl -s "$API/recon/results"

# Get specific AP info
curl -s "$API/recon/ap?bssid=AA:BB:CC:DD:EE:FF"

# Get clients
curl -s "$API/recon/clients"

# Export results
curl -s "$API/recon/export?format=csv" -o recon_results.csv
```

### Automated Recon via API

```bash
#!/bin/bash
# Automated recon using API

API="http://172.16.42.1:1471/api"

start_recon() {
    curl -s -X POST "$API/recon/start" -d "duration=300&band=abg"
}

wait_for_completion() {
    while true; do
        STATUS=$(curl -s "$API/recon/status" | grep -o '"scanning":[^,]*' | cut -d: -f2)
        if [ "$STATUS" = "false" ]; then
            break
        fi
        sleep 10
    done
}

get_results() {
    curl -s "$API/recon/results"
}

# Execute
echo "Starting recon..."
start_recon
echo "Waiting for scan to complete..."
wait_for_completion
echo "Results:"
get_results | python3 -m json.tool
```

---

## Output Formats

### CSV Parsing

```bash
#!/bin/bash
# Parse airodump CSV output

CSV_FILE="${1:?Usage: $0 csvfile}"

echo "=== Access Points ==="
echo "BSSID,Channel,Privacy,ESSID"

# APs are before the blank line
sed -n '2,/^$/p' "$CSV_FILE" | head -n -1 | while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip essid key; do
    # Clean whitespace
    bssid=$(echo "$bssid" | xargs)
    channel=$(echo "$channel" | xargs)
    privacy=$(echo "$privacy" | xargs)
    essid=$(echo "$essid" | xargs)

    echo "$bssid,$channel,$privacy,$essid"
done

echo -e "\n=== Clients ==="
echo "Station MAC,Associated BSSID,Probed ESSIDs"

# Clients are after "Station MAC" header
sed -n '/Station MAC/,$p' "$CSV_FILE" | tail -n +2 | while IFS=',' read -r station first_seen last_seen power packets bssid probed; do
    station=$(echo "$station" | xargs)
    bssid=$(echo "$bssid" | xargs)
    probed=$(echo "$probed" | xargs)

    echo "$station,$bssid,$probed"
done
```

### JSON Export

```bash
#!/bin/bash
# Export recon results as JSON

CSV_FILE="${1:?Usage: $0 csvfile}"
JSON_FILE="${2:-results.json}"

{
    echo '{'
    echo '  "timestamp": "'$(date -Iseconds)'",'
    echo '  "access_points": ['

    FIRST=1
    sed -n '2,/^$/p' "$CSV_FILE" | head -n -1 | while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip essid key; do
        bssid=$(echo "$bssid" | xargs)
        channel=$(echo "$channel" | xargs)
        privacy=$(echo "$privacy" | xargs)
        essid=$(echo "$essid" | xargs | sed 's/"/\\"/g')
        power=$(echo "$power" | xargs)

        [ $FIRST -eq 0 ] && echo ','
        FIRST=0

        echo '    {'
        echo '      "bssid": "'$bssid'",'
        echo '      "essid": "'$essid'",'
        echo '      "channel": '$channel','
        echo '      "privacy": "'$privacy'",'
        echo '      "signal": '$power
        echo -n '    }'
    done

    echo -e '\n  ],'
    echo '  "clients": ['

    FIRST=1
    sed -n '/Station MAC/,$p' "$CSV_FILE" | tail -n +2 | while IFS=',' read -r station first_seen last_seen power packets bssid probed; do
        station=$(echo "$station" | xargs)
        bssid=$(echo "$bssid" | xargs)
        probed=$(echo "$probed" | xargs | sed 's/"/\\"/g')

        [ $FIRST -eq 0 ] && echo ','
        FIRST=0

        echo '    {'
        echo '      "mac": "'$station'",'
        echo '      "associated_bssid": "'$bssid'",'
        echo '      "probed_networks": "'$probed'"'
        echo -n '    }'
    done

    echo -e '\n  ]'
    echo '}'
} > "$JSON_FILE"

echo "JSON exported to: $JSON_FILE"
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────┐
│                 RECON SUITE QUICK REFERENCE                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  SCAN TYPES:                                                 │
│    Passive   - Monitor only, no transmit                    │
│    Active    - Send probe requests                          │
│    Targeted  - Focus on specific channel/BSSID              │
│                                                              │
│  KEY COMMANDS:                                               │
│    airmon-ng start wlan1        - Enable monitor mode       │
│    airodump-ng wlan1mon         - Scan networks             │
│    airodump-ng -c 6 wlan1mon    - Scan specific channel    │
│    airodump-ng --band abg       - All bands (2.4/5GHz)     │
│    iw dev wlan0 scan            - Quick scan (active)       │
│                                                              │
│  OUTPUT FILES:                                               │
│    *-01.csv     - CSV with APs and clients                 │
│    *-01.cap     - Packet capture                           │
│    *-01.kismet  - Kismet format                            │
│                                                              │
│  PROBE HARVESTING:                                           │
│    tcpdump 'type mgt subtype probe-req'                    │
│    Parse for MAC + SSID pairs                               │
│                                                              │
│  ANALYSIS:                                                   │
│    - Count unique SSIDs                                      │
│    - Identify corporate networks                            │
│    - Track client-AP associations                           │
│    - Monitor signal strength                                │
│                                                              │
│  API ENDPOINTS:                                              │
│    POST /recon/start                                        │
│    POST /recon/stop                                         │
│    GET  /recon/status                                       │
│    GET  /recon/results                                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← Payloads Suite](10_Payloads_Suite.md) | [Back to Fundamentals](README.md) | [Next: PineAP Suite →](05_PineAP_Module.md)
