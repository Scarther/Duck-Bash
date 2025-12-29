#!/bin/bash
#####################################################
# Payload: PP-B04 - Network Scanner
# Device:  WiFi Pineapple Pager
# Type:    User Payload
# Author:  Ducky_Bash Training Repository
# Version: 1.0
#
# Description:
# Scans for nearby WiFi networks and counts them.
# Basic reconnaissance payload.
#
# MITRE ATT&CK: T1016 (System Network Configuration Discovery)
# Documentation: Chapter_02/02_Basic_Payloads/PP-B04_Network_Scan.md
#####################################################

# ===== CONFIGURATION =====
INTERFACE="wlan0"
SCAN_TIME=15
LOOT_DIR="/root/loot/scans"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$LOOT_DIR/scan_$TIMESTAMP.txt"

# ===== SETUP =====
mkdir -p "$LOOT_DIR"

# ===== MAIN =====
LED BLUE
NOTIFY "Starting network scan..."

# Enable monitor mode
airmon-ng start "$INTERFACE" > /dev/null 2>&1
MON_IF="${INTERFACE}mon"

# Perform scan
timeout "$SCAN_TIME" airodump-ng "$MON_IF" -w /tmp/scan --output-format csv > /dev/null 2>&1

# Process results
if [ -f /tmp/scan-01.csv ]; then
    echo "=== WiFi Scan Results ===" > "$OUTPUT_FILE"
    echo "Scan Time: $(date)" >> "$OUTPUT_FILE"
    echo "Duration: ${SCAN_TIME}s" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "BSSID | Channel | ESSID" >> "$OUTPUT_FILE"
    echo "-------------------------------" >> "$OUTPUT_FILE"

    # Parse CSV (skip header, extract BSSID, Channel, ESSID)
    tail -n +3 /tmp/scan-01.csv | \
    grep -E "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | \
    cut -d',' -f1,4,14 | \
    sed 's/,/ | /g' >> "$OUTPUT_FILE"

    # Count networks
    NETWORK_COUNT=$(grep -c "|" "$OUTPUT_FILE" 2>/dev/null || echo "0")

    LED GREEN
    NOTIFY "Scan complete: $NETWORK_COUNT networks"
else
    LED RED
    NOTIFY "Scan failed!"
    echo "Scan failed at $(date)" > "$OUTPUT_FILE"
fi

# ===== CLEANUP =====
airmon-ng stop "$MON_IF" > /dev/null 2>&1
rm -f /tmp/scan-01.csv

sleep 2
LED OFF

exit 0
