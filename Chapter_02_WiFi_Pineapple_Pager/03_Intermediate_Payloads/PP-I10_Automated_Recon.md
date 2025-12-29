# PP-I10: Automated Recon

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I10 |
| **Name** | Automated Recon |
| **Difficulty** | Intermediate |
| **Type** | Recon |
| **Purpose** | Scheduled reconnaissance |
| **MITRE ATT&CK** | T1595 (Active Scanning) |

## What This Payload Does

Runs automated reconnaissance on a schedule, capturing network snapshots, probe requests, and client information over time.

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I10
# Name: Automated Recon
# Description: Scheduled reconnaissance
# Author: Security Training
#

INTERFACE="wlan1"
OUTPUT_DIR="/sd/loot/recon"
SCAN_DURATION=60
SCAN_INTERVAL=300  # 5 minutes

mkdir -p "$OUTPUT_DIR"

echo "Automated Recon Started"
echo "Scan every ${SCAN_INTERVAL}s for ${SCAN_DURATION}s each"

# Enable monitor mode
airmon-ng start "$INTERFACE" 2>/dev/null
MON="${INTERFACE}mon"

while true; do
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

    echo "[$(date)] Running scan..."

    timeout $SCAN_DURATION airodump-ng \
        -w "$OUTPUT_DIR/scan_$TIMESTAMP" \
        -o csv,netxml \
        "$MON" 2>/dev/null

    # Parse and summarize
    if [ -f "$OUTPUT_DIR/scan_${TIMESTAMP}-01.csv" ]; then
        APS=$(grep -c "^[0-9A-Fa-f]" "$OUTPUT_DIR/scan_${TIMESTAMP}-01.csv" 2>/dev/null)
        echo "  Found $APS access points"
    fi

    sleep $SCAN_INTERVAL
done
```

---

## Cron-Based Scheduling

```bash
# Add to crontab
crontab -e

# Run every hour
0 * * * * /root/payloads/PP-I10_Automated_Recon.sh

# Run at specific times
0 9,12,17 * * * /root/payloads/PP-I10_Automated_Recon.sh
```

---

## Payload File

Save as `PP-I10_Automated_Recon.sh`:

```bash
#!/bin/bash
# PP-I10: Automated Recon (Compact)
while true; do
    timeout 60 airodump-ng -w /sd/loot/scan_$(date +%s) -o csv wlan1mon 2>/dev/null
    sleep 300
done
```

---

[← PP-I09 Traffic Capture](PP-I09_Traffic_Capture.md) | [Back to Intermediate](README.md) | [Next: Advanced Payloads →](../04_Advanced_Payloads/README.md)
