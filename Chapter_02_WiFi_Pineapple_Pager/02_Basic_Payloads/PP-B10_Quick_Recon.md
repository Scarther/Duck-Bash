# PP-B10: Quick Recon

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B10 |
| **Name** | Quick Recon |
| **Difficulty** | Basic |
| **Type** | Recon |
| **Purpose** | Fast wireless environment summary |
| **MITRE ATT&CK** | T1595 (Active Scanning) |

## What This Payload Does

Performs a rapid reconnaissance of the wireless environment, providing a quick summary of nearby networks, clients, and potential targets in under 60 seconds.

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B10
# Name: Quick Recon
# Description: Fast wireless environment summary
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan1"
SCAN_DURATION=15              # Quick 15-second scan
OUTPUT_DIR="/sd/loot/recon"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTPUT_FILE="$OUTPUT_DIR/quick_recon_$TIMESTAMP.txt"

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-b10.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    pkill -f airodump-ng 2>/dev/null
    airmon-ng stop "${INTERFACE}mon" 2>/dev/null
    ip link set "$INTERFACE" up 2>/dev/null
}

trap cleanup EXIT

# ============================================
# MAIN
# ============================================
log "Starting PP-B10: Quick Recon"

mkdir -p "$OUTPUT_DIR"

{
    echo "╔════════════════════════════════════════════════════╗"
    echo "║           QUICK WIRELESS RECON                     ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Duration: ${SCAN_DURATION}s"
    echo ""
} | tee "$OUTPUT_FILE"

# ============================================
# ENABLE MONITOR MODE
# ============================================
log "Enabling monitor mode..."
airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$INTERFACE" >/dev/null 2>&1

if ip link show "${INTERFACE}mon" >/dev/null 2>&1; then
    MON_INTERFACE="${INTERFACE}mon"
else
    MON_INTERFACE="${INTERFACE}"
fi

# ============================================
# QUICK SCAN
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
echo " SCANNING ($SCAN_DURATION seconds)..." | tee -a "$OUTPUT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"

SCAN_PREFIX="/tmp/quickrecon_$$"

# Run quick scan
timeout $SCAN_DURATION airodump-ng \
    --write "$SCAN_PREFIX" \
    --output-format csv \
    --write-interval 5 \
    "$MON_INTERFACE" >/dev/null 2>&1

CSV_FILE="${SCAN_PREFIX}-01.csv"

# ============================================
# PARSE RESULTS
# ============================================
if [ ! -f "$CSV_FILE" ]; then
    echo "ERROR: Scan failed - no output generated" | tee -a "$OUTPUT_FILE"
    exit 1
fi

# Count totals
TOTAL_APS=$(awk -F',' '/^[0-9A-Fa-f]/ && !/Station/ {count++} END {print count+0}' "$CSV_FILE")
OPEN_APS=$(grep -c "OPN" "$CSV_FILE" 2>/dev/null || echo 0)
WEP_APS=$(grep -c " WEP" "$CSV_FILE" 2>/dev/null || echo 0)
WPA_APS=$(grep -ic "WPA" "$CSV_FILE" 2>/dev/null || echo 0)

# Client section starts after "Station MAC"
CLIENT_LINE=$(grep -n "Station MAC" "$CSV_FILE" | cut -d: -f1)
if [ -n "$CLIENT_LINE" ]; then
    TOTAL_CLIENTS=$(tail -n +$((CLIENT_LINE + 1)) "$CSV_FILE" | grep -c "^[0-9A-Fa-f]" || echo 0)
else
    TOTAL_CLIENTS=0
fi

{
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " SUMMARY"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Access Points:  $TOTAL_APS"
    echo "    ├── Open:     $OPEN_APS"
    echo "    ├── WEP:      $WEP_APS"
    echo "    └── WPA/WPA2: $WPA_APS"
    echo ""
    echo "  Clients:        $TOTAL_CLIENTS"
    echo ""
} | tee -a "$OUTPUT_FILE"

# ============================================
# TOP NETWORKS (by signal)
# ============================================
{
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " TOP 10 NETWORKS (by signal strength)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    printf "  %-24s %-18s %-4s %-6s %-8s\n" "SSID" "BSSID" "CH" "PWR" "ENC"
    echo "  ────────────────────────────────────────────────────────────"
} | tee -a "$OUTPUT_FILE"

# Parse and sort by power (column 9)
awk -F',' '
    NR>2 && /^[0-9A-Fa-f]/ && !/Station/ {
        bssid=$1
        channel=$4
        power=$9
        privacy=$6
        ssid=$14

        # Clean fields
        gsub(/^ +| +$/, "", bssid)
        gsub(/^ +| +$/, "", ssid)
        gsub(/^ +| +$/, "", power)
        gsub(/^ +| +$/, "", privacy)
        gsub(/^ +| +$/, "", channel)

        if(ssid == "") ssid = "<hidden>"
        if(length(ssid) > 22) ssid = substr(ssid,1,22)".."

        # Store with power for sorting
        if(power ~ /^-?[0-9]+$/) {
            printf "%d|%-24s|%-18s|%-4s|%-6s|%-8s\n", power, ssid, bssid, channel, power, privacy
        }
    }
' "$CSV_FILE" | sort -t'|' -k1 -nr | head -10 | while IFS='|' read pwr ssid bssid ch power enc; do
    printf "  %-24s %-18s %-4s %-6s %-8s\n" "$ssid" "$bssid" "$ch" "$power" "$enc"
done | tee -a "$OUTPUT_FILE"

# ============================================
# OPEN NETWORKS
# ============================================
{
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " OPEN NETWORKS (no encryption)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
} | tee -a "$OUTPUT_FILE"

OPEN_COUNT=$(grep "OPN" "$CSV_FILE" | wc -l)

if [ "$OPEN_COUNT" -gt 0 ]; then
    grep "OPN" "$CSV_FILE" | awk -F',' '{
        ssid=$14
        bssid=$1
        channel=$4
        power=$9
        gsub(/^ +| +$/, "", ssid)
        gsub(/^ +| +$/, "", bssid)
        if(ssid == "") ssid = "<hidden>"
        printf "  ⚠ %-24s %-18s CH:%-3s PWR:%s\n", ssid, bssid, channel, power
    }' | head -10 | tee -a "$OUTPUT_FILE"
else
    echo "  None found" | tee -a "$OUTPUT_FILE"
fi

# ============================================
# WEP NETWORKS
# ============================================
{
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " WEP NETWORKS (easily crackable)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
} | tee -a "$OUTPUT_FILE"

WEP_COUNT=$(grep " WEP" "$CSV_FILE" | wc -l)

if [ "$WEP_COUNT" -gt 0 ]; then
    grep " WEP" "$CSV_FILE" | awk -F',' '{
        ssid=$14
        bssid=$1
        channel=$4
        ivs=$11
        gsub(/^ +| +$/, "", ssid)
        gsub(/^ +| +$/, "", bssid)
        printf "  ⚠ %-24s %-18s CH:%-3s IVs:%s\n", ssid, bssid, channel, ivs
    }' | head -10 | tee -a "$OUTPUT_FILE"
else
    echo "  None found" | tee -a "$OUTPUT_FILE"
fi

# ============================================
# ACTIVE CLIENTS
# ============================================
{
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " ACTIVE CLIENTS (with associated AP)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
} | tee -a "$OUTPUT_FILE"

if [ -n "$CLIENT_LINE" ] && [ "$TOTAL_CLIENTS" -gt 0 ]; then
    tail -n +$((CLIENT_LINE + 1)) "$CSV_FILE" | awk -F',' '
        /^[0-9A-Fa-f]/ && $6 !~ /not associated/ {
            client=$1
            bssid=$6
            power=$4
            probes=$7

            gsub(/^ +| +$/, "", client)
            gsub(/^ +| +$/, "", bssid)
            gsub(/^ +| +$/, "", probes)

            if(bssid ~ /^[0-9A-Fa-f]/) {
                printf "  %-18s → %-18s (PWR: %s)\n", client, bssid, power
            }
        }
    ' | head -15 | tee -a "$OUTPUT_FILE"
else
    echo "  No associated clients found" | tee -a "$OUTPUT_FILE"
fi

# ============================================
# PROBE REQUESTS
# ============================================
{
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " PROBE REQUESTS (SSIDs devices are looking for)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
} | tee -a "$OUTPUT_FILE"

if [ -n "$CLIENT_LINE" ]; then
    tail -n +$((CLIENT_LINE + 1)) "$CSV_FILE" | awk -F',' '
        $7 != "" && $7 !~ /^[ ]*$/ {
            probes=$7
            gsub(/^ +| +$/, "", probes)
            n=split(probes, arr, ",")
            for(i=1; i<=n; i++) {
                gsub(/^ +| +$/, "", arr[i])
                if(arr[i] != "") print arr[i]
            }
        }
    ' | sort | uniq -c | sort -rn | head -10 | awk '{
        printf "  %3d× %s\n", $1, $2
    }' | tee -a "$OUTPUT_FILE"
fi

# ============================================
# RECOMMENDATIONS
# ============================================
{
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " RECOMMENDATIONS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [ "$OPEN_COUNT" -gt 0 ]; then
        echo "  → Open networks found - prime Evil Twin targets"
    fi

    if [ "$WEP_COUNT" -gt 0 ]; then
        echo "  → WEP networks found - crack with aircrack-ng"
    fi

    if [ "$TOTAL_CLIENTS" -gt 5 ]; then
        echo "  → High client count - good environment for attacks"
    fi

    if [ "$TOTAL_APS" -gt 20 ]; then
        echo "  → Dense environment - consider targeted scans"
    fi

    echo ""
} | tee -a "$OUTPUT_FILE"

# ============================================
# CLEANUP
# ============================================
rm -f "${SCAN_PREFIX}"* 2>/dev/null

{
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " Scan complete. Results saved to:"
    echo " $OUTPUT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
} | tee -a "$OUTPUT_FILE"

log "Quick recon complete"
exit 0
```

---

## Understanding the Output

### Network Categories

| Category | Security Risk | Attack Potential |
|----------|---------------|------------------|
| **Open** | Critical | Direct connection, MITM |
| **WEP** | Critical | Crack in minutes |
| **WPA-TKIP** | High | Potential vulnerabilities |
| **WPA2-CCMP** | Medium | Handshake crack possible |
| **WPA3** | Low | Resistant to offline attacks |

### Probe Requests Value

Probe requests reveal networks that devices are looking for:
- Home network names → Personal information
- Corporate names → Employer identification
- Previous hotel/café names → Travel patterns
- Create matching Evil Twin for automatic connection

---

## Quick Recon Workflow

```
┌─────────────────────────────────────────────────────────────┐
│              QUICK RECON WORKFLOW                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. RUN QUICK RECON                                        │
│      └── 15-second overview of environment                  │
│                                                              │
│   2. IDENTIFY TARGETS                                       │
│      ├── Open networks (immediate access)                   │
│      ├── WEP networks (quick crack)                         │
│      └── High-value WPA networks (for handshake)            │
│                                                              │
│   3. NOTE ACTIVE CLIENTS                                    │
│      ├── Devices connected to target networks               │
│      └── Probe requests for Evil Twin                       │
│                                                              │
│   4. PLAN ATTACK                                            │
│      ├── Evil Twin for open/probe matches                   │
│      ├── WEP cracking for legacy networks                   │
│      └── Deauth + capture for WPA                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Red Team Notes

- Run quick recon first on every engagement
- Note busiest channels for deauth effectiveness
- Identify corporate vs personal networks
- Probe requests are gold for targeted attacks
- Save results for reporting

## Blue Team Notes

- Quick recon reveals what attackers see instantly
- Open networks and WEP are immediate risks
- Probe requests leak user information
- Dense environments need monitoring

---

## Payload File

Save as `PP-B10_Quick_Recon.sh`:

```bash
#!/bin/bash
# PP-B10: Quick Recon (Compact)
airmon-ng check kill >/dev/null 2>&1
airmon-ng start wlan1 >/dev/null 2>&1
timeout 15 airodump-ng -w /tmp/qr -o csv wlan1mon >/dev/null 2>&1
echo "=== Quick Recon Results ==="
echo "APs: $(grep -c "^[0-9A-Fa-f]" /tmp/qr-01.csv 2>/dev/null || echo 0)"
echo "Open: $(grep -c "OPN" /tmp/qr-01.csv 2>/dev/null || echo 0)"
echo "WEP: $(grep -c " WEP" /tmp/qr-01.csv 2>/dev/null || echo 0)"
cat /tmp/qr-01.csv | head -20
rm /tmp/qr* 2>/dev/null
airmon-ng stop wlan1mon >/dev/null 2>&1
```

---

[← PP-B09 Log Viewer](PP-B09_Log_Viewer.md) | [Back to Basic Payloads](README.md) | [Next: Intermediate Payloads →](../03_Intermediate_Payloads/README.md)
