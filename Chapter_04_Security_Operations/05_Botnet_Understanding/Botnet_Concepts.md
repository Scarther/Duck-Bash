# Botnet Understanding for Defenders

## Overview

This guide covers botnet concepts, architectures, and defensive techniques. Understanding how botnets operate helps defenders detect and mitigate BadUSB attacks that may be part of larger botnet operations.

---

## Why Botnets Matter for BadUSB

```
BadUSB payloads often serve as initial access for botnets:

1. INITIAL ACCESS (BadUSB)
   └── Payload execution on target

2. ESTABLISH C2
   └── Connect to command & control server

3. PERSISTENCE
   └── Survive reboots, maintain access

4. LATERAL MOVEMENT
   └── Spread to other systems

5. OBJECTIVE
   └── Data theft, DDoS, cryptomining, etc.
```

---

## Botnet Architectures

### Centralized (Star Topology)

```
                    ┌───────────────┐
                    │   C2 Server   │
                    │ (attacker)    │
                    └───────┬───────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
      ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
      │   Bot 1   │   │   Bot 2   │   │   Bot 3   │
      └───────────┘   └───────────┘   └───────────┘

Detection: Block known C2 IPs/domains
Weakness: Single point of failure
```

### Hierarchical (Multi-tier)

```
                    ┌───────────────┐
                    │   Master C2   │
                    └───────┬───────┘
            ┌───────────────┼───────────────┐
      ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
      │  Proxy 1  │   │  Proxy 2  │   │  Proxy 3  │
      └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
            │               │               │
      ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
      │  Bots...  │   │  Bots...  │   │  Bots...  │
      └───────────┘   └───────────┘   └───────────┘

Detection: More complex, need to identify proxies
Weakness: Proxies can be identified over time
```

### Peer-to-Peer (Decentralized)

```
      ┌───────────┐         ┌───────────┐
      │   Bot 1   │◄───────►│   Bot 2   │
      └─────┬─────┘         └─────┬─────┘
            │                     │
            │    ┌───────────┐    │
            └───►│   Bot 3   │◄───┘
                 └─────┬─────┘
                       │
      ┌───────────┐    │    ┌───────────┐
      │   Bot 4   │◄───┴───►│   Bot 5   │
      └───────────┘         └───────────┘

Detection: Traffic pattern analysis
Weakness: Harder to take down
```

---

## Common C2 Communication Methods

### HTTP/HTTPS Beaconing

```python
#!/usr/bin/env python3
"""
Example C2 Beacon Detector
For educational/defensive purposes only
"""

import re
from datetime import datetime

# Suspicious patterns in HTTP traffic
SUSPICIOUS_PATTERNS = [
    r'/collect',
    r'/beacon',
    r'/cmd',
    r'/task',
    r'/update',
    r'[a-zA-Z0-9]{32,}',  # Long random strings
]

def analyze_http_log(log_file):
    """Analyze HTTP logs for C2 indicators"""

    beacons = {}

    with open(log_file, 'r') as f:
        for line in f:
            # Parse common log format
            match = re.search(r'(\d+\.\d+\.\d+\.\d+).*"(GET|POST) ([^"]+)"', line)
            if match:
                ip, method, uri = match.groups()

                # Check for suspicious patterns
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, uri):
                        if ip not in beacons:
                            beacons[ip] = []
                        beacons[ip].append({
                            'method': method,
                            'uri': uri,
                            'pattern': pattern
                        })

    return beacons

# Interval analysis for beaconing
def detect_beaconing(timestamps, threshold_seconds=60):
    """Detect regular interval beaconing"""
    if len(timestamps) < 3:
        return False

    intervals = []
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(delta)

    # Check for consistent intervals (within 10% variance)
    avg_interval = sum(intervals) / len(intervals)
    consistent = all(
        abs(i - avg_interval) < (avg_interval * 0.1)
        for i in intervals
    )

    return consistent and avg_interval < threshold_seconds
```

### DNS Tunneling

```bash
#!/bin/bash
#######################################
# DNS Tunneling Detector
#######################################

PCAP_FILE="$1"

if [ -z "$PCAP_FILE" ]; then
    echo "Usage: $0 <capture.pcap>"
    exit 1
fi

echo "[*] Analyzing DNS traffic for tunneling..."
echo ""

# Extract DNS queries
QUERIES=$(tshark -r "$PCAP_FILE" -T fields -e dns.qry.name -Y "dns.flags.response == 0" 2>/dev/null)

# Statistics
TOTAL=$(echo "$QUERIES" | wc -l)
LONG=$(echo "$QUERIES" | awk 'length > 50' | wc -l)
UNIQUE_TLD=$(echo "$QUERIES" | rev | cut -d. -f1-2 | rev | sort -u | wc -l)

echo "Total queries: $TOTAL"
echo "Long queries (>50 chars): $LONG"
echo "Unique domains: $UNIQUE_TLD"
echo ""

# Flag potential tunneling
if [ "$LONG" -gt 10 ]; then
    echo "[ALERT] High number of long DNS queries detected"
    echo ""
    echo "Suspicious queries:"
    echo "$QUERIES" | awk 'length > 50' | head -20
fi

# Check for high query frequency to single domain
echo ""
echo "[*] High-frequency domains:"
echo "$QUERIES" | rev | cut -d. -f1-2 | rev | sort | uniq -c | sort -rn | head -10

# Check for entropy (randomness) in subdomains
echo ""
echo "[*] Checking subdomain entropy..."
echo "$QUERIES" | while read query; do
    subdomain=$(echo "$query" | cut -d. -f1)
    if echo "$subdomain" | grep -qE '^[a-zA-Z0-9]{20,}$'; then
        echo "[SUSPICIOUS] High-entropy subdomain: $query"
    fi
done | head -20
```

---

## Bot Detection Techniques

### Behavioral Analysis Script

```bash
#!/bin/bash
#######################################
# Bot Behavior Detector
# Identify compromised systems
#######################################

echo "════════════════════════════════════════════════════"
echo "           Bot Behavior Detection"
echo "════════════════════════════════════════════════════"
echo ""

# 1. Check for periodic outbound connections
echo "[*] Checking for periodic connections..."
ss -tn state established | awk '{print $4}' | cut -d: -f1 | \
    sort | uniq -c | sort -rn | head -10
echo ""

# 2. Check for unusual processes
echo "[*] Checking for suspicious processes..."
ps aux | grep -iE "nc |ncat|socat|/tmp/|/dev/shm/|\.hidden" | grep -v grep
echo ""

# 3. Check for persistence mechanisms
echo "[*] Checking cron jobs..."
crontab -l 2>/dev/null
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v "^#" | while read line; do
        if [ -n "$line" ]; then
            echo "  User $user: $line"
        fi
    done
done
echo ""

# 4. Check for unusual network listeners
echo "[*] Checking for unusual listeners..."
ss -tulpn | grep -vE ":22|:80|:443|:53|127.0.0.1"
echo ""

# 5. Check for DNS anomalies
echo "[*] Recent DNS queries (from cache/logs)..."
if [ -f /var/log/dnsmasq.log ]; then
    tail -50 /var/log/dnsmasq.log | grep query
fi
echo ""

# 6. Check outbound traffic volume
echo "[*] Network interface statistics..."
cat /proc/net/dev | head -5
echo ""

# 7. Check for known bot indicators
echo "[*] Checking for known bot files..."
BOT_PATHS=(
    "/tmp/.ICE-unix"
    "/var/tmp/.X11"
    "/dev/shm/.data"
    "/tmp/.font-unix"
)
for path in "${BOT_PATHS[@]}"; do
    if [ -e "$path" ]; then
        echo "[ALERT] Suspicious path exists: $path"
    fi
done
```

### Network Behavior Analysis

```bash
#!/bin/bash
#######################################
# Network Behavior Profiler
# Detect bot-like communication patterns
#######################################

DURATION="${1:-300}"  # 5 minutes default
OUTPUT="/tmp/network_profile_$$.log"

echo "[*] Profiling network behavior for $DURATION seconds..."

# Capture connection data
for ((i=0; i<$DURATION; i+=10)); do
    ss -tn state established 2>/dev/null | \
        awk '{print strftime("%H:%M:%S"), $4, $5}' >> "$OUTPUT"
    sleep 10
done

echo "[*] Analyzing patterns..."

# Find periodic connections
echo ""
echo "[*] Destinations contacted repeatedly:"
cat "$OUTPUT" | awk '{print $3}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

# Find connections at regular intervals
echo ""
echo "[*] Checking for beaconing patterns..."
while read dest; do
    count=$(grep "$dest" "$OUTPUT" | wc -l)
    if [ "$count" -gt 5 ]; then
        # Calculate time intervals
        times=$(grep "$dest" "$OUTPUT" | awk '{print $1}')
        echo "Destination $dest contacted $count times"
    fi
done < <(cat "$OUTPUT" | awk '{print $3}' | cut -d: -f1 | sort -u)

rm -f "$OUTPUT"
```

---

## Botnet C2 Indicators

### Common C2 Indicators of Compromise (IOCs)

```bash
#!/bin/bash
#######################################
# C2 IOC Checker
#######################################

# Known suspicious ports
C2_PORTS="4444 5555 6666 7777 8888 9999 1234 31337"

# Known suspicious domains patterns
C2_DOMAIN_PATTERNS=(
    "[a-z]{20,}\.com"
    "[0-9]{5,}\.xyz"
    "duckdns\.org"
    "no-ip\."
    "ddns\."
)

echo "[*] Checking for C2 indicators..."
echo ""

# Check active connections to suspicious ports
echo "[*] Connections to suspicious ports:"
for port in $C2_PORTS; do
    matches=$(ss -tn state established "dport = :$port" 2>/dev/null)
    if [ -n "$matches" ]; then
        echo "[ALERT] Connection to port $port:"
        echo "$matches"
    fi
done

# Check DNS cache/queries for suspicious domains
echo ""
echo "[*] Checking DNS for suspicious patterns..."
# This would integrate with your DNS logs/cache

# Check for DGA-like domains
echo ""
echo "[*] Checking for DGA-like domain patterns in connections..."
ss -tn state established 2>/dev/null | while read line; do
    # Extract hostnames if resolved
    host=$(echo "$line" | awk '{print $4}' | cut -d: -f1)
    # Check if it looks like DGA
    if echo "$host" | grep -qE '^[a-z0-9]{15,}\.(com|net|org|xyz)$'; then
        echo "[ALERT] Possible DGA domain: $host"
    fi
done
```

---

## Defense Strategies

### Sinkholing and Blocking

```bash
#!/bin/bash
#######################################
# C2 Blocking Script
# Block known C2 infrastructure
#######################################

# Load blocklist
BLOCKLIST="/etc/c2_blocklist.txt"

if [ ! -f "$BLOCKLIST" ]; then
    echo "[*] Creating initial blocklist..."
    cat > "$BLOCKLIST" << 'EOF'
# Known C2 IPs (example - replace with real threat intel)
# 192.0.2.1
# 198.51.100.1

# Known C2 domains
# malware-c2.com
# botnet-controller.xyz
EOF
fi

echo "[*] Applying C2 blocks..."

# Block IPs via iptables
grep -v "^#" "$BLOCKLIST" | grep -E "^[0-9]" | while read ip; do
    iptables -A OUTPUT -d "$ip" -j DROP
    echo "Blocked IP: $ip"
done

# Block domains via hosts file
grep -v "^#" "$BLOCKLIST" | grep -v "^[0-9]" | while read domain; do
    if ! grep -q "$domain" /etc/hosts; then
        echo "127.0.0.1 $domain" >> /etc/hosts
        echo "Sinkholed domain: $domain"
    fi
done

echo "[+] Blocks applied"
```

### Network Segmentation Check

```bash
#!/bin/bash
#######################################
# Network Segmentation Validator
# Ensure proper isolation
#######################################

echo "[*] Validating network segmentation..."
echo ""

# Check default gateway
echo "[*] Default gateway:"
ip route | grep default
echo ""

# Check which networks are reachable
echo "[*] Reachable networks:"
ip route
echo ""

# Test critical segment isolation
SENSITIVE_NETS="10.0.0.0/8 172.16.0.0/12"

for net in $SENSITIVE_NETS; do
    first_ip=$(echo "$net" | cut -d/ -f1 | sed 's/0$/1/')
    if ping -c 1 -W 1 "$first_ip" &>/dev/null; then
        echo "[WARNING] Can reach $net - verify if authorized"
    else
        echo "[OK] Cannot reach $net"
    fi
done
```

---

## Incident Response for Botnet Infection

### Containment Checklist

```
IMMEDIATE ACTIONS:

1. ISOLATE
   ☐ Disconnect from network (don't power off)
   ☐ Block at firewall
   ☐ Preserve running memory

2. DOCUMENT
   ☐ Screenshot active connections
   ☐ Capture running processes
   ☐ Note timeline of discovery

3. PRESERVE
   ☐ Memory dump if possible
   ☐ Disk image before changes
   ☐ Network traffic capture

4. ANALYZE
   ☐ Identify C2 infrastructure
   ☐ Determine spread mechanism
   ☐ Find persistence methods

5. REMEDIATE
   ☐ Remove persistence
   ☐ Patch vulnerabilities
   ☐ Reset credentials

6. RECOVER
   ☐ Rebuild if necessary
   ☐ Restore from backup
   ☐ Monitor for reinfection
```

---

[← Back to Security Operations](../README.md)
