# Network Monitoring & IDS/IPS Guide

## Overview

This guide covers network-based detection of BadUSB attack traffic using IDS/IPS systems and network monitoring tools.

---

## Network Detection Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                  NETWORK MONITORING ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ENDPOINTS                   NETWORK TAP                           │
│   ┌─────────┐                ┌─────────┐                           │
│   │ PC      │────────────────│ Mirror  │                           │
│   │ Laptop  │                │ Port    │                           │
│   └─────────┘                └────┬────┘                           │
│                                   │                                 │
│                                   ▼                                 │
│                          ┌───────────────┐                         │
│                          │    IDS/IPS    │                         │
│                          │   Suricata    │                         │
│                          │     Zeek      │                         │
│                          └───────┬───────┘                         │
│                                  │                                  │
│                                  ▼                                  │
│                          ┌───────────────┐                         │
│                          │     SIEM      │                         │
│                          │   Alerting    │                         │
│                          └───────────────┘                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Suricata Configuration

### BadUSB-Related Rules

```yaml
# /etc/suricata/rules/local.rules

# DNS Exfiltration Detection
alert dns any any -> any any (msg:"Possible DNS Exfiltration - Long Query"; dns.query; content:"."; offset:50; sid:1000001; rev:1;)

alert dns any any -> any any (msg:"Possible DNS Exfiltration - Base64 Pattern"; dns.query; pcre:"/[A-Za-z0-9+\/]{30,}={0,2}\./"; sid:1000002; rev:1;)

# HTTP Exfiltration
alert http any any -> any any (msg:"Suspicious POST to /collect endpoint"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/collect"; sid:1000003; rev:1;)

alert http any any -> any any (msg:"Base64 Data in HTTP Request"; flow:to_server,established; http.uri; pcre:"/[A-Za-z0-9+\/]{50,}={0,2}/"; sid:1000004; rev:1;)

# PowerShell Download Cradle
alert http any any -> any any (msg:"PowerShell Download Pattern"; flow:to_server,established; content:"powershell"; nocase; content:"-enc"; nocase; sid:1000005; rev:1;)

# Known C2 Ports
alert tcp any any -> any 4444 (msg:"Connection to Common Metasploit Port"; flow:to_server,established; sid:1000006; rev:1;)

alert tcp any any -> any 5555 (msg:"Connection to Common Backdoor Port"; flow:to_server,established; sid:1000007; rev:1;)

# Reverse Shell Indicators
alert tcp any any -> any any (msg:"Potential Reverse Shell - Bash in TCP Stream"; flow:established; content:"/bin/bash"; sid:1000008; rev:1;)

alert tcp any any -> any any (msg:"Potential Reverse Shell - cmd.exe in Stream"; flow:established; content:"cmd.exe"; nocase; sid:1000009; rev:1;)
```

### Suricata Setup Script

```bash
#!/bin/bash
#######################################
# Suricata IDS Setup
# For BadUSB traffic detection
#######################################

echo "[*] Installing Suricata..."
apt update && apt install -y suricata

# Configure interface
IFACE="${1:-eth0}"
echo "[*] Configuring for interface: $IFACE"

# Backup original config
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

# Update interface setting
sed -i "s/interface: eth0/interface: $IFACE/" /etc/suricata/suricata.yaml

# Enable community rules
suricata-update

# Add local rules
cat >> /etc/suricata/rules/local.rules << 'EOF'
# Local BadUSB Detection Rules

# DNS Tunneling Detection
alert dns any any -> any any (msg:"Long DNS Query - Possible Exfil"; dns.query; content:"."; offset:50; sid:2000001; rev:1;)

# Encoded PowerShell
alert http any any -> any any (msg:"Base64 Encoded PowerShell"; flow:to_server; content:"powershell"; nocase; content:"-enc"; nocase; sid:2000002; rev:1;)
EOF

# Test configuration
suricata -T -c /etc/suricata/suricata.yaml

# Enable and start
systemctl enable suricata
systemctl start suricata

echo "[+] Suricata installed and configured"
echo "[*] Logs: /var/log/suricata/"
```

---

## Zeek (Bro) Configuration

### Zeek Scripts for BadUSB Detection

```zeek
# /opt/zeek/share/zeek/site/badusb_detection.zeek

@load base/protocols/http
@load base/protocols/dns

module BadUSB;

export {
    redef enum Notice::Type += {
        DNS_Exfiltration,
        Suspicious_POST,
        Encoded_PowerShell,
        Known_C2_Port
    };

    # Configurable thresholds
    const dns_query_threshold = 50 &redef;
    const base64_pattern = /[A-Za-z0-9+\/]{30,}={0,2}/ &redef;
}

# Detect long DNS queries (possible exfiltration)
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( |query| > dns_query_threshold )
    {
        NOTICE([
            $note=DNS_Exfiltration,
            $msg=fmt("Long DNS query detected: %d chars", |query|),
            $conn=c,
            $sub=query
        ]);
    }
}

# Detect suspicious HTTP POSTs
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    if ( method == "POST" )
    {
        if ( /\/collect|\/exfil|\/data|\/upload/ in unescaped_URI )
        {
            NOTICE([
                $note=Suspicious_POST,
                $msg=fmt("Suspicious POST endpoint: %s", unescaped_URI),
                $conn=c
            ]);
        }
    }
}

# Detect encoded PowerShell in HTTP
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    if ( is_orig && /-enc/ in data && /powershell/i in data )
    {
        NOTICE([
            $note=Encoded_PowerShell,
            $msg="Encoded PowerShell detected in HTTP stream",
            $conn=c
        ]);
    }
}

# Detect connections to known C2 ports
event connection_established(c: connection)
{
    local c2_ports: set[port] = { 4444/tcp, 5555/tcp, 6666/tcp, 8888/tcp };

    if ( c$id$resp_p in c2_ports )
    {
        NOTICE([
            $note=Known_C2_Port,
            $msg=fmt("Connection to known C2 port: %s", c$id$resp_p),
            $conn=c
        ]);
    }
}
```

### Zeek Setup Script

```bash
#!/bin/bash
#######################################
# Zeek Network Security Monitor Setup
#######################################

echo "[*] Installing Zeek..."

# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | \
    sudo tee /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | \
    gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null

apt update && apt install -y zeek

# Configure interface
IFACE="${1:-eth0}"

cat > /opt/zeek/etc/node.cfg << EOF
[zeek]
type=standalone
host=localhost
interface=$IFACE
EOF

# Add local scripts
cat > /opt/zeek/share/zeek/site/local.zeek << 'EOF'
@load tuning/defaults
@load misc/loaded-scripts
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/http/software-browser-plugins

# Custom BadUSB detection
# @load ./badusb_detection.zeek

redef Site::local_nets += { 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 };
EOF

# Deploy
zeekctl deploy

echo "[+] Zeek installed and configured"
echo "[*] Logs: /opt/zeek/logs/current/"
```

---

## Traffic Analysis Scripts

### Packet Capture Analysis

```bash
#!/bin/bash
#######################################
# PCAP Analysis for BadUSB Traffic
#######################################

PCAP_FILE="$1"

if [ -z "$PCAP_FILE" ]; then
    echo "Usage: $0 <capture.pcap>"
    exit 1
fi

echo "════════════════════════════════════════════════════"
echo "         PCAP Analysis for BadUSB Traffic"
echo "════════════════════════════════════════════════════"
echo ""

# Basic statistics
echo "[*] Capture Statistics:"
capinfos "$PCAP_FILE" 2>/dev/null | grep -E "packets|duration|data size"
echo ""

# DNS analysis
echo "[*] DNS Queries (Top 20):"
tshark -r "$PCAP_FILE" -T fields -e dns.qry.name -Y "dns.flags.response == 0" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -20
echo ""

# Long DNS queries (possible exfil)
echo "[*] Long DNS Queries (>50 chars):"
tshark -r "$PCAP_FILE" -T fields -e dns.qry.name -Y "dns.flags.response == 0" 2>/dev/null | \
    awk 'length > 50' | head -10
echo ""

# HTTP POST requests
echo "[*] HTTP POST Requests:"
tshark -r "$PCAP_FILE" -T fields -e ip.src -e http.host -e http.request.uri \
    -Y "http.request.method == POST" 2>/dev/null | head -20
echo ""

# PowerShell indicators
echo "[*] PowerShell Keywords in Traffic:"
tshark -r "$PCAP_FILE" -T fields -e tcp.payload 2>/dev/null | \
    xxd -r -p 2>/dev/null | strings | grep -iE "powershell|invoke-|downloadstring" | head -10
echo ""

# Suspicious ports
echo "[*] Connections to Suspicious Ports:"
tshark -r "$PCAP_FILE" -T fields -e ip.src -e ip.dst -e tcp.dstport \
    -Y "tcp.dstport == 4444 or tcp.dstport == 5555 or tcp.dstport == 6666" 2>/dev/null
echo ""

# External connections
echo "[*] External Connections (non-RFC1918):"
tshark -r "$PCAP_FILE" -T fields -e ip.src -e ip.dst -e tcp.dstport \
    -Y "not ip.dst matches \"^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)\"" 2>/dev/null | \
    sort -u | head -20
```

### Live Traffic Monitor

```bash
#!/bin/bash
#######################################
# Live Network Monitor
# Detect BadUSB-related traffic
#######################################

IFACE="${1:-eth0}"

echo "[*] Monitoring interface: $IFACE"
echo "[*] Press Ctrl+C to stop"
echo ""

# Monitor with tcpdump, filter for suspicious patterns
tcpdump -i "$IFACE" -n -l 2>/dev/null | while read line; do

    # Check for DNS exfiltration
    if echo "$line" | grep -qE "A\? [a-zA-Z0-9]{50,}\."; then
        echo "[ALERT] Possible DNS exfil: $line"
    fi

    # Check for suspicious ports
    if echo "$line" | grep -qE "\.4444|\.5555|\.6666"; then
        echo "[ALERT] Suspicious port: $line"
    fi

    # Check for HTTP POST
    if echo "$line" | grep -qE "POST|PUT"; then
        echo "[INFO] HTTP POST/PUT: $line"
    fi
done
```

---

## Network Baseline and Anomaly Detection

### Establish Baseline

```bash
#!/bin/bash
#######################################
# Network Baseline Generator
#######################################

DURATION="${1:-3600}"  # Default 1 hour
OUTPUT_DIR="/var/log/network_baseline"

mkdir -p "$OUTPUT_DIR"

echo "[*] Generating network baseline for $DURATION seconds..."

# Capture connection data
timeout "$DURATION" ss -tulpn 2>/dev/null >> "$OUTPUT_DIR/connections_baseline.txt" &

# DNS baseline
timeout "$DURATION" tcpdump -i any port 53 -c 10000 -w "$OUTPUT_DIR/dns_baseline.pcap" 2>/dev/null &

# HTTP/HTTPS baseline
timeout "$DURATION" tcpdump -i any "port 80 or port 443" -c 10000 -w "$OUTPUT_DIR/web_baseline.pcap" 2>/dev/null &

wait

# Generate statistics
echo "[*] Generating baseline statistics..."

# Normal DNS query lengths
tshark -r "$OUTPUT_DIR/dns_baseline.pcap" -T fields -e dns.qry.name 2>/dev/null | \
    awk '{print length}' | sort -n | uniq -c > "$OUTPUT_DIR/dns_query_lengths.txt"

# Normal destinations
tshark -r "$OUTPUT_DIR/web_baseline.pcap" -T fields -e ip.dst 2>/dev/null | \
    sort | uniq -c | sort -rn > "$OUTPUT_DIR/destinations.txt"

echo "[+] Baseline saved to: $OUTPUT_DIR"
```

### Compare Against Baseline

```bash
#!/bin/bash
#######################################
# Network Anomaly Detector
# Compare current traffic to baseline
#######################################

BASELINE_DIR="/var/log/network_baseline"
CURRENT_PCAP="$1"

if [ -z "$CURRENT_PCAP" ]; then
    echo "Usage: $0 <current_capture.pcap>"
    exit 1
fi

echo "[*] Comparing traffic against baseline..."
echo ""

# Compare DNS query lengths
echo "[*] DNS Query Length Anomalies:"
AVG_LEN=$(awk '{sum+=$2*$1; count+=$1} END {print sum/count}' "$BASELINE_DIR/dns_query_lengths.txt")
echo "    Baseline average query length: $AVG_LEN"

tshark -r "$CURRENT_PCAP" -T fields -e dns.qry.name 2>/dev/null | while read query; do
    len=${#query}
    if [ "$len" -gt "$((${AVG_LEN%.*} * 3))" ]; then
        echo "    [ANOMALY] Long query ($len chars): $query"
    fi
done

# Compare destinations
echo ""
echo "[*] New Destination Anomalies:"
KNOWN_DESTS=$(cat "$BASELINE_DIR/destinations.txt" | awk '{print $2}')
tshark -r "$CURRENT_PCAP" -T fields -e ip.dst 2>/dev/null | sort -u | while read ip; do
    if ! echo "$KNOWN_DESTS" | grep -q "^$ip$"; then
        echo "    [ANOMALY] New destination: $ip"
    fi
done
```

---

## IDS Alert Response

### Alert Handler Script

```bash
#!/bin/bash
#######################################
# IDS Alert Handler
# Process Suricata alerts
#######################################

ALERT_LOG="/var/log/suricata/fast.log"
RESPONSE_DIR="/var/log/ids_response"

mkdir -p "$RESPONSE_DIR"

tail -F "$ALERT_LOG" 2>/dev/null | while read line; do

    # Parse alert
    TIMESTAMP=$(echo "$line" | cut -d' ' -f1-2)
    SID=$(echo "$line" | grep -oP '\[\d+:\d+:\d+\]' | head -1)
    MSG=$(echo "$line" | grep -oP '"\K[^"]+(?=")')

    echo "[$(date)] Alert: $MSG"

    # High severity responses
    if echo "$line" | grep -qiE "exfiltration|reverse.shell|c2"; then
        echo "[!] High severity - logging additional data"

        # Capture context
        SRC_IP=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)

        if [ -n "$SRC_IP" ]; then
            # Log related connections
            ss -tulpn | grep "$SRC_IP" >> "$RESPONSE_DIR/$(date +%Y%m%d)_connections.log"

            # Capture short packet sample
            timeout 30 tcpdump -i any host "$SRC_IP" -c 100 -w "$RESPONSE_DIR/$(date +%Y%m%d_%H%M%S)_$SRC_IP.pcap" &
        fi
    fi

done
```

---

## Quick Reference

### Common Detection Signatures

| Attack Type | Signature Pattern |
|-------------|------------------|
| DNS Exfil | Query length > 50 chars |
| HTTP Exfil | POST to /collect, /data, /upload |
| Reverse Shell | /bin/bash in TCP stream |
| C2 Communication | Ports 4444, 5555, 6666 |
| Encoded Payload | Base64 pattern in traffic |

### Useful tcpdump Filters

```bash
# All DNS traffic
tcpdump -i eth0 port 53

# HTTP POST requests
tcpdump -i eth0 -s 0 -A 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'

# Connections to suspicious ports
tcpdump -i eth0 'port 4444 or port 5555 or port 6666'

# Non-RFC1918 destinations
tcpdump -i eth0 'not (dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16)'
```

---

[← Back to Security Operations](../README.md)
