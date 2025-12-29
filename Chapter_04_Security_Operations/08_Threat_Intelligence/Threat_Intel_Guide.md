# Threat Intelligence Guide

## Overview

This guide covers threat intelligence concepts and techniques for understanding, tracking, and defending against BadUSB threats.

---

## Threat Intelligence Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                  THREAT INTELLIGENCE LIFECYCLE                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│      PLANNING         COLLECTION         PROCESSING                 │
│    ┌─────────┐       ┌─────────┐       ┌─────────┐                 │
│    │  What   │──────►│ Gather  │──────►│  Clean  │                 │
│    │  do we  │       │  data   │       │ & Parse │                 │
│    │  need?  │       │         │       │         │                 │
│    └─────────┘       └─────────┘       └────┬────┘                 │
│         ▲                                   │                       │
│         │                                   ▼                       │
│    ┌────┴────┐       ┌─────────┐       ┌─────────┐                 │
│    │FEEDBACK │◄──────│DISSEM-  │◄──────│ANALYSIS │                 │
│    │         │       │INATION  │       │         │                 │
│    └─────────┘       └─────────┘       └─────────┘                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Types of Threat Intelligence

### Strategic Intelligence
- **Purpose:** Executive decision-making
- **Timeframe:** Long-term trends
- **Example:** "BadUSB attacks increased 40% in finance sector"

### Tactical Intelligence
- **Purpose:** Security team planning
- **Timeframe:** Medium-term
- **Example:** "Attackers using Flipper Zero with custom firmware"

### Operational Intelligence
- **Purpose:** Active defense
- **Timeframe:** Short-term
- **Example:** "Campaign using Discord for C2 communication"

### Technical Intelligence
- **Purpose:** Detection systems
- **Timeframe:** Immediate
- **Example:** "Block USB VID 0483, PID 5740"

---

## BadUSB Threat Landscape

### Common Attack Vectors

| Vector | Description | Risk Level |
|--------|-------------|------------|
| Physical Drop | USB devices left in parking lots | High |
| Supply Chain | Compromised USB devices in shipments | Critical |
| Social Engineering | "IT support" delivering devices | High |
| Conference Swag | Free USB drives at events | Medium |
| Hardware Implant | Keyboard cables with embedded devices | Critical |

### Threat Actor Categories

```
NATION-STATE ACTORS
├── Resources: High
├── Sophistication: Very High
├── Targets: Government, Critical Infrastructure
└── Examples: APT groups using USB for air-gap jumping

CYBERCRIMINAL GROUPS
├── Resources: Medium-High
├── Sophistication: Medium-High
├── Targets: Financial, Healthcare
└── Examples: Ransomware delivery via USB

HACKTIVISTS
├── Resources: Low-Medium
├── Sophistication: Low-Medium
├── Targets: Various based on ideology
└── Examples: Protest-related USB drops

INSIDER THREATS
├── Resources: Varies
├── Sophistication: Low-High
├── Targets: Own organization
└── Examples: Data theft, sabotage

SCRIPT KIDDIES
├── Resources: Low
├── Sophistication: Low
├── Targets: Opportunistic
└── Examples: Using public payloads for pranks
```

---

## Indicators of Compromise (IOC) Management

### IOC Collection Script

```bash
#!/bin/bash
#######################################
# BadUSB IOC Collector
# Gather indicators from multiple sources
#######################################

IOC_DIR="/var/lib/threat_intel/iocs"
mkdir -p "$IOC_DIR"/{usb_vids,domains,ips,hashes}

TIMESTAMP=$(date +%Y%m%d)

echo "[*] Collecting BadUSB IOCs..."

# Known BadUSB USB VID/PIDs
cat > "$IOC_DIR/usb_vids/badusb_devices_$TIMESTAMP.txt" << 'EOF'
# Known BadUSB Device Identifiers
# Format: VID:PID Description

# Flipper Zero
0483:5740 Flipper Zero (default)

# USB Rubber Ducky
1532:0110 USB Rubber Ducky
05AC:021E USB Rubber Ducky (Apple spoof)

# DigiSpark
16D0:0753 DigiSpark ATtiny85

# Arduino Leonardo
2341:8036 Arduino Leonardo
2341:8037 Arduino Micro

# Teensy
16C0:0483 Teensy 2.0
16C0:0486 Teensy++ 2.0

# Raspberry Pi Pico
2E8A:0005 Raspberry Pi Pico

# O.MG Cable
2341:0043 O.MG Cable (Arduino spoof)
EOF

# Known C2 patterns
cat > "$IOC_DIR/domains/c2_patterns_$TIMESTAMP.txt" << 'EOF'
# C2 Domain Patterns
# Use for pattern matching, not exact blocking

# DGA-like patterns
[a-z0-9]{15,}\.(com|net|org|xyz|top)

# Common dynamic DNS
*.duckdns.org
*.no-ip.com
*.ddns.net
*.hopto.org
*.servegame.com

# Free hosting often abused
*.000webhostapp.com
*.herokuapp.com
*.netlify.app
*.vercel.app

# Paste sites (exfil)
pastebin.com
ghostbin.com
paste.ee
hastebin.com
EOF

# Suspicious process patterns
cat > "$IOC_DIR/patterns/suspicious_processes_$TIMESTAMP.txt" << 'EOF'
# Suspicious Process Patterns

# PowerShell with evasion flags
powershell.*-w\s*hidden
powershell.*-windowstyle\s*hidden
powershell.*-ep\s*bypass
powershell.*-executionpolicy\s*bypass
powershell.*-enc\s
powershell.*-encodedcommand\s
powershell.*-nop
powershell.*-noprofile

# Download cradles
iex.*downloadstring
invoke-expression.*downloadstring
invoke-webrequest.*iex
wget.*\|.*sh
curl.*\|.*sh

# Reverse shells
nc.*-e.*/bin
ncat.*-e.*/bin
bash.*-i.*>/dev/tcp
python.*socket.*connect

# Persistence indicators
schtasks.*/create.*hidden
reg.*add.*currentversion\\run
crontab.*-e
EOF

echo "[+] IOCs saved to: $IOC_DIR"
ls -la "$IOC_DIR"/*
```

### IOC Lookup Script

```bash
#!/bin/bash
#######################################
# IOC Lookup Tool
# Check if indicator is known bad
#######################################

IOC_DIR="/var/lib/threat_intel/iocs"
QUERY="$1"
TYPE="${2:-auto}"

if [ -z "$QUERY" ]; then
    echo "Usage: $0 <indicator> [type]"
    echo "Types: usb, domain, ip, hash, auto"
    exit 1
fi

# Auto-detect type
if [ "$TYPE" = "auto" ]; then
    if [[ "$QUERY" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$ ]]; then
        TYPE="usb"
    elif [[ "$QUERY" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TYPE="ip"
    elif [[ "$QUERY" =~ ^[a-fA-F0-9]{32,64}$ ]]; then
        TYPE="hash"
    else
        TYPE="domain"
    fi
fi

echo "[*] Searching for: $QUERY (type: $TYPE)"
echo ""

case "$TYPE" in
    usb)
        MATCHES=$(grep -ri "$QUERY" "$IOC_DIR/usb_vids/" 2>/dev/null)
        ;;
    domain)
        MATCHES=$(grep -ri "$QUERY" "$IOC_DIR/domains/" 2>/dev/null)
        ;;
    ip)
        MATCHES=$(grep -ri "$QUERY" "$IOC_DIR/ips/" 2>/dev/null)
        ;;
    hash)
        MATCHES=$(grep -ri "$QUERY" "$IOC_DIR/hashes/" 2>/dev/null)
        ;;
esac

if [ -n "$MATCHES" ]; then
    echo "[!] IOC FOUND:"
    echo "$MATCHES"
else
    echo "[OK] No matches in local IOC database"
fi

# Optional: Query external services
echo ""
echo "[*] External lookups:"
echo "    VirusTotal: https://www.virustotal.com/gui/search/$QUERY"
echo "    AbuseIPDB: https://www.abuseipdb.com/check/$QUERY"
echo "    URLhaus: https://urlhaus.abuse.ch/browse.php?search=$QUERY"
```

---

## Threat Intelligence Feeds

### Feed Integration Script

```bash
#!/bin/bash
#######################################
# Threat Intelligence Feed Aggregator
#######################################

FEED_DIR="/var/lib/threat_intel/feeds"
mkdir -p "$FEED_DIR"

TIMESTAMP=$(date +%Y%m%d)

echo "[*] Updating threat intelligence feeds..."

# URLhaus - Malware URLs
echo "[*] Fetching URLhaus feed..."
curl -s "https://urlhaus.abuse.ch/downloads/csv_recent/" | \
    grep -v "^#" | cut -d',' -f2 | tr -d '"' > "$FEED_DIR/urlhaus_urls_$TIMESTAMP.txt"

# Abuse.ch Feodo Tracker - C2 IPs
echo "[*] Fetching Feodo Tracker feed..."
curl -s "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" | \
    grep -v "^#" > "$FEED_DIR/feodo_ips_$TIMESTAMP.txt"

# Count entries
echo ""
echo "[+] Feed update complete:"
echo "    URLhaus URLs: $(wc -l < $FEED_DIR/urlhaus_urls_$TIMESTAMP.txt 2>/dev/null || echo 0)"
echo "    Feodo C2 IPs: $(wc -l < $FEED_DIR/feodo_ips_$TIMESTAMP.txt 2>/dev/null || echo 0)"
```

### Feed Monitoring Script

```bash
#!/bin/bash
#######################################
# Monitor Network Against Threat Feeds
#######################################

FEED_DIR="/var/lib/threat_intel/feeds"
LOG_FILE="/var/log/threat_feed_hits.log"

# Get latest feeds
MALICIOUS_IPS=$(cat "$FEED_DIR"/feodo_ips_*.txt 2>/dev/null | sort -u)
MALICIOUS_DOMAINS=$(cat "$FEED_DIR"/*_domains_*.txt 2>/dev/null | sort -u)

echo "[*] Monitoring network against threat feeds..."
echo "[*] Loaded $(echo "$MALICIOUS_IPS" | wc -l) malicious IPs"
echo "[*] Loaded $(echo "$MALICIOUS_DOMAINS" | wc -l) malicious domains"

# Check current connections
echo ""
echo "[*] Checking active connections..."

ss -tn state established 2>/dev/null | while read line; do
    DEST_IP=$(echo "$line" | awk '{print $4}' | cut -d: -f1)

    if echo "$MALICIOUS_IPS" | grep -q "^$DEST_IP$"; then
        MSG="[ALERT] Connection to known malicious IP: $DEST_IP"
        echo "$MSG"
        echo "$(date) $MSG" >> "$LOG_FILE"
    fi
done

# Check DNS queries (if logging available)
if [ -f /var/log/dnsmasq.log ]; then
    echo ""
    echo "[*] Checking recent DNS queries..."

    tail -1000 /var/log/dnsmasq.log | while read line; do
        QUERY=$(echo "$line" | grep -oP 'query\[\w+\] \K[^ ]+')

        if echo "$MALICIOUS_DOMAINS" | grep -q "^$QUERY$"; then
            MSG="[ALERT] DNS query to malicious domain: $QUERY"
            echo "$MSG"
            echo "$(date) $MSG" >> "$LOG_FILE"
        fi
    done
fi
```

---

## MITRE ATT&CK Integration

### BadUSB Technique Mapping

```bash
#!/bin/bash
#######################################
# MITRE ATT&CK Mapping for BadUSB
#######################################

cat << 'EOF'
═══════════════════════════════════════════════════════════════
           BADUSB MITRE ATT&CK MAPPING
═══════════════════════════════════════════════════════════════

INITIAL ACCESS
├── T1091 - Replication Through Removable Media
│   └── BadUSB device insertion
├── T1200 - Hardware Additions
│   └── Malicious USB device

EXECUTION
├── T1059.001 - PowerShell
│   └── Keystroke injection runs PowerShell
├── T1059.003 - Windows Command Shell
│   └── Keystroke injection runs cmd.exe
├── T1204.002 - Malicious File
│   └── User plugs in USB device

PERSISTENCE
├── T1547.001 - Registry Run Keys
│   └── Payload adds registry persistence
├── T1053.005 - Scheduled Task
│   └── Payload creates scheduled task
├── T1546.003 - Windows Management Instrumentation Event
│   └── WMI persistence

PRIVILEGE ESCALATION
├── T1548.002 - Bypass User Account Control
│   └── UAC bypass techniques

DEFENSE EVASION
├── T1027 - Obfuscated Files/Information
│   └── Base64 encoded commands
├── T1070.004 - File Deletion
│   └── Self-deleting payloads
├── T1036 - Masquerading
│   └── USB device spoofs VID/PID

CREDENTIAL ACCESS
├── T1003 - OS Credential Dumping
│   └── Credential harvesting payload
├── T1056.001 - Keylogging
│   └── Keylogger deployment

COLLECTION
├── T1005 - Data from Local System
│   └── System info gathering
├── T1119 - Automated Collection
│   └── Scripted data collection

EXFILTRATION
├── T1041 - Exfiltration Over C2 Channel
│   └── HTTP/HTTPS exfiltration
├── T1048.003 - Exfiltration Over Alternative Protocol
│   └── DNS tunneling

═══════════════════════════════════════════════════════════════
EOF
```

### Detection Rule Generator

```bash
#!/bin/bash
#######################################
# Generate Detection Rules from ATT&CK
#######################################

OUTPUT_DIR="/etc/detection_rules"
mkdir -p "$OUTPUT_DIR"

cat > "$OUTPUT_DIR/badusb_sigma_rules.yml" << 'EOF'
# Sigma rules for BadUSB detection
# Generated from MITRE ATT&CK mapping

title: BadUSB Initial Access - USB Device Connection
id: badusb-001
status: experimental
description: Detects USB device connection followed by rapid command execution
references:
    - https://attack.mitre.org/techniques/T1091/
logsource:
    product: windows
    service: security
detection:
    usb_connection:
        EventID: 6416
    command_execution:
        EventID: 4688
        NewProcessName|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    timeframe: 30s
    condition: usb_connection and command_execution
level: high
tags:
    - attack.initial_access
    - attack.t1091
---
title: BadUSB Execution - Encoded PowerShell
id: badusb-002
status: stable
description: Detects encoded PowerShell execution typical of BadUSB payloads
references:
    - https://attack.mitre.org/techniques/T1059.001/
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - '-enc '
            - '-EncodedCommand'
            - 'FromBase64String'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
---
title: BadUSB Persistence - Registry Run Key
id: badusb-003
status: stable
description: Detects registry Run key modification from script execution
references:
    - https://attack.mitre.org/techniques/T1547.001/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains: '\CurrentVersion\Run'
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1547.001
EOF

echo "[+] Detection rules generated: $OUTPUT_DIR/badusb_sigma_rules.yml"
```

---

## Threat Hunting Queries

### Proactive Hunt Script

```bash
#!/bin/bash
#######################################
# BadUSB Threat Hunting
# Proactive search for indicators
#######################################

echo "════════════════════════════════════════════════════"
echo "         BadUSB Threat Hunt"
echo "════════════════════════════════════════════════════"
echo ""

# Hunt 1: Recent USB device connections
echo "[Hunt 1] USB Device History"
echo "─────────────────────────────"
dmesg | grep -i "usb" | grep -iE "new|attached|keyboard" | tail -20
echo ""

# Hunt 2: Processes spawned from explorer (HID injection indicator)
echo "[Hunt 2] Shell Processes from Explorer"
echo "─────────────────────────────────────"
ps -eo ppid,pid,cmd | while read ppid pid cmd; do
    parent_cmd=$(ps -p $ppid -o cmd= 2>/dev/null)
    if echo "$parent_cmd" | grep -qi "explorer"; then
        if echo "$cmd" | grep -qiE "powershell|cmd|wscript|cscript"; then
            echo "PID $pid: $cmd (parent: $parent_cmd)"
        fi
    fi
done
echo ""

# Hunt 3: Scheduled tasks created recently
echo "[Hunt 3] Recent Scheduled Tasks (last 7 days)"
echo "──────────────────────────────────────────────"
find /var/spool/cron -mtime -7 -ls 2>/dev/null
echo ""

# Hunt 4: Files in temp with execution permissions
echo "[Hunt 4] Executable Files in Temp Directories"
echo "──────────────────────────────────────────────"
find /tmp /var/tmp /dev/shm -type f -perm -111 -ls 2>/dev/null | head -20
echo ""

# Hunt 5: Hidden files created recently
echo "[Hunt 5] Recently Created Hidden Files"
echo "──────────────────────────────────────"
find /tmp /home -name ".*" -type f -mtime -1 -ls 2>/dev/null | head -20
echo ""

# Hunt 6: Unusual network connections
echo "[Hunt 6] Connections to Unusual Ports"
echo "────────────────────────────────────"
ss -tn state established | awk '{print $4}' | cut -d: -f2 | sort | uniq -c | sort -rn | \
    while read count port; do
        if [[ "$port" =~ ^(4444|5555|6666|7777|8888|9999|1234|31337)$ ]]; then
            echo "[!] Suspicious port: $port (count: $count)"
        fi
    done
echo ""

echo "════════════════════════════════════════════════════"
echo "Hunt complete. Review any findings above."
echo "════════════════════════════════════════════════════"
```

---

## Intelligence Sharing

### STIX/TAXII Integration Example

```python
#!/usr/bin/env python3
"""
STIX Indicator Generator for BadUSB IOCs
Creates shareable threat intelligence
"""

import json
from datetime import datetime

def create_stix_indicator(ioc_type, value, description):
    """Create a STIX 2.1 indicator"""

    indicator_id = f"indicator--{hash(value) % 10**12:012d}"

    pattern_map = {
        "usb": f"[hardware:vendor_id = '{value.split(':')[0]}' AND hardware:product_id = '{value.split(':')[1]}']",
        "domain": f"[domain-name:value = '{value}']",
        "ip": f"[ipv4-addr:value = '{value}']",
        "hash": f"[file:hashes.'SHA-256' = '{value}']"
    }

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": f"BadUSB IOC: {value}",
        "description": description,
        "pattern": pattern_map.get(ioc_type, f"[{ioc_type}:value = '{value}']"),
        "pattern_type": "stix",
        "valid_from": datetime.utcnow().isoformat() + "Z",
        "labels": ["malicious-activity", "badusb"]
    }

    return indicator

# Example usage
if __name__ == "__main__":
    indicators = [
        create_stix_indicator("usb", "0483:5740", "Flipper Zero default VID/PID"),
        create_stix_indicator("usb", "16D0:0753", "DigiSpark BadUSB device"),
    ]

    bundle = {
        "type": "bundle",
        "id": "bundle--badusb-iocs",
        "objects": indicators
    }

    print(json.dumps(bundle, indent=2))
```

---

## Quick Reference

### Threat Intel Sources

| Source | Type | URL |
|--------|------|-----|
| URLhaus | Malware URLs | urlhaus.abuse.ch |
| Feodo Tracker | C2 IPs | feodotracker.abuse.ch |
| MalwareBazaar | Malware Samples | bazaar.abuse.ch |
| ThreatFox | IOCs | threatfox.abuse.ch |
| AlienVault OTX | Community Intel | otx.alienvault.com |
| MISP | Sharing Platform | misp-project.org |

---

[← Back to Security Operations](../README.md)
