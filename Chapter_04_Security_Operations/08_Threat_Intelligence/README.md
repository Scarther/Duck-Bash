# Threat Intelligence

## Overview

Threat intelligence transforms raw data into actionable information that helps defenders anticipate, detect, and respond to attacks. This section covers intelligence sources, IOC management, and threat hunting techniques relevant to USB/HID and wireless attacks.

---

## Intelligence Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│             THREAT INTELLIGENCE LIFECYCLE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│       ┌──────────────────────────────────────────────┐              │
│       │                                              │              │
│       ▼                                              │              │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐        │              │
│   │ PLANNING │──▶│COLLECTION│──▶│PROCESSING│        │              │
│   │& DIRECTION   │          │   │          │        │              │
│   └──────────┘   └──────────┘   └──────────┘        │              │
│                                        │             │              │
│                                        ▼             │              │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐        │              │
│   │ FEEDBACK │◀──│DISSEMINA-│◀──│ ANALYSIS │        │              │
│   │          │   │   TION   │   │          │────────┘              │
│   └──────────┘   └──────────┘   └──────────┘                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Intelligence Types

```
┌─────────────────────────────────────────────────────────────────────┐
│              LEVELS OF THREAT INTELLIGENCE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  STRATEGIC (Executive Level)                                        │
│  ────────────────────────────                                       │
│  • Who is targeting us?                                              │
│  • What are their motivations?                                       │
│  • What are industry trends?                                         │
│  → Used for: Risk assessment, budget decisions                      │
│                                                                      │
│  TACTICAL (Security Team)                                           │
│  ─────────────────────────                                          │
│  • What TTPs do adversaries use?                                     │
│  • How do attacks progress?                                          │
│  • What tools do they use?                                           │
│  → Used for: Detection rules, security architecture                 │
│                                                                      │
│  OPERATIONAL (SOC/Hunt Team)                                        │
│  ───────────────────────────                                        │
│  • Who is attacking right now?                                       │
│  • What infrastructure are they using?                               │
│  • What are their current campaigns?                                 │
│  → Used for: Threat hunting, incident response                      │
│                                                                      │
│  TECHNICAL (Detection Systems)                                      │
│  ─────────────────────────────                                      │
│  • Specific IOCs (IPs, domains, hashes)                              │
│  • Malware signatures                                                │
│  • Network patterns                                                  │
│  → Used for: SIEM rules, firewall blocks, EDR policies             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Intelligence Sources

### Open Source Intelligence (OSINT)

| Source | Type | Focus Area |
|--------|------|------------|
| VirusTotal | Technical | File/URL/IP analysis |
| AlienVault OTX | Technical | IOC feeds |
| Shodan | Operational | Internet scanning data |
| MITRE ATT&CK | Tactical | TTPs database |
| abuse.ch | Technical | Malware/botnet IOCs |
| Hybrid Analysis | Technical | Malware sandboxing |

### USB/HID Specific Sources

| Source | Information |
|--------|-------------|
| Hak5 Forums | New payload techniques |
| Flipper Zero Discord | Device capabilities |
| GitHub Repositories | Public payloads |
| Security Conferences | Research presentations |
| CISA Advisories | Official warnings |

### Mining/Botnet Specific Sources

| Source | Information |
|--------|-------------|
| abuse.ch Feodo Tracker | Botnet C2 servers |
| MalwareBazaar | Malware samples |
| URLhaus | Malicious URLs |
| Mining Pool Lists | Known pool domains |
| Cryptolaemus | Banking trojan/miner intel |

---

## IOC Management

### IOC Types for USB Attacks

```yaml
# USB/HID Attack IOCs
usb_iocs:
  device_identifiers:
    - type: VID/PID
      value: "VID_0483&PID_5740"
      description: "Flipper Zero default"
      
    - type: VID/PID
      value: "VID_FEED"
      description: "Common BadUSB"
      
    - type: VID/PID
      value: "VID_1337"
      description: "Hak5 devices"

  file_hashes:
    - type: SHA256
      value: "abc123..."
      description: "Known miner binary"
      
  domains:
    - type: C2
      value: "evil.example.com"
      description: "Payload staging server"
      
  ip_addresses:
    - type: C2
      value: "185.x.x.x"
      description: "Command and control"
      
  registry_keys:
    - type: Persistence
      value: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\payload"
      
  process_names:
    - type: Miner
      value: "xmrig.exe"
      variants: ["xmr.exe", "miner.exe", "svchost.exe (fake)"]
```

### Mining IOCs

```yaml
# Cryptocurrency Mining IOCs
mining_iocs:
  domains:
    - pool.minexmr.com
    - xmr.nanopool.org
    - supportxmr.com
    - monerohash.com
    - pool.hashvault.pro
    - xmrpool.eu
    - moneroocean.stream
    
  ports:
    - 3333  # Stratum standard
    - 3334  # Stratum SSL
    - 4444  # Alternative
    - 5555  # Alternative
    - 14444 # Common XMR
    - 14433 # XMR SSL
    
  wallet_patterns:
    monero: "4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"
    bitcoin: "[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    ethereum: "0x[a-fA-F0-9]{40}"
    
  file_names:
    - xmrig
    - xmr-stak
    - cpuminer
    - ccminer
    - ethminer
    - phoenixminer
```

---

## Threat Hunting

### Hunt Hypotheses for USB Attacks

```
┌─────────────────────────────────────────────────────────────────────┐
│              USB/HID THREAT HUNTING HYPOTHESES                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  HYPOTHESIS 1: Unauthorized USB HID devices connected               │
│  ─────────────────────────────────────────────────────              │
│  Data Sources: USB device logs, EDR telemetry                       │
│  Hunt Query: Find USB HID devices not in approved list              │
│  Expected Outcome: Identify unknown/suspicious devices              │
│                                                                      │
│  HYPOTHESIS 2: PowerShell spawned from explorer.exe                 │
│  ─────────────────────────────────────────────────────              │
│  Data Sources: Sysmon Event ID 1, EDR process events                │
│  Hunt Query: explorer.exe → powershell.exe chain                    │
│  Expected Outcome: Detect potential keystroke injection             │
│                                                                      │
│  HYPOTHESIS 3: Encoded commands executed                            │
│  ─────────────────────────────────────────────────────              │
│  Data Sources: PowerShell logs, process command lines               │
│  Hunt Query: Find -enc/-EncodedCommand flags                        │
│  Expected Outcome: Identify obfuscated payload execution            │
│                                                                      │
│  HYPOTHESIS 4: Registry Run key persistence                         │
│  ─────────────────────────────────────────────────────              │
│  Data Sources: Sysmon Event ID 12/13, registry logs                 │
│  Hunt Query: New Run key entries from non-installers                │
│  Expected Outcome: Detect persistence mechanisms                    │
│                                                                      │
│  HYPOTHESIS 5: Cryptocurrency mining activity                       │
│  ─────────────────────────────────────────────────────              │
│  Data Sources: Network traffic, process CPU usage                   │
│  Hunt Query: Stratum connections, high CPU processes                │
│  Expected Outcome: Identify cryptomining infections                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Hunt Queries

```kql
// Hunt: Unauthorized USB HID Devices
DeviceEvents
| where ActionType == "UsbDeviceConnected"
| where DeviceType == "HID"
| summarize count() by DeviceId, DeviceName
| join kind=leftanti (
    // Approved device list
    datatable(DeviceId:string)["VID_045E*", "VID_046D*"]
) on DeviceId
| project DeviceName, DeviceId, count_

// Hunt: PowerShell from Explorer
DeviceProcessEvents
| where InitiatingProcessFileName == "explorer.exe"
| where FileName in ("powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc

// Hunt: Encoded PowerShell Commands
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc" or
        ProcessCommandLine contains "-EncodedCommand" or
        ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, ProcessCommandLine

// Hunt: Mining Pool Connections
DeviceNetworkEvents
| where RemotePort in (3333, 3334, 4444, 14444, 14433)
| summarize count() by DeviceName, RemoteIP, RemotePort
| order by count_ desc

// Hunt: High CPU Processes
DeviceProcessEvents
| where ProcessCPUUsage > 80
| where Timestamp > ago(24h)
| summarize AvgCPU = avg(ProcessCPUUsage) by DeviceName, FileName
| where AvgCPU > 60
| order by AvgCPU desc
```

---

## IOC Integration

### SIEM Integration

```yaml
# IOC feed configuration for SIEM
ioc_feeds:
  - name: "USB_BadUSB_Devices"
    type: "device_ids"
    format: "csv"
    update_interval: "daily"
    action: "alert"
    
  - name: "Mining_Pool_Domains"
    type: "domain"
    format: "stix"
    update_interval: "hourly"
    action: "block_and_alert"
    
  - name: "Malware_Hashes"
    type: "file_hash"
    format: "json"
    update_interval: "hourly"
    action: "block"
    
  - name: "C2_IPs"
    type: "ip"
    format: "plain"
    update_interval: "15min"
    action: "block_and_alert"
```

### Automated IOC Processing

```python
#!/usr/bin/env python3
"""
IOC Processing Script
Collects, deduplicates, and distributes IOCs
"""

import json
import requests
from datetime import datetime

class IOCProcessor:
    def __init__(self):
        self.iocs = {
            'domains': set(),
            'ips': set(),
            'hashes': set(),
            'usb_ids': set()
        }
    
    def fetch_mining_pools(self):
        """Fetch known mining pool domains"""
        pools = [
            "pool.minexmr.com",
            "xmr.nanopool.org",
            "supportxmr.com",
            "monerohash.com",
            "pool.hashvault.pro"
        ]
        self.iocs['domains'].update(pools)
    
    def fetch_badusb_ids(self):
        """Fetch known BadUSB device IDs"""
        devices = [
            "VID_0483&PID_5740",  # Flipper Zero
            "VID_FEED",           # Generic BadUSB
            "VID_1337",           # Hak5
            "VID_F000"            # O.MG Cable
        ]
        self.iocs['usb_ids'].update(devices)
    
    def export_for_siem(self, output_file):
        """Export IOCs in SIEM-compatible format"""
        output = {
            'generated': datetime.utcnow().isoformat(),
            'iocs': {
                'domains': list(self.iocs['domains']),
                'ips': list(self.iocs['ips']),
                'hashes': list(self.iocs['hashes']),
                'usb_ids': list(self.iocs['usb_ids'])
            }
        }
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
    
    def export_for_firewall(self, output_file):
        """Export IOCs for firewall blocking"""
        with open(output_file, 'w') as f:
            f.write("# Mining Pool Domains - Block\n")
            for domain in self.iocs['domains']:
                f.write(f"{domain}\n")

if __name__ == "__main__":
    processor = IOCProcessor()
    processor.fetch_mining_pools()
    processor.fetch_badusb_ids()
    processor.export_for_siem('/var/iocs/current.json')
    processor.export_for_firewall('/var/iocs/blocklist.txt')
```

---

## Threat Actor Profiles

### USB Attack Actor Categories

```
┌─────────────────────────────────────────────────────────────────────┐
│              USB ATTACK THREAT ACTORS                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  OPPORTUNISTIC ATTACKERS                                            │
│  ───────────────────────                                            │
│  Motivation: Financial gain, experimentation                        │
│  Capability: Low to Medium                                          │
│  Targets: Any vulnerable system                                     │
│  Common Payloads: Cryptominers, info stealers                       │
│  TTPs:                                                               │
│  • Pre-built payloads from internet                                 │
│  • Public BadUSB tools                                               │
│  • Random targeting (USB drops)                                     │
│                                                                      │
│  TARGETED ATTACKERS                                                 │
│  ─────────────────                                                  │
│  Motivation: Espionage, sabotage, specific data                     │
│  Capability: Medium to High                                         │
│  Targets: Specific organizations/individuals                        │
│  Common Payloads: Custom RATs, data exfiltration                    │
│  TTPs:                                                               │
│  • Social engineering for USB insertion                             │
│  • Custom payload development                                        │
│  • Reconnaissance before attack                                     │
│                                                                      │
│  INSIDER THREATS                                                    │
│  ────────────────                                                   │
│  Motivation: Revenge, financial, ideology                           │
│  Capability: Varies (low to high)                                   │
│  Targets: Employer systems and data                                 │
│  Common Payloads: Data theft, sabotage                              │
│  TTPs:                                                               │
│  • Legitimate access to systems                                     │
│  • Knowledge of security controls                                   │
│  • May use legitimate admin tools                                   │
│                                                                      │
│  RED TEAM / PENTESTERS (Authorized)                                 │
│  ─────────────────────────────────                                  │
│  Motivation: Security testing                                       │
│  Capability: High                                                   │
│  Targets: Client-authorized systems                                 │
│  Common Payloads: Full-featured frameworks                          │
│  TTPs:                                                               │
│  • Advanced evasion techniques                                      │
│  • Multi-stage payloads                                              │
│  • C2 frameworks (Cobalt Strike, etc.)                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Intelligence Sharing

### STIX/TAXII Format

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--badusb-flipper-001",
  "created": "2024-01-01T00:00:00.000Z",
  "modified": "2024-01-01T00:00:00.000Z",
  "name": "Flipper Zero Default USB ID",
  "description": "USB VID/PID for Flipper Zero device in BadUSB mode",
  "indicator_types": ["malicious-activity"],
  "pattern": "[file:hashes.'SHA-256' = 'example'] OR [usb-device:vendor_id = '0483' AND usb-device:product_id = '5740']",
  "pattern_type": "stix",
  "valid_from": "2024-01-01T00:00:00.000Z",
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "initial-access"
    }
  ],
  "labels": ["badusb", "flipper", "hid-attack"]
}
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│           THREAT INTELLIGENCE QUICK REFERENCE                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  KEY INTELLIGENCE SOURCES:                                          │
│  ├── VirusTotal - File/URL analysis                                │
│  ├── AlienVault OTX - IOC feeds                                    │
│  ├── MITRE ATT&CK - TTP database                                   │
│  ├── abuse.ch - Malware/botnet intel                               │
│  └── Hak5/Flipper communities - USB attack techniques              │
│                                                                      │
│  BADUSB IOC CATEGORIES:                                             │
│  ├── USB VID/PID (device identifiers)                              │
│  ├── File hashes (payload binaries)                                │
│  ├── C2 domains and IPs                                             │
│  ├── Registry persistence paths                                     │
│  └── Process names and patterns                                     │
│                                                                      │
│  MINING IOC CATEGORIES:                                             │
│  ├── Pool domains and IPs                                           │
│  ├── Stratum ports (3333, 4444, 14444)                             │
│  ├── Miner binary hashes                                            │
│  ├── Wallet address patterns                                        │
│  └── Process names (xmrig, cpuminer)                               │
│                                                                      │
│  HUNT PRIORITIES:                                                   │
│  1. Unknown USB HID devices                                         │
│  2. PowerShell from explorer.exe                                    │
│  3. Encoded command execution                                       │
│  4. Registry Run key modifications                                  │
│  5. Mining pool connections                                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Incident Response](../07_Incident_Response/) | [Back to Security Operations](../README.md) | [Back to Main →](../../README.md)
