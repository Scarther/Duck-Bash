# Security Monitoring & SIEM

## Overview

Security Information and Event Management (SIEM) systems provide centralized log collection, correlation, alerting, and analysis capabilities. This section covers implementing SIEM for detecting USB/HID and wireless attacks.

---

## SIEM Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      SIEM ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   LOG SOURCES                    SIEM PLATFORM                      │
│   ───────────                    ─────────────                      │
│                                                                      │
│   ┌──────────┐                   ┌────────────────────────────┐    │
│   │ Windows  │───────────────────▶│                            │    │
│   │ Events   │                   │    ┌──────────────────┐    │    │
│   └──────────┘                   │    │  Log Collection  │    │    │
│                                   │    │  & Parsing       │    │    │
│   ┌──────────┐                   │    └────────┬─────────┘    │    │
│   │ Sysmon   │───────────────────▶│             │              │    │
│   │          │                   │    ┌────────▼─────────┐    │    │
│   └──────────┘                   │    │  Normalization   │    │    │
│                                   │    │  & Enrichment    │    │    │
│   ┌──────────┐                   │    └────────┬─────────┘    │    │
│   │ Network  │───────────────────▶│             │              │    │
│   │ Devices  │                   │    ┌────────▼─────────┐    │    │
│   └──────────┘                   │    │  Correlation     │    │    │
│                                   │    │  Engine          │    │    │
│   ┌──────────┐                   │    └────────┬─────────┘    │    │
│   │ Wireless │───────────────────▶│             │              │    │
│   │ Systems  │                   │    ┌────────▼─────────┐    │    │
│   └──────────┘                   │    │  Alerting &      │    │    │
│                                   │    │  Dashboards      │    │    │
│   ┌──────────┐                   │    └────────┬─────────┘    │    │
│   │  EDR     │───────────────────▶│             │              │    │
│   │          │                   │             ▼              │    │
│   └──────────┘                   │      SECURITY TEAM        │    │
│                                   │                            │    │
│                                   └────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Essential Log Sources

### Windows Event Logs

| Event ID | Source | Description | Relevance |
|----------|--------|-------------|-----------|
| 4624 | Security | Successful logon | Track authentication |
| 4625 | Security | Failed logon | Brute force detection |
| 4688 | Security | Process creation | Command execution |
| 4657 | Security | Registry value modified | Persistence detection |
| 2003 | System | USB device connected | BadUSB detection |
| 7045 | System | Service installed | Persistence detection |

### Sysmon Events

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| 1 | Process creation | Payload execution |
| 3 | Network connection | C2 communication |
| 7 | Image loaded | DLL injection |
| 11 | File create | Payload drops |
| 12/13/14 | Registry events | Persistence |
| 22 | DNS query | C2 domain lookup |

### Network Logs

```
Essential Network Sources:
├── Firewall logs
│   ├── Allowed/denied connections
│   ├── NAT translations
│   └── Policy violations
│
├── DNS logs
│   ├── Query requests
│   ├── Response data
│   └── Failed lookups
│
├── DHCP logs
│   ├── IP assignments
│   └── Lease changes
│
├── Proxy/Web filter logs
│   ├── HTTP/HTTPS traffic
│   ├── Blocked categories
│   └── User activity
│
└── IDS/IPS logs
    ├── Alert events
    └── Block actions
```

---

## SIEM Platforms

### Open Source Options

| Platform | Strengths | Considerations |
|----------|-----------|----------------|
| Wazuh | Free, active development | Requires tuning |
| Elastic SIEM | Powerful search, visualizations | Resource intensive |
| OSSIM | All-in-one solution | Steeper learning curve |
| Graylog | Fast search, scalable | Limited correlation |

### Commercial Options

| Platform | Strengths | Considerations |
|----------|-----------|----------------|
| Splunk | Industry leader, extensive apps | Expensive licensing |
| Microsoft Sentinel | Native Azure integration | Cloud-focused |
| QRadar | Strong correlation | Complex deployment |
| LogRhythm | Good out-of-box content | License model |

---

## Detection Rules for USB/HID Attacks

### Sigma Rule: Suspicious USB HID Device

```yaml
title: Suspicious USB HID Device Connection
id: usb-hid-suspicious-001
status: experimental
description: Detects known BadUSB device VID/PID combinations
references:
    - https://github.com/flipperdevices/flipperzero-firmware
author: Security Team
date: 2024/01/01

logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 2003
        DeviceId|contains:
            - 'VID_0483&PID_5740'  # Flipper Zero
            - 'VID_FEED'           # Common BadUSB
            - 'VID_1337'           # Hak5 devices
            - 'VID_F000'           # O.MG Cable
    condition: selection
falsepositives:
    - Legitimate STM32 development boards
    - Authorized security testing devices
level: high
tags:
    - attack.initial_access
    - attack.t1200
```

### Sigma Rule: Rapid Command Execution

```yaml
title: Rapid Command Execution from Explorer
id: badusb-rapid-exec-001
status: experimental
description: Detects multiple command-line processes spawned from explorer in short time
author: Security Team
date: 2024/01/01

logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage|endswith: '\explorer.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    timeframe: 30s
    condition: selection | count() > 3
falsepositives:
    - Batch file execution
    - Legitimate automation
level: high
tags:
    - attack.execution
    - attack.t1059
```

### Sigma Rule: PowerShell Encoded Commands

```yaml
title: PowerShell Encoded Command Execution
id: ps-encoded-001
status: experimental
description: Detects Base64 encoded PowerShell commands commonly used by BadUSB
author: Security Team
date: 2024/01/01

logsource:
    product: windows
    service: powershell
detection:
    selection_encoding:
        EventID: 4104
        ScriptBlockText|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-ec'
            - 'FromBase64String'
    selection_suspicious:
        ScriptBlockText|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'downloadstring'
            - 'Net.WebClient'
    condition: selection_encoding or selection_suspicious
falsepositives:
    - Legitimate encoded scripts
    - Software deployment tools
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

---

## Detection Rules for Wireless Attacks

### Sigma Rule: Deauthentication Flood

```yaml
title: WiFi Deauthentication Flood Detected
id: wifi-deauth-flood-001
status: experimental
description: Detects high volume of deauthentication frames
author: Security Team
date: 2024/01/01

logsource:
    product: kismet
    service: wireless
detection:
    selection:
        alert_type: 'DEAUTHFLOOD'
    condition: selection
falsepositives:
    - Legitimate network maintenance
    - Client roaming issues
level: high
tags:
    - attack.impact
    - attack.t1498
```

### Custom Alert: Evil Twin Detection

```python
# Splunk SPL for Evil Twin Detection
index=wireless sourcetype=wids
| stats dc(bssid) as bssid_count by ssid
| where bssid_count > 1
| lookup known_aps.csv ssid OUTPUT known_bssid
| where bssid != known_bssid
| table _time, ssid, bssid, known_bssid, signal_strength

# Alert condition: When results > 0
```

---

## Correlation Rules

### BadUSB Attack Chain

```
CORRELATION: BadUSB Attack Chain Detection

Rule Logic:
IF (USB HID device connected within last 5 minutes)
AND (PowerShell or CMD launched from explorer.exe)
AND (Registry Run key modified OR Scheduled Task created)
THEN Alert: Potential BadUSB Attack Chain

Events to Correlate:
├── Event 2003: USB device connected (T-0)
├── Event 1: Process creation (T+0 to T+30s)
├── Event 13: Registry value set (T+0 to T+60s)
└── Event 106: Scheduled task registered (T+0 to T+60s)
```

### Wireless Compromise Chain

```
CORRELATION: Wireless Attack Chain Detection

Rule Logic:
IF (Deauth frames detected against client)
AND (Same client reconnects within 60 seconds)
AND (EAPOL handshake captured)
THEN Alert: Potential WPA Handshake Capture Attack

Events to Correlate:
├── WIDS Alert: DEAUTHFLOOD (T-0)
├── AP Log: Client disconnect (T+0 to T+5s)
├── AP Log: Client reconnect (T+5 to T+30s)
└── WIDS Alert: Handshake captured (T+30 to T+60s)
```

---

## Dashboard Components

### USB Security Dashboard

```
┌─────────────────────────────────────────────────────────────────────┐
│                  USB SECURITY DASHBOARD                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │ USB Connections │  │ Unknown Devices │  │ BadUSB Alerts   │     │
│  │     Today       │  │    This Week    │  │   This Month    │     │
│  │      247        │  │       12        │  │        3        │     │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘     │
│                                                                      │
│  USB Connections Over Time                                          │
│  ─────────────────────────                                          │
│  │     ╭─╮                                                          │
│  │    ╭╯ ╰╮     ╭─╮                                                 │
│  │   ╭╯   ╰─────╯ ╰╮    ╭──╮                                       │
│  │  ╭╯              ╰────╯  ╰─╮                                     │
│  │ ╭╯                        ╰─────                                 │
│  └──────────────────────────────────▶ Time                         │
│                                                                      │
│  Top 10 USB Devices by Connection Count                            │
│  ───────────────────────────────────────                            │
│  1. Microsoft USB Keyboard (VID_045E)      ████████████  892       │
│  2. Logitech Mouse (VID_046D)              ██████████    756       │
│  3. Dell Keyboard (VID_413C)               ████████      534       │
│  ...                                                                 │
│                                                                      │
│  Recent Suspicious Events                                           │
│  ────────────────────────                                           │
│  │ Time       │ Host      │ Event                    │ Severity │  │
│  │ 14:32:01   │ WS-042    │ Unknown HID device       │ HIGH     │  │
│  │ 14:30:45   │ WS-042    │ Rapid keystroke pattern  │ CRITICAL │  │
│  │ 13:15:22   │ WS-108    │ PowerShell from explorer │ MEDIUM   │  │
│  └────────────────────────────────────────────────────────────────  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Wireless Security Dashboard

```
┌─────────────────────────────────────────────────────────────────────┐
│                 WIRELESS SECURITY DASHBOARD                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │ Authorized APs  │  │ Unknown APs     │  │ Active Alerts   │     │
│  │                 │  │   Detected      │  │                 │     │
│  │      42         │  │        5        │  │        2        │     │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘     │
│                                                                      │
│  AP Map / Signal Strength                                           │
│  ─────────────────────────                                          │
│       Building A              Building B                            │
│    ┌───────────────┐       ┌───────────────┐                       │
│    │ ○    ○    ○   │       │ ○    ○    ○   │                       │
│    │   AP-1  AP-2  │       │   AP-5  AP-6  │                       │
│    │ ○    ⚠    ○   │       │ ○    ○    ○   │                       │
│    │   AP-3  ???   │       │   AP-7  AP-8  │                       │
│    │ ○    ○    ○   │       │ ○    ○    ○   │                       │
│    └───────────────┘       └───────────────┘                       │
│                                                                      │
│  ⚠ = Unknown/Suspicious AP                                          │
│                                                                      │
│  WIDS Alert Timeline                                                │
│  ──────────────────                                                 │
│  │ Time       │ Type           │ Target        │ Status    │       │
│  │ 14:45:00   │ Deauth Flood   │ Corp-WiFi     │ Active    │       │
│  │ 14:30:00   │ Evil Twin      │ Guest-WiFi    │ Resolved  │       │
│  │ 12:00:00   │ Rogue AP       │ N/A           │ Active    │       │
│  └────────────────────────────────────────────────────────────────  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Checklist

```
□ Log Collection
  □ Windows Security Events forwarded
  □ Sysmon deployed and logging
  □ PowerShell logging enabled
  □ Network device logs forwarded
  □ Wireless/WIDS logs integrated
  □ DNS query logging enabled

□ Parsing & Normalization
  □ Log parsers configured for all sources
  □ Field extraction validated
  □ Timezone normalization applied
  □ Asset enrichment configured

□ Detection Rules
  □ USB/HID detection rules deployed
  □ Wireless attack rules deployed
  □ Correlation rules configured
  □ False positive tuning completed
  □ Alert thresholds adjusted

□ Alerting & Response
  □ Alert routing configured
  □ Escalation procedures documented
  □ Response playbooks linked
  □ Notification channels tested

□ Dashboards & Reporting
  □ Security dashboards created
  □ Executive reports scheduled
  □ Compliance reports configured
  □ Metrics tracking enabled
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SIEM QUICK REFERENCE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  KEY WINDOWS EVENTS:                                                │
│  ├── 4624/4625 - Logon success/failure                             │
│  ├── 4688 - Process creation                                        │
│  ├── 4657 - Registry modification                                   │
│  ├── 2003 - USB device connected                                    │
│  └── 7045 - Service installation                                    │
│                                                                      │
│  KEY SYSMON EVENTS:                                                 │
│  ├── 1 - Process creation (with command line)                      │
│  ├── 3 - Network connection                                         │
│  ├── 11 - File creation                                             │
│  ├── 12/13/14 - Registry events                                     │
│  └── 22 - DNS query                                                 │
│                                                                      │
│  BADUSB INDICATORS:                                                 │
│  ├── Suspicious VID/PID (0483, FEED, 1337)                         │
│  ├── Rapid keystroke injection                                      │
│  ├── PowerShell from explorer.exe                                   │
│  └── Encoded/obfuscated commands                                    │
│                                                                      │
│  WIRELESS INDICATORS:                                               │
│  ├── Duplicate SSID, different BSSID                               │
│  ├── Deauth frame floods                                            │
│  ├── Unknown AP in managed space                                    │
│  └── Failed 802.1X authentication spikes                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Blue Team Fundamentals](../01_Blue_Team_Fundamentals/) | [Back to Security Operations](../README.md) | [Next: EDR →](../03_EDR/)
