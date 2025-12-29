# Incident Response

## Overview

Effective incident response minimizes damage and enables rapid recovery from security incidents. This section provides playbooks and procedures for responding to USB/HID attacks, wireless compromises, and cryptomining infections.

---

## Incident Response Framework

```
┌─────────────────────────────────────────────────────────────────────┐
│               INCIDENT RESPONSE LIFECYCLE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│       ┌───────────────────────────────────────────────┐             │
│       │                                               │             │
│       ▼                                               │             │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐       │             │
│   │          │    │          │    │          │       │             │
│   │ PREPARE  │───▶│ IDENTIFY │───▶│ CONTAIN  │       │             │
│   │          │    │          │    │          │       │             │
│   └──────────┘    └──────────┘    └──────────┘       │             │
│                                         │             │             │
│                                         ▼             │             │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐       │             │
│   │          │    │          │    │          │       │             │
│   │ LESSONS  │◀───│ RECOVER  │◀───│ERADICATE │       │             │
│   │ LEARNED  │    │          │    │          │       │             │
│   └──────────┘    └──────────┘    └──────────┘       │             │
│       │                                               │             │
│       └───────────────────────────────────────────────┘             │
│                    (Continuous Improvement)                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Playbook: BadUSB Attack Response

### Detection Triggers

| Alert Source | Indicator | Priority |
|--------------|-----------|----------|
| EDR | Suspicious USB HID device | Critical |
| SIEM | Rapid command execution from explorer | High |
| EDR | PowerShell encoded commands | High |
| SIEM | Registry Run key modification | Medium |
| EDR | Unknown process network connection | Medium |

### Response Procedure

```
┌─────────────────────────────────────────────────────────────────────┐
│              BADUSB INCIDENT RESPONSE PLAYBOOK                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PHASE 1: IDENTIFICATION (0-15 minutes)                             │
│  ══════════════════════════════════════                             │
│                                                                      │
│  □ 1.1 Review alert details                                        │
│     - Alert type and severity                                       │
│     - Affected host(s)                                              │
│     - User account(s)                                               │
│     - Timestamp                                                     │
│                                                                      │
│  □ 1.2 Validate alert (check for false positive)                   │
│     - Was this authorized testing?                                  │
│     - Is user aware of USB device?                                  │
│     - Check asset inventory for expected devices                    │
│                                                                      │
│  □ 1.3 Assess scope                                                │
│     - Single host or multiple?                                      │
│     - Evidence of lateral movement?                                 │
│     - Data accessed?                                                │
│                                                                      │
│  □ 1.4 Document findings                                           │
│     - Start incident timeline                                       │
│     - Record all indicators                                         │
│                                                                      │
│  PHASE 2: CONTAINMENT (15-45 minutes)                               │
│  ═════════════════════════════════════                              │
│                                                                      │
│  □ 2.1 Isolate affected endpoint                                   │
│     - EDR network isolation (preferred)                             │
│     - Physical network disconnect (if needed)                       │
│     - Do NOT power off (preserve memory)                           │
│                                                                      │
│  □ 2.2 Block identified IOCs                                       │
│     - Block C2 IPs/domains at firewall                             │
│     - Add file hashes to EDR blocklist                             │
│     - Update DNS blackhole                                          │
│                                                                      │
│  □ 2.3 Preserve evidence                                           │
│     - Memory dump (if possible)                                     │
│     - Disk image (if needed)                                        │
│     - Log export from SIEM/EDR                                      │
│                                                                      │
│  □ 2.4 Secure the USB device                                       │
│     - Do NOT connect to other systems                              │
│     - Photograph/document device                                    │
│     - Store securely as evidence                                    │
│                                                                      │
│  □ 2.5 Notify stakeholders                                         │
│     - Security management                                           │
│     - Affected user's manager                                       │
│     - Legal/HR (if insider threat suspected)                       │
│                                                                      │
│  PHASE 3: ERADICATION (45 min - 4 hours)                            │
│  ═══════════════════════════════════════                            │
│                                                                      │
│  □ 3.1 Terminate malicious processes                               │
│     - Kill any running payload processes                           │
│     - Kill any miner processes                                      │
│     - Kill any C2 beacon processes                                 │
│                                                                      │
│  □ 3.2 Remove persistence mechanisms                               │
│     - Registry Run keys                                             │
│     - Scheduled tasks                                               │
│     - Startup folder items                                          │
│     - Services                                                      │
│                                                                      │
│  □ 3.3 Delete malicious files                                      │
│     - Payload executables                                           │
│     - Downloaded scripts                                            │
│     - Config files                                                  │
│                                                                      │
│  □ 3.4 Reset credentials                                           │
│     - User's domain password                                        │
│     - Any cached credentials                                        │
│     - Service accounts (if compromised)                            │
│                                                                      │
│  □ 3.5 Verify removal                                              │
│     - Full AV/EDR scan                                              │
│     - Check for persistence                                         │
│     - Network traffic analysis                                      │
│                                                                      │
│  PHASE 4: RECOVERY (1-8 hours)                                      │
│  ═════════════════════════════                                      │
│                                                                      │
│  □ 4.1 Restore system (if needed)                                  │
│     - Restore from known-good backup                               │
│     - Or rebuild from image                                         │
│                                                                      │
│  □ 4.2 Remove network isolation                                    │
│     - Verify clean state first                                      │
│     - Re-enable network access                                      │
│                                                                      │
│  □ 4.3 Enhanced monitoring                                         │
│     - Increase log verbosity for 30 days                           │
│     - Create custom detection rules                                 │
│     - Watch for reinfection                                         │
│                                                                      │
│  □ 4.4 User notification                                           │
│     - Inform user of incident                                       │
│     - Provide security awareness                                    │
│     - Explain new precautions                                       │
│                                                                      │
│  PHASE 5: LESSONS LEARNED (Within 1 week)                           │
│  ════════════════════════════════════════                           │
│                                                                      │
│  □ 5.1 Complete incident report                                    │
│  □ 5.2 Conduct debrief meeting                                     │
│  □ 5.3 Update detection rules                                      │
│  □ 5.4 Review/update security controls                             │
│  □ 5.5 Share IOCs with threat intel team                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Playbook: Cryptominer Response

```
┌─────────────────────────────────────────────────────────────────────┐
│              CRYPTOMINER INCIDENT RESPONSE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DETECTION INDICATORS:                                              │
│  ├── High CPU/GPU utilization (sustained >80%)                     │
│  ├── Connections to mining pools (ports 3333, 4444, etc.)          │
│  ├── Stratum protocol traffic                                       │
│  ├── Unknown processes consuming resources                          │
│  └── EDR/AV alerts for mining software                             │
│                                                                      │
│  IMMEDIATE ACTIONS (0-30 minutes):                                  │
│  ─────────────────────────────────                                  │
│  □ Confirm mining activity                                         │
│     ps aux | grep -i "xmrig\|miner\|cpuminer"                      │
│     netstat -an | grep -E "3333|4444|14444"                        │
│                                                                      │
│  □ Identify mining process                                         │
│     - Process ID and name                                           │
│     - Parent process (how was it started?)                         │
│     - Associated files                                              │
│                                                                      │
│  □ Block pool connections (immediate)                              │
│     iptables -A OUTPUT -p tcp --dport 3333 -j DROP                 │
│     iptables -A OUTPUT -p tcp --dport 4444 -j DROP                 │
│                                                                      │
│  □ Terminate miner process                                         │
│     kill -9 <PID>                                                   │
│     taskkill /F /PID <PID>                                         │
│                                                                      │
│  INVESTIGATION (30 min - 2 hours):                                  │
│  ─────────────────────────────────                                  │
│  □ Determine infection vector                                      │
│     - BadUSB device?                                                │
│     - Phishing email?                                               │
│     - Drive-by download?                                            │
│     - Vulnerable service?                                           │
│                                                                      │
│  □ Check for persistence                                           │
│     - Scheduled tasks                                               │
│     - Registry Run keys                                             │
│     - Cron jobs (Linux)                                             │
│     - Services                                                      │
│                                                                      │
│  □ Identify attacker's wallet                                      │
│     - Extract from config file                                      │
│     - Log for attribution                                           │
│                                                                      │
│  □ Check for other malware                                         │
│     - Miners often come with RATs                                   │
│     - Check for C2 communications                                   │
│     - Full system scan                                              │
│                                                                      │
│  REMEDIATION:                                                       │
│  ────────────                                                       │
│  □ Remove miner binary and config                                  │
│  □ Remove all persistence mechanisms                               │
│  □ Block mining pool domains/IPs                                   │
│  □ Reset credentials if needed                                     │
│  □ Patch vulnerability (if applicable)                             │
│  □ Update security controls                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Playbook: Wireless Attack Response

```
┌─────────────────────────────────────────────────────────────────────┐
│              WIRELESS ATTACK INCIDENT RESPONSE                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ATTACK TYPES:                                                      │
│  ├── Evil Twin / Rogue AP                                          │
│  ├── Deauthentication Attack                                       │
│  ├── Credential Capture (Captive Portal)                           │
│  └── WPA Handshake Capture                                         │
│                                                                      │
│  ROGUE AP DETECTED:                                                 │
│  ─────────────────                                                  │
│  □ Identify rogue AP location                                      │
│     - Signal strength analysis                                      │
│     - Physical search                                               │
│     - WiFi triangulation                                            │
│                                                                      │
│  □ Determine if clients connected                                  │
│     - Check RADIUS logs                                             │
│     - Review client connection logs                                 │
│     - Interview users in area                                       │
│                                                                      │
│  □ Disable/remove rogue AP                                         │
│     - WIPS automatic containment                                    │
│     - Physical removal                                              │
│     - Alert to physical security                                    │
│                                                                      │
│  □ Identify affected clients                                       │
│     - Review AP association logs                                    │
│     - Check for credential compromise                               │
│     - Reset passwords for affected users                           │
│                                                                      │
│  DEAUTH ATTACK IN PROGRESS:                                         │
│  ───────────────────────────                                        │
│  □ Confirm attack via WIDS                                         │
│  □ Identify source if possible                                     │
│  □ Enable PMF on infrastructure                                    │
│  □ Consider temporary SSID change                                  │
│  □ Alert users of potential phishing                               │
│  □ Physical security sweep                                         │
│                                                                      │
│  CREDENTIAL CAPTURE SUSPECTED:                                      │
│  ────────────────────────────                                       │
│  □ Identify potentially compromised accounts                       │
│  □ Force password reset                                             │
│  □ Review authentication logs                                       │
│  □ Check for unauthorized access                                    │
│  □ Enhance monitoring on affected accounts                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Evidence Collection

### Digital Evidence Checklist

```bash
#!/bin/bash
# Incident evidence collection script

EVIDENCE_DIR="/forensics/case_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

# System Information
hostname > "$EVIDENCE_DIR/hostname.txt"
date > "$EVIDENCE_DIR/timestamp.txt"
uname -a > "$EVIDENCE_DIR/system_info.txt"

# Running Processes
ps auxf > "$EVIDENCE_DIR/processes.txt"
lsof -i > "$EVIDENCE_DIR/open_files.txt"

# Network Connections
netstat -antup > "$EVIDENCE_DIR/network_connections.txt"
ss -tulpn > "$EVIDENCE_DIR/sockets.txt"
cat /etc/resolv.conf > "$EVIDENCE_DIR/dns_config.txt"

# USB Devices (Linux)
lsusb -v > "$EVIDENCE_DIR/usb_devices.txt"
dmesg | grep -i usb > "$EVIDENCE_DIR/usb_dmesg.txt"

# User Activity
last > "$EVIDENCE_DIR/user_logins.txt"
who > "$EVIDENCE_DIR/current_users.txt"
cat /etc/passwd > "$EVIDENCE_DIR/users.txt"

# Scheduled Tasks
crontab -l > "$EVIDENCE_DIR/user_crontab.txt"
cat /etc/crontab > "$EVIDENCE_DIR/system_crontab.txt"
ls -la /etc/cron.* > "$EVIDENCE_DIR/cron_dirs.txt"

# Hash evidence files
cd "$EVIDENCE_DIR"
sha256sum * > hashes.txt

echo "Evidence collected in: $EVIDENCE_DIR"
```

### Windows Evidence Collection

```powershell
# Windows incident evidence collection
$evidenceDir = "C:\Forensics\Case_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $evidenceDir -Force

# System Information
Get-ComputerInfo | Out-File "$evidenceDir\system_info.txt"
Get-Date | Out-File "$evidenceDir\timestamp.txt"

# Running Processes
Get-Process | Sort-Object CPU -Descending | Out-File "$evidenceDir\processes.txt"
Get-WmiObject Win32_Process | Select Name, ProcessId, ParentProcessId, CommandLine | 
    Out-File "$evidenceDir\processes_detailed.txt"

# Network Connections
Get-NetTCPConnection | Out-File "$evidenceDir\tcp_connections.txt"
Get-NetUDPEndpoint | Out-File "$evidenceDir\udp_connections.txt"

# USB Devices
Get-PnpDevice -Class USB | Out-File "$evidenceDir\usb_devices.txt"
Get-WinEvent -LogName System -MaxEvents 1000 | 
    Where-Object {$_.Message -match "USB"} | 
    Out-File "$evidenceDir\usb_events.txt"

# Scheduled Tasks
Get-ScheduledTask | Out-File "$evidenceDir\scheduled_tasks.txt"

# Registry Run Keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | 
    Out-File "$evidenceDir\registry_run_hklm.txt"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | 
    Out-File "$evidenceDir\registry_run_hkcu.txt"

# Recent PowerShell History
Get-History | Out-File "$evidenceDir\powershell_history.txt"
Get-Content (Get-PSReadLineOption).HistorySavePath | 
    Out-File "$evidenceDir\powershell_history_full.txt"

# Event Logs
Get-WinEvent -LogName Security -MaxEvents 5000 | 
    Export-Csv "$evidenceDir\security_events.csv"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5000 | 
    Export-Csv "$evidenceDir\sysmon_events.csv"

# Generate hashes
Get-ChildItem $evidenceDir -File | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    "$($hash.Hash) $($_.Name)" | Out-File "$evidenceDir\hashes.txt" -Append
}

Write-Host "Evidence collected in: $evidenceDir"
```

---

## Communication Templates

### Initial Incident Notification

```
Subject: [SECURITY INCIDENT] BadUSB/HID Attack Detected - [HOSTNAME]

Priority: HIGH

SUMMARY:
A potential BadUSB attack has been detected on [HOSTNAME].

DETAILS:
- Detection Time: [TIMESTAMP]
- Affected System: [HOSTNAME/IP]
- Affected User: [USERNAME]
- Alert Source: [EDR/SIEM ALERT NAME]

INITIAL INDICATORS:
- [USB device connected with VID/PID]
- [Rapid command execution detected]
- [Suspicious process activity]

CURRENT STATUS:
[  ] Investigating
[  ] Contained
[  ] Eradicated

IMMEDIATE ACTIONS TAKEN:
1. Endpoint isolated from network
2. Malicious processes terminated
3. Evidence collection initiated

NEXT STEPS:
1. Complete forensic analysis
2. Identify scope of compromise
3. Eradicate persistence mechanisms

POINT OF CONTACT:
[Analyst Name] - [Contact Info]

Updates will be provided every [30 minutes/1 hour] until resolved.
```

### Incident Closure Report

```
INCIDENT CLOSURE REPORT
=======================

Incident ID: [INC-XXXX]
Date Opened: [DATE]
Date Closed: [DATE]
Total Duration: [X hours/days]

EXECUTIVE SUMMARY:
[Brief description of incident and resolution]

TIMELINE:
[TIME] - Initial detection
[TIME] - Containment initiated
[TIME] - Investigation began
[TIME] - Root cause identified
[TIME] - Eradication completed
[TIME] - Recovery completed
[TIME] - Incident closed

ROOT CAUSE:
[Description of how the attack occurred]

IMPACT ASSESSMENT:
- Systems Affected: [COUNT]
- Users Affected: [COUNT]
- Data Compromised: [YES/NO - Details]
- Business Impact: [Description]

REMEDIATION ACTIONS:
1. [Action taken]
2. [Action taken]
3. [Action taken]

LESSONS LEARNED:
1. [What could be improved]
2. [What worked well]
3. [Recommended changes]

RECOMMENDATIONS:
1. [Short-term recommendation]
2. [Long-term recommendation]

APPENDICES:
A. IOC List
B. Timeline Details
C. Evidence Inventory
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│            INCIDENT RESPONSE QUICK REFERENCE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  FIRST RESPONSE PRIORITIES:                                         │
│  1. Validate the alert                                              │
│  2. Isolate affected system(s)                                      │
│  3. Preserve evidence (DON'T power off!)                           │
│  4. Notify stakeholders                                             │
│                                                                      │
│  CONTAINMENT OPTIONS:                                               │
│  ├── EDR network isolation (preferred)                             │
│  ├── Switch port disable                                            │
│  ├── Firewall block                                                 │
│  └── Physical disconnect (last resort)                             │
│                                                                      │
│  EVIDENCE TO COLLECT:                                               │
│  ├── Memory dump                                                    │
│  ├── Process list                                                   │
│  ├── Network connections                                            │
│  ├── USB device info                                                │
│  ├── Registry (Run keys, services)                                  │
│  └── Relevant logs                                                  │
│                                                                      │
│  KEY QUESTIONS:                                                     │
│  ├── How did they get in?                                          │
│  ├── What did they do?                                              │
│  ├── Are they still in?                                             │
│  ├── What data was accessed?                                        │
│  └── Have they spread?                                              │
│                                                                      │
│  NEVER DO:                                                          │
│  ├── Power off without memory capture                              │
│  ├── Delete evidence files                                          │
│  ├── Connect suspicious USB elsewhere                              │
│  └── Skip documentation                                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Security Hardening](../06_Security_Hardening/) | [Back to Security Operations](../README.md) | [Next: Threat Intelligence →](../08_Threat_Intelligence/)
