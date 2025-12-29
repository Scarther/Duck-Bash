# MITRE ATT&CK Quick Reference for BadUSB

## BadUSB-Relevant Techniques

### Initial Access (TA0001)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1091 | Replication Through Removable Media | Direct USB-based delivery |
| T1200 | Hardware Additions | Physical device insertion |

### Execution (TA0002)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1059.001 | PowerShell | Primary Windows payload execution |
| T1059.003 | Windows Command Shell | CMD-based payloads |
| T1059.004 | Unix Shell | Linux/macOS payloads |
| T1059.005 | Visual Basic | VBScript droppers |
| T1059.006 | Python | Python-based payloads |
| T1204.002 | User Execution: Malicious File | Dropped executable |

### Persistence (TA0003)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1547.001 | Registry Run Keys | Auto-start via registry |
| T1547.009 | Shortcut Modification | Startup folder shortcuts |
| T1053.005 | Scheduled Task | Task scheduler persistence |
| T1546.003 | WMI Event Subscription | WMI-based persistence |
| T1546.008 | Accessibility Features | Sticky keys backdoor |
| T1136.001 | Local Account | Create backdoor user |
| T1098 | Account Manipulation | Add user to admins |

### Privilege Escalation (TA0004)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1548.002 | Bypass UAC | Elevated execution |
| T1134 | Access Token Manipulation | Token impersonation |

### Defense Evasion (TA0005)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1562.001 | Disable or Modify Tools | Disable AV/Defender |
| T1070.001 | Clear Windows Event Logs | Log cleanup |
| T1070.003 | Clear Command History | History deletion |
| T1027 | Obfuscated Files | Encoded payloads |
| T1140 | Deobfuscate/Decode | Base64 execution |
| T1218.005 | Mshta | HTA execution |
| T1218.010 | Regsvr32 | Scriptlet execution |
| T1218.011 | Rundll32 | DLL execution |

### Credential Access (TA0006)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1555.003 | Credentials from Web Browsers | Browser password theft |
| T1552.001 | Credentials in Files | Search for creds |
| T1552.002 | Credentials in Registry | Registry credential dump |
| T1003.001 | LSASS Memory | Mimikatz credential dump |
| T1552.004 | Private Keys | SSH key theft |
| T1555.004 | Windows Credential Manager | Saved credentials |

### Discovery (TA0007)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1082 | System Information Discovery | systeminfo, hostname |
| T1016 | System Network Configuration | ipconfig, ifconfig |
| T1033 | System Owner/User Discovery | whoami |
| T1057 | Process Discovery | tasklist, ps |
| T1083 | File and Directory Discovery | dir, find |
| T1087.001 | Local Account Discovery | net user |
| T1135 | Network Share Discovery | net share |

### Collection (TA0009)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1005 | Data from Local System | File harvesting |
| T1039 | Data from Network Shared Drive | Shared drive access |
| T1560.001 | Archive via Utility | Compress for exfil |
| T1119 | Automated Collection | Scripted collection |

### Command and Control (TA0011)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1071.001 | Web Protocols | HTTP/HTTPS C2 |
| T1071.004 | DNS | DNS tunneling |
| T1105 | Ingress Tool Transfer | Download stager |
| T1573 | Encrypted Channel | HTTPS C2 |
| T1572 | Protocol Tunneling | ICMP, DNS tunnels |

### Exfiltration (TA0010)

| ID | Technique | BadUSB Relevance |
|----|-----------|------------------|
| T1041 | Exfil Over C2 Channel | HTTP POST exfil |
| T1048.001 | Exfil Over Alternative Protocol | DNS exfil |
| T1567.002 | Exfil to Cloud Storage | Cloud upload |

---

## Quick Mapping Table

### By Payload Type

| Payload Type | Primary Techniques |
|--------------|-------------------|
| Credential Harvester | T1555.003, T1552.001, T1003.001 |
| Reverse Shell | T1059.001, T1071.001, T1105 |
| Persistence | T1547.001, T1053.005, T1136.001 |
| Reconnaissance | T1082, T1016, T1033, T1083 |
| Data Exfiltration | T1005, T1560.001, T1041 |
| AV Evasion | T1562.001, T1027, T1140 |

### By Operating System

**Windows Payloads:**
```
T1059.001 (PowerShell)
T1547.001 (Registry Run Keys)
T1053.005 (Scheduled Task)
T1548.002 (UAC Bypass)
T1562.001 (Disable Defender)
T1555.003 (Browser Creds)
```

**Linux Payloads:**
```
T1059.004 (Unix Shell)
T1053.003 (Cron)
T1098 (SSH Keys)
T1552.004 (Private Keys)
```

**macOS Payloads:**
```
T1059.004 (Unix Shell)
T1547.015 (Login Items)
T1059.002 (AppleScript)
```

---

## Detection Recommendations by Technique

### High Priority Detection

| Technique | Detection Method |
|-----------|------------------|
| T1059.001 | PowerShell logging (ScriptBlock, Module) |
| T1547.001 | Registry monitoring (Run keys) |
| T1053.005 | Task scheduler event monitoring |
| T1562.001 | Windows Defender tampering alerts |
| T1003.001 | LSASS access monitoring |
| T1200 | USB device insertion logging |

### Medium Priority Detection

| Technique | Detection Method |
|-----------|------------------|
| T1105 | Network traffic to unknown IPs |
| T1071.001 | Outbound HTTP/HTTPS anomalies |
| T1560.001 | Archive creation monitoring |
| T1070.003 | History file modifications |

---

## ATT&CK Navigator Layers

### Minimal Payload Coverage
```json
{
  "techniques": [
    {"techniqueID": "T1091", "score": 100},
    {"techniqueID": "T1059.001", "score": 100},
    {"techniqueID": "T1082", "score": 100}
  ]
}
```

### Full BadUSB Coverage
```json
{
  "techniques": [
    {"techniqueID": "T1091", "score": 100, "comment": "USB Delivery"},
    {"techniqueID": "T1200", "score": 100, "comment": "Hardware Addition"},
    {"techniqueID": "T1059.001", "score": 90, "comment": "PowerShell"},
    {"techniqueID": "T1059.004", "score": 80, "comment": "Bash"},
    {"techniqueID": "T1547.001", "score": 70, "comment": "Registry"},
    {"techniqueID": "T1053.005", "score": 70, "comment": "Scheduled Task"},
    {"techniqueID": "T1555.003", "score": 60, "comment": "Browser Creds"},
    {"techniqueID": "T1041", "score": 80, "comment": "C2 Exfil"},
    {"techniqueID": "T1071.001", "score": 80, "comment": "HTTP C2"}
  ]
}
```

---

## Common Attack Chains

### Chain 1: Quick Credential Grab
```
T1091 → T1059.001 → T1555.003 → T1041
(USB) → (PowerShell) → (Browser Creds) → (HTTP Exfil)
```

### Chain 2: Persistent Access
```
T1091 → T1059.001 → T1547.001 → T1071.001
(USB) → (PowerShell) → (Registry Run) → (HTTP C2)
```

### Chain 3: Full Compromise
```
T1091 → T1059.001 → T1548.002 → T1562.001 → T1003.001 → T1136.001 → T1041
(USB) → (PS) → (UAC Bypass) → (Disable AV) → (Mimikatz) → (Add User) → (Exfil)
```

---

## Reference Links

- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)

---

[← Back to Main](../README.md)
