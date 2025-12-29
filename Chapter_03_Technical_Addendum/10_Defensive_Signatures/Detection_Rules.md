# Defensive Signatures for BadUSB Detection

## Overview

This document contains detection rules in multiple formats (Sigma, YARA, Snort/Suricata) for identifying BadUSB attacks.

---

## Sigma Rules

### USB Device with Rapid Keystroke Injection

```yaml
title: BadUSB Rapid Keystroke Injection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects rapid keystroke input typical of BadUSB devices
author: Security Training
logsource:
    product: windows
    service: sysmon
detection:
    usb_connection:
        EventID: 1
        ParentImage|endswith: '\explorer.exe'
    rapid_execution:
        EventID: 1
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    timeframe: 10s
    condition: usb_connection and rapid_execution
level: high
tags:
    - attack.initial_access
    - attack.t1091
    - attack.execution
    - attack.t1059
```

### Suspicious PowerShell Flags

```yaml
title: PowerShell with BadUSB Indicators
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: stable
description: Detects PowerShell execution with common BadUSB evasion flags
author: Security Training
logsource:
    product: windows
    service: powershell
    definition: 'Script Block Logging must be enabled'
detection:
    selection_flags:
        EventID: 4104
        ScriptBlockText|contains:
            - '-w hidden'
            - '-WindowStyle Hidden'
            - '-ep bypass'
            - '-ExecutionPolicy Bypass'
            - '-nop'
            - '-NoProfile'
            - '-enc '
            - '-EncodedCommand'
    condition: selection_flags
level: high
falsepositives:
    - Administrative scripts
    - Some legitimate software installers
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
```

### Registry Run Key Persistence

```yaml
title: Registry Run Key Modification via Script
id: c3d4e5f6-a7b8-9012-cdef-345678901234
status: stable
description: Detects modification of Run keys commonly used by BadUSB for persistence
author: Security Training
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains:
            - '\CurrentVersion\Run'
            - '\CurrentVersion\RunOnce'
        Details|contains:
            - 'powershell'
            - '.ps1'
            - 'cmd'
            - '%TEMP%'
            - '\AppData\'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```

---

## YARA Rules

### BadUSB Payload Detection

```yara
rule BadUSB_DuckyScript_Payload {
    meta:
        description = "Detects DuckyScript payload files"
        author = "Security Training"
        date = "2024-01-01"
        severity = "high"

    strings:
        $ducky1 = "DELAY" ascii wide nocase
        $ducky2 = "STRING " ascii wide
        $ducky3 = "STRINGLN" ascii wide
        $ducky4 = "GUI " ascii wide
        $ducky5 = "ENTER" ascii wide
        $ducky6 = "REM " ascii wide

        $suspicious1 = "powershell" ascii wide nocase
        $suspicious2 = "-w hidden" ascii wide nocase
        $suspicious3 = "-ep bypass" ascii wide nocase
        $suspicious4 = "Invoke-WebRequest" ascii wide nocase
        $suspicious5 = "DownloadString" ascii wide nocase

    condition:
        filesize < 100KB and
        (3 of ($ducky*)) and
        (1 of ($suspicious*))
}

rule BadUSB_Exfiltration_Script {
    meta:
        description = "Detects scripts with exfiltration patterns"
        author = "Security Training"

    strings:
        $exfil1 = "Invoke-WebRequest" ascii wide nocase
        $exfil2 = "Invoke-RestMethod" ascii wide nocase
        $exfil3 = "curl" ascii wide nocase
        $exfil4 = "wget" ascii wide nocase
        $exfil5 = "Net.WebClient" ascii wide nocase

        $data1 = "COMPUTERNAME" ascii wide
        $data2 = "USERNAME" ascii wide
        $data3 = "Get-Content" ascii wide
        $data4 = "Get-Process" ascii wide
        $data5 = "Get-NetIPAddress" ascii wide

    condition:
        (1 of ($exfil*)) and (2 of ($data*))
}

rule BadUSB_Persistence_Script {
    meta:
        description = "Detects persistence mechanism installation"
        author = "Security Training"

    strings:
        $reg1 = "CurrentVersion\\Run" ascii wide nocase
        $reg2 = "Set-ItemProperty" ascii wide nocase
        $reg3 = "New-ItemProperty" ascii wide nocase

        $task1 = "schtasks" ascii wide nocase
        $task2 = "Register-ScheduledTask" ascii wide nocase
        $task3 = "New-ScheduledTask" ascii wide nocase

        $startup = "Startup" ascii wide nocase

    condition:
        (2 of ($reg*)) or (1 of ($task*)) or $startup
}
```

---

## Snort/Suricata Rules

### DNS Exfiltration Detection

```
# Detect long DNS queries (possible exfiltration)
alert dns any any -> any any (msg:"Possible DNS Exfiltration - Long Query"; \
    dns.query; content:"."; offset:50; \
    sid:1000001; rev:1; \
    classtype:policy-violation; \
    metadata:attack_target Client_Endpoint, deployment Perimeter;)

# Detect base64 patterns in DNS queries
alert dns any any -> any any (msg:"Possible DNS Exfiltration - Base64 Pattern"; \
    dns.query; pcre:"/[A-Za-z0-9+\/]{30,}={0,2}\./"; \
    sid:1000002; rev:1; \
    classtype:policy-violation;)
```

### HTTP Exfiltration Detection

```
# Detect POST to suspicious endpoints
alert http any any -> any any (msg:"Possible Data Exfiltration POST"; \
    flow:to_server,established; \
    http.method; content:"POST"; \
    http.uri; content:"/collect"; \
    sid:1000003; rev:1; \
    classtype:policy-violation;)

# Detect encoded data in HTTP parameters
alert http any any -> any any (msg:"Base64 Data in HTTP Request"; \
    flow:to_server,established; \
    http.uri; pcre:"/[A-Za-z0-9+\/]{50,}={0,2}/"; \
    sid:1000004; rev:1; \
    classtype:policy-violation;)
```

---

## Windows Event Log Queries

### PowerShell Script Block Analysis

```powershell
# Find suspicious PowerShell execution
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    ID = 4104
} | Where-Object {
    $_.Message -match '(-w\s*hidden|-ep\s*bypass|-enc\s|DownloadString|IEX|Invoke-Expression)'
} | Select-Object TimeCreated, Message | Format-List
```

### USB Device Events

```powershell
# Find recent USB device connections
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 6416
} -MaxEvents 50 | Select-Object TimeCreated, Message
```

### Process Creation with Command Line

```powershell
# Find suspicious process creation
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4688
} | Where-Object {
    $_.Message -match '(powershell|cmd).*(-w\s*hidden|-ep\s*bypass|%TEMP%)'
} | Select-Object TimeCreated, Message
```

---

## Linux Detection Commands

### USB Device Monitoring

```bash
#!/bin/bash
# Monitor USB device connections
echo "[*] Monitoring USB device events..."
udevadm monitor --kernel --property --subsystem-match=usb | while read line; do
    if echo "$line" | grep -q "ACTION=add"; then
        echo "[ALERT] USB device connected at $(date)"
        echo "$line"
    fi
done
```

### Process Monitoring for BadUSB Indicators

```bash
#!/bin/bash
# Monitor for rapid process spawning (BadUSB indicator)
THRESHOLD=5
WINDOW=10

echo "[*] Monitoring for rapid process creation..."
while true; do
    COUNT=$(ps -eo lstart | grep "$(date +%H:%M)" | wc -l)
    if [ $COUNT -gt $THRESHOLD ]; then
        echo "[ALERT] Rapid process creation detected: $COUNT processes"
        ps aux --sort=-start_time | head -10
    fi
    sleep $WINDOW
done
```

---

## Implementation Checklist

- [ ] Deploy Sigma rules to SIEM
- [ ] Enable PowerShell Script Block Logging
- [ ] Enable Process Command Line Auditing
- [ ] Install Sysmon with USB monitoring config
- [ ] Deploy YARA rules to endpoint protection
- [ ] Configure network IDS with Snort/Suricata rules
- [ ] Set up USB device whitelisting
- [ ] Create alert dashboards

---

[← Back to Technical Addendum](../README.md)
