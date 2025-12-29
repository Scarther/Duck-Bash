# FZ-B03: Hello World - Linux

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B03 |
| **Name** | Hello World - Linux |
| **Difficulty** | Basic |
| **Target OS** | Ubuntu/Debian with GNOME |
| **Execution Time** | ~3 seconds |
| **Prerequisites** | None |

## What This Payload Does

Opens a terminal window using the standard keyboard shortcut and echoes a greeting message.

---

## The Payload

```ducky
REM =============================================
REM BASIC: Hello World - Linux
REM Target: Ubuntu/Debian with GNOME
REM Action: Opens terminal, echoes message
REM Skill: Basic
REM =============================================

DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN echo "Hello from Flipper Zero on Linux!"
```

---

## Line-by-Line Breakdown

| Line | Command | Purpose |
|------|---------|---------|
| 1-6 | REM | Documentation header |
| 8 | DELAY 2000 | Wait for USB enumeration |
| 9 | CTRL ALT t | Open terminal (GNOME shortcut) |
| 10 | DELAY 1000 | Wait for terminal to appear |
| 11 | STRINGLN | Type command AND press Enter |

---

## The Linux Approach

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🐧 LINUX: THE DIRECT APPROACH                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ WHY LINUX IS DIFFERENT:                                                      │
│ - Linux uses CTRL+ALT+T as the standard terminal shortcut (GNOME/KDE)       │
│ - No "Run dialog" needed - terminal IS the command interface                │
│ - Commands execute immediately with STRINGLN (includes Enter)              │
│                                                                              │
│ THE COMMAND EXPLAINED:                                                       │
│ ┌────────────────────────────────────────────────────────────────────┐      │
│ │ echo "Hello from Flipper Zero on Linux!"                          │      │
│ └────────────────────────────────────────────────────────────────────┘      │
│                                                                              │
│   echo    = Built-in command that outputs text                              │
│   "..."   = The message to display                                          │
│   Result  = Message appears in terminal, then new prompt                    │
│                                                                              │
│ ON TARGET LINUX SYSTEM:                                                      │
│ ┌────────────────────────────────────────────────────────────────────┐      │
│ │ user@ubuntu:~$                                                      │      │
│ └────────────────────────────────────────────────────────────────────┘      │
│                     ↓ CTRL+ALT+T pressed                                    │
│ ┌────────────────────────────────────────────────────────────────────┐      │
│ │ Terminal - user@ubuntu                                          X  │      │
│ │──────────────────────────────────────────────────────────────────│      │
│ │ user@ubuntu:~$ echo "Hello from Flipper Zero on Linux!"          │      │
│ │ Hello from Flipper Zero on Linux!                                 │      │
│ │ user@ubuntu:~$ _                                                  │      │
│ │                                                                    │      │
│ └────────────────────────────────────────────────────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Desktop Environment Variations

| Desktop | Terminal Shortcut | Notes |
|---------|-------------------|-------|
| GNOME (Ubuntu) | CTRL+ALT+T | Works by default |
| KDE (Kubuntu) | CTRL+ALT+T | Also F12 for Yakuake |
| XFCE (Xubuntu) | May vary | Often needs configuration |
| Cinnamon (Mint) | CTRL+ALT+T | Works by default |
| MATE | CTRL+ALT+T | Works by default |

---

## Alternative Approaches

If CTRL+ALT+T doesn't work, try these alternatives:

### Option 1: Using ALT+F2 (Run Dialog)
```ducky
DELAY 2000
ALT F2
DELAY 500
STRING gnome-terminal
ENTER
DELAY 1000
STRINGLN echo "Hello from Flipper Zero!"
```

### Option 2: Using Application Menu
```ducky
DELAY 2000
GUI
DELAY 500
STRING terminal
DELAY 500
ENTER
DELAY 1000
STRINGLN echo "Hello from Flipper Zero!"
```

---

## Red Team Perspective

### Linux Advantages
- Terminal access = full system access
- No execution policy like PowerShell
- Many attack tools are Linux-native
- SSH access often available

### Linux Challenges
- Desktop environment variations
- User might not be in sudoers
- Some systems don't have GUI
- Different distros have different tools

---

## Blue Team Perspective

### Detection Opportunities

1. **USB Device Connection**
   - `dmesg` shows USB events
   - `journalctl` logs device connections

2. **Terminal Launch**
   - Unusual terminal spawn
   - Rapid command execution

3. **Command History**
   - Commands logged to `.bash_history`
   - Audit logs (if enabled)

### Protection Measures

```bash
# Check recent USB devices
dmesg | grep -i usb | tail -20

# Check command history
cat ~/.bash_history | tail -20

# Monitor for BadUSB
# Install USBGuard for device whitelisting
sudo apt install usbguard
```

---

## Practice Exercises

### Exercise 1: System Information
Modify the payload to show system info:
```ducky
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN uname -a && whoami && id
```

### Exercise 2: Create a File
Create a file on the desktop:
```ducky
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN echo "BadUSB was here" > ~/Desktop/hello.txt
```

### Exercise 3: Multiple Commands
Run multiple commands in sequence:
```ducky
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN hostname; date; uptime
```

---

## Payload File

Save as `FZ-B03_Hello_World_Linux.txt`:

```ducky
REM FZ-B03: Hello World - Linux
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN echo "Hello from Flipper Zero on Linux!"
```

---

[← Back to Basic Scripts](README.md) | [Next: FZ-B04 Display IP →](FZ-B04_Display_IP.md)
