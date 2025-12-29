# FZ-B04: Display IP Address - Windows

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B04 |
| **Name** | Display IP Address |
| **Difficulty** | Basic |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~4 seconds |
| **MITRE ATT&CK** | T1016 (System Network Configuration Discovery) |

## What This Payload Does

Opens Command Prompt and displays the system's IPv4 addresses using ipconfig with filtering.

---

## The Payload

```ducky
REM =============================================
REM BASIC: Show IP Address
REM Target: Windows
REM Action: Displays current IP in command prompt
REM Skill: Basic
REM =============================================

DELAY 2000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 1000
STRINGLN ipconfig | findstr /i "IPv4"
```

---

## Line-by-Line Breakdown

| Line | Command | Purpose |
|------|---------|---------|
| 1-6 | REM | Documentation header |
| 8 | DELAY 2000 | Wait for USB enumeration |
| 9 | GUI r | Open Run dialog |
| 10 | DELAY 500 | Wait for dialog |
| 11 | STRING cmd | Type "cmd" |
| 12 | ENTER | Launch Command Prompt |
| 13 | DELAY 1000 | Wait for CMD to open |
| 14 | STRINGLN | Run ipconfig with filter |

---

## Understanding the Command

```
ipconfig | findstr /i "IPv4"

ipconfig     = Windows network configuration tool
|            = Pipe output to next command
findstr      = Windows text search utility
/i           = Case-insensitive search
"IPv4"       = The text to find
```

### Sample Output
```
   IPv4 Address. . . . . . . . . . . : 192.168.1.105
   IPv4 Address. . . . . . . . . . . : 10.0.0.15
```

---

## Variations

### Show Full Network Config
```ducky
STRINGLN ipconfig /all
```

### Show Only Active Connections
```ducky
STRINGLN netstat -an | findstr ESTABLISHED
```

### Show Default Gateway
```ducky
STRINGLN ipconfig | findstr /i "Gateway"
```

### Cross-Platform Versions

**macOS:**
```ducky
DELAY 2000
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
STRINGLN ifconfig | grep "inet "
```

**Linux:**
```ducky
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN ip addr | grep "inet "
```

---

## Red Team Perspective

### Why This Matters
- First step in network reconnaissance
- Identifies target's network segment
- Helps plan lateral movement
- Can identify VPN connections

### Information Gathered
| Data Point | Use Case |
|------------|----------|
| IP Address | Network mapping |
| Subnet | Scope identification |
| Multiple IPs | VPN/multi-homed detection |
| Gateway | Network topology |

---

## Blue Team Perspective

### Detection
- Command Prompt launched from Run dialog
- ipconfig execution logged
- Unusual reconnaissance activity

### Monitoring Command
```powershell
# Check for recent ipconfig runs (Event ID 4688)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} | Where-Object { $_.Message -match 'ipconfig' }
```

---

## Practice Exercises

### Exercise 1: Extended Network Info
Add more network commands:
```ducky
STRINGLN ipconfig /all
STRINGLN arp -a
STRINGLN netstat -ano
```

### Exercise 2: Save to File
Save output instead of displaying:
```ducky
STRINGLN ipconfig /all > %TEMP%\network.txt
```

### Exercise 3: Open Result
Display and leave CMD open:
```ducky
STRING cmd /k ipconfig | findstr /i "IPv4"
```
(The `/k` keeps CMD open after command)

---

## Payload File

Save as `FZ-B04_Display_IP.txt`:

```ducky
REM FZ-B04: Display IP Address
DELAY 2000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 1000
STRINGLN ipconfig | findstr /i "IPv4"
```

---

[← FZ-B03 Linux](FZ-B03_Hello_World_Linux.md) | [Next: FZ-B05 Open Website →](FZ-B05_Open_Website.md)
