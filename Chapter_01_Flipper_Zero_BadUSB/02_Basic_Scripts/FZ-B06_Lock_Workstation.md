# FZ-B06: Lock Workstation - Windows

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B06 |
| **Name** | Lock Workstation |
| **Difficulty** | Basic |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~1 second |

## What This Payload Does

Immediately locks the Windows workstation using the Win+L keyboard shortcut. The simplest possible payload!

---

## The Payload

```ducky
REM =============================================
REM BASIC: Lock Screen
REM Target: Windows
REM Action: Immediately locks the workstation
REM Skill: Basic
REM =============================================

DELAY 1000
GUI l
```

That's it - just 2 commands!

---

## Why Only 1 Second Delay?

Unlike other payloads, locking the screen:
- Doesn't require a dialog to open
- Doesn't need to type anything
- Is a direct keyboard shortcut
- Happens instantly

The 1-second delay is just for USB enumeration safety.

---

## Use Cases

### Security Awareness Training
"I just locked your computer by plugging in a USB. Imagine if I had done something malicious instead."

### Quick Exit Strategy
Payload finishes its work, then locks screen to:
- Prevent user from seeing activity
- Trigger login prompt
- End the session cleanly

### Prank
Lock someone's computer when they step away.

---

## Cross-Platform Versions

### macOS
```ducky
DELAY 1000
CTRL GUI q
```
Note: This triggers the Lock Screen shortcut.

### macOS (Sleep)
```ducky
DELAY 1000
CTRL SHIFT POWER
```
Or use the Media key:
```ducky
DELAY 1000
CTRL SHIFT MEDIA EJECT
```

### Linux (GNOME)
```ducky
DELAY 1000
GUI l
```
Or:
```ducky
DELAY 2000
CTRL ALT t
DELAY 500
STRINGLN gnome-screensaver-command -l
```

### Linux (KDE)
```ducky
DELAY 1000
GUI l
```

---

## Combined with Other Actions

### Lock After Payload Execution
```ducky
REM Run some other commands first...
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -c "Get-ComputerInfo | Out-File $env:TEMP\info.txt"
ENTER
DELAY 3000

REM Now lock the screen to cover tracks
GUI l
```

### Lock + Message
```ducky
REM Create message then lock
DELAY 2000
GUI r
DELAY 500
STRING cmd /c echo Security Training > %USERPROFILE%\Desktop\locked.txt
ENTER
DELAY 500
GUI l
```

---

## Red Team Perspective

### Use Cases
- Cover tracks after payload runs
- Force re-authentication (capture credentials with keylogger)
- Signal successful execution to operator
- Create distraction

### Not Just a Prank
Locking a workstation can be part of a larger attack:
1. Payload establishes persistence
2. Lock workstation
3. User returns, logs back in
4. Malware now has fresh authentication

---

## Blue Team Perspective

### Detection
Honestly, this is hard to detect maliciously because:
- Users lock their own computers all the time
- Win+L is a normal shortcut
- No suspicious processes spawned

### The Real Lesson
If someone can lock your computer with a USB, they can do MUCH worse. The lock is just a demonstration of access.

### Prevention
- USB device control
- USB port blockers
- Security awareness training

---

## Practice Exercises

### Exercise 1: Delayed Lock
Lock after 10 seconds (for testing):
```ducky
DELAY 10000
GUI l
```

### Exercise 2: Message + Lock
Create a file, then lock:
```ducky
DELAY 2000
GUI r
DELAY 500
STRING notepad %USERPROFILE%\Desktop\message.txt
ENTER
DELAY 1000
STRING Security Awareness Test
DELAY 500
CTRL s
DELAY 500
ALT F4
DELAY 500
GUI l
```

### Exercise 3: All Platforms
Create three versions:
- Windows: GUI l
- macOS: CTRL GUI q
- Linux: GUI l

---

## Payload File

Save as `FZ-B06_Lock_Workstation.txt`:

```ducky
REM FZ-B06: Lock Workstation
DELAY 1000
GUI l
```

---

[← FZ-B05 Open Website](FZ-B05_Open_Website.md) | [Next: FZ-B07 Screenshot →](FZ-B07_Screenshot.md)
