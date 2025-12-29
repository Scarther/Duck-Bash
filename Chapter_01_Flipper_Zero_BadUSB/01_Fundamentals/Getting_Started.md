# Flipper Zero BadUSB Fundamentals

## Overview

This guide introduces the fundamentals of Flipper Zero's BadUSB functionality, from basic concepts to your first payloads.

---

## What is BadUSB?

```
TRADITIONAL USB DEVICE:
┌─────────────┐    ┌─────────────┐
│   USB       │───►│  Computer   │
│   Drive     │    │  (Storage)  │
└─────────────┘    └─────────────┘

BADUSB DEVICE:
┌─────────────┐    ┌─────────────┐
│   Flipper   │───►│  Computer   │
│   Zero      │    │ (Keyboard!) │
└─────────────┘    └─────────────┘
    Types commands automatically
```

**BadUSB** exploits the trust computers place in USB Human Interface Devices (HIDs) like keyboards. When you plug in a Flipper Zero running BadUSB, the computer sees a keyboard and accepts its "keystrokes" without question.

---

## Why Flipper Zero for BadUSB?

| Feature | Benefit |
|---------|---------|
| Portable | Fits in your pocket |
| Standalone | No computer needed to deploy |
| Scriptable | Easy-to-learn DuckyScript |
| Multi-function | Also does NFC, RFID, Sub-GHz, IR |
| Active Community | Lots of payloads and help available |
| Visible Display | See what's happening |

---

## DuckyScript Basics

DuckyScript is a simple scripting language for keyboard automation.

### Essential Commands

| Command | Description | Example |
|---------|-------------|---------|
| `DELAY` | Wait (milliseconds) | `DELAY 1000` (1 second) |
| `STRING` | Type text | `STRING Hello World` |
| `STRINGLN` | Type text + Enter | `STRINGLN echo test` |
| `ENTER` | Press Enter key | `ENTER` |
| `GUI` | Windows/Command key | `GUI r` (Win+R) |
| `CTRL` | Control key | `CTRL c` (Ctrl+C) |
| `ALT` | Alt key | `ALT F4` |
| `SHIFT` | Shift key | `SHIFT TAB` |
| `TAB` | Tab key | `TAB` |
| `ESC` | Escape key | `ESC` |
| `REM` | Comment (not executed) | `REM This is a comment` |

### Key Combinations

```
Single key:
ENTER
TAB
ESCAPE

Modifier + key:
GUI r          (Windows + R)
CTRL c         (Ctrl + C)
ALT TAB        (Alt + Tab)

Multiple modifiers:
CTRL ALT DELETE
CTRL SHIFT ESC
```

---

## Your First Payload

### Hello World

```
REM =============================================
REM My First Payload
REM Opens Notepad and types a message
REM =============================================

DELAY 2000
REM Wait 2 seconds for computer to recognize device

GUI r
REM Open Run dialog (Windows + R)

DELAY 500
REM Wait for Run dialog to appear

STRING notepad
REM Type "notepad"

ENTER
REM Press Enter to open Notepad

DELAY 1000
REM Wait for Notepad to open

STRING Hello from Flipper Zero!
REM Type our message

REM That's it! You've created your first payload!
```

### Step-by-Step Explanation

```
Line 1-4: Comments explaining the payload
Line 6: DELAY 2000 - Wait 2 seconds
          Why? Computer needs time to recognize the USB device

Line 8: GUI r - Opens Windows Run dialog
          Why? Quick way to launch programs

Line 10: DELAY 500 - Wait half a second
          Why? Run dialog needs time to appear

Line 12: STRING notepad - Types "notepad"
          Why? This is what we want to run

Line 14: ENTER - Presses Enter
          Why? Executes the command in Run dialog

Line 16: DELAY 1000 - Wait 1 second
          Why? Notepad needs time to open

Line 18: STRING Hello from Flipper Zero!
          Why? This is our message
```

---

## Loading Payloads to Flipper

### Method 1: qFlipper (Easiest)

1. Connect Flipper to computer via USB
2. Open qFlipper application
3. Go to "SD Card" section
4. Navigate to `badusb/` folder
5. Drag and drop your `.txt` payload file

### Method 2: Direct SD Card Access

1. Connect Flipper via USB
2. Enable Mass Storage mode on Flipper
3. Browse to SD Card
4. Copy payload to `/badusb/` folder

### Method 3: Flipper Mobile App

1. Connect phone to Flipper via Bluetooth
2. Open Flipper app
3. Navigate to BadUSB section
4. Upload payload file

---

## Running Your First Payload

1. **Disconnect** Flipper from computer
2. Navigate to: **BadUSB** → **Your Payload**
3. Select your payload file
4. Press **OK** to arm the payload
5. **Connect** Flipper to target computer
6. Watch the magic happen!

### What You'll See

```
1. Connect Flipper
2. Computer recognizes "USB Keyboard"
3. Run dialog opens automatically
4. "notepad" is typed
5. Notepad opens
6. "Hello from Flipper Zero!" appears
```

---

## Understanding Timing

Timing is CRITICAL for reliable payloads.

### Why Delays Matter

```
Without delay (FAILS):
GUI r
STRING notepad    ← Typed before Run dialog opens!
ENTER

With delay (WORKS):
GUI r
DELAY 500         ← Wait for Run dialog
STRING notepad
ENTER
```

### Recommended Delays

| Action | Minimum Delay |
|--------|---------------|
| After USB connection | 2000ms |
| After GUI r (Run dialog) | 500ms |
| After opening application | 1000ms |
| Between rapid commands | 100ms |
| After UAC prompt | 3000ms |

### Adaptive Delays

For unreliable timing, use longer delays or multiple attempts:

```
REM More reliable Run dialog opening
GUI r
DELAY 500
GUI r
DELAY 500
GUI r
DELAY 1000
STRING notepad
```

---

## Common First Payload Patterns

### Pattern 1: Open Application

```
DELAY 2000
GUI r
DELAY 500
STRING [application name]
ENTER
DELAY 1000
```

### Pattern 2: Open PowerShell

```
DELAY 2000
GUI r
DELAY 500
STRING powershell
ENTER
DELAY 1000
```

### Pattern 3: Open CMD

```
DELAY 2000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 1000
```

### Pattern 4: Open Browser

```
DELAY 2000
GUI r
DELAY 500
STRING https://example.com
ENTER
```

---

## Practice Exercises

### Exercise 1: Calculator
Create a payload that opens the Calculator app.

<details>
<summary>Solution</summary>

```
REM Open Calculator
DELAY 2000
GUI r
DELAY 500
STRING calc
ENTER
```
</details>

### Exercise 2: System Information
Create a payload that opens System Information.

<details>
<summary>Solution</summary>

```
REM Open System Information
DELAY 2000
GUI r
DELAY 500
STRING msinfo32
ENTER
```
</details>

### Exercise 3: Write a File
Create a payload that creates a text file on the Desktop.

<details>
<summary>Solution</summary>

```
REM Create file on Desktop
DELAY 2000
GUI r
DELAY 500
STRING notepad %USERPROFILE%\Desktop\hello.txt
ENTER
DELAY 1500
STRING This file was created by Flipper Zero!
CTRL s
DELAY 500
ALT F4
```
</details>

---

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| Nothing happens | USB not recognized | Wait longer, check cable |
| Wrong characters | Keyboard layout mismatch | Use correct layout in payload |
| Partial execution | Timing too fast | Increase DELAY values |
| Commands typed literally | Run dialog didn't open | Add more delay after GUI r |

---

## Safety and Ethics

```
⚠️ IMPORTANT ⚠️

BadUSB payloads can cause real harm:
- Data destruction
- Privacy violation
- System compromise
- Legal consequences

ALWAYS:
✓ Get written permission before testing
✓ Test on your own systems first
✓ Understand what your payload does
✓ Have a way to stop/reverse effects

NEVER:
✗ Run payloads on systems you don't own
✗ Use for malicious purposes
✗ Share payloads designed to harm
✗ Deploy without understanding consequences
```

---

## Next Steps

After mastering the basics:
1. Learn more DuckyScript commands
2. Try intermediate payloads
3. Understand target system detection
4. Explore evasion techniques
5. Practice writing detection rules

---

[← Back to Chapter 01](../README.md)
