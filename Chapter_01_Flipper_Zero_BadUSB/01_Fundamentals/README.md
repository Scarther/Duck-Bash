# Chapter 1.1: Flipper Zero BadUSB Fundamentals

## What is BadUSB?

BadUSB is an attack that exploits the inherent trust computers place in USB devices. When you plug in a USB keyboard, your computer trusts it completely - no driver installation prompts, no security warnings. BadUSB exploits this trust by making a device (like Flipper Zero) pretend to be a keyboard and "type" malicious commands faster than any human could.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HOW BADUSB WORKS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│    ┌──────────────┐         ┌──────────────┐         ┌──────────────┐       │
│    │   FLIPPER    │  USB    │   COMPUTER   │ Trust   │   COMMANDS   │       │
│    │    ZERO      │────────▶│   "Keyboard  │────────▶│   EXECUTE    │       │
│    │  (BadUSB)    │         │   detected!" │         │   AS USER    │       │
│    └──────────────┘         └──────────────┘         └──────────────┘       │
│                                                                              │
│    The computer sees a keyboard, not a hacking device.                       │
│    Commands run with the logged-in user's privileges.                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Why is This Dangerous?

1. **No Antivirus Alert**: You're "typing" commands, not running malware files
2. **Speed**: Can type thousands of characters per second
3. **User Privileges**: Runs as the logged-in user (often an admin)
4. **Physical Access**: Often bypasses network-based security

## The Flipper Zero

The Flipper Zero is a portable multi-tool for security professionals. Its BadUSB module can:
- Emulate USB HID (Human Interface Device) keyboards
- Run DuckyScript payloads
- Customize VID/PID to impersonate specific keyboards
- Store multiple payloads on SD card

### Hardware Specs

| Component | Specification |
|-----------|---------------|
| Processor | STM32WB55RG (ARM Cortex-M4 + M0+) |
| Storage | 1MB internal + MicroSD (up to 256GB) |
| USB | USB 2.0 Type-C |
| Screen | 1.4" monochrome LCD (128x64) |
| Battery | 2000mAh Li-Po |

---

## DuckyScript: The Language of BadUSB

DuckyScript is a simple scripting language designed for keystroke injection. Originally created for the USB Rubber Ducky, it's now supported by Flipper Zero and other BadUSB devices.

### Core Philosophy

DuckyScript simulates **what a human would type**. If you can do it with a keyboard, DuckyScript can automate it.

---

## Complete Command Reference

### Basic Commands

#### REM - Comments
```ducky
REM This is a comment - it won't be executed
REM Use comments to document your payloads
```
**What it does**: Nothing! Comments are for humans reading the code.

---

#### DELAY - Wait
```ducky
DELAY 1000
```
**What it does**: Pauses execution for specified milliseconds.

| Delay | Time |
|-------|------|
| 100 | 0.1 seconds |
| 500 | 0.5 seconds |
| 1000 | 1 second |
| 5000 | 5 seconds |

**Why it matters**: Computers need time to process. Opening an application takes time. Always add delays after actions that need to complete.

```ducky
REM BAD - No delay, might fail
GUI r
STRING notepad
ENTER

REM GOOD - Delays let each step complete
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
```

---

#### STRING - Type Text
```ducky
STRING Hello, World!
```
**What it does**: Types the text exactly as written.

**Important Notes**:
- Does NOT press Enter after typing
- Case-sensitive (types exactly what you write)
- Special characters depend on keyboard layout

```ducky
REM Type a command
STRING ipconfig /all

REM Type a URL
STRING https://example.com

REM Type with special characters
STRING Password123!@#
```

---

#### STRINGLN - Type Text + Enter
```ducky
STRINGLN echo "Hello"
```
**What it does**: Types text AND presses Enter. Equivalent to:
```ducky
STRING echo "Hello"
ENTER
```

---

### Key Commands

#### Single Keys
```ducky
ENTER          REM Press Enter
TAB            REM Press Tab
SPACE          REM Press Spacebar
BACKSPACE      REM Press Backspace
DELETE         REM Press Delete
ESCAPE         REM Press Escape
PAUSE          REM Press Pause/Break
CAPSLOCK       REM Toggle Caps Lock
NUMLOCK        REM Toggle Num Lock
SCROLLLOCK     REM Toggle Scroll Lock
```

#### Arrow Keys
```ducky
UP             REM or UPARROW
DOWN           REM or DOWNARROW
LEFT           REM or LEFTARROW
RIGHT          REM or RIGHTARROW
```

#### Function Keys
```ducky
F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12
```

#### Navigation Keys
```ducky
HOME           REM Go to beginning
END            REM Go to end
PAGEUP         REM Page up
PAGEDOWN       REM Page down
INSERT         REM Toggle insert mode
PRINTSCREEN    REM Screenshot (OS dependent)
```

---

### Modifier Keys

Modifiers are held while pressing another key, like keyboard shortcuts.

#### GUI (Windows/Super/Command)
```ducky
GUI            REM Just the Windows/Command key
GUI r          REM Windows+R (Run dialog)
GUI d          REM Windows+D (Show desktop)
GUI l          REM Windows+L (Lock screen)
GUI e          REM Windows+E (File Explorer)
```

#### ALT
```ducky
ALT            REM Just Alt
ALT F4         REM Alt+F4 (Close window)
ALT TAB        REM Alt+Tab (Switch windows)
ALT F          REM Alt+F (Often opens File menu)
```

#### CTRL (Control)
```ducky
CTRL           REM Just Ctrl
CTRL c         REM Ctrl+C (Copy)
CTRL v         REM Ctrl+V (Paste)
CTRL a         REM Ctrl+A (Select all)
CTRL s         REM Ctrl+S (Save)
CTRL z         REM Ctrl+Z (Undo)
CTRL SHIFT     REM Ctrl+Shift (common combo starter)
```

#### SHIFT
```ducky
SHIFT          REM Just Shift
SHIFT TAB      REM Shift+Tab (Reverse tab)
SHIFT INSERT   REM Shift+Insert (Paste in terminal)
```

#### Combining Modifiers
```ducky
CTRL ALT DELETE         REM The famous three-finger salute
CTRL SHIFT ESCAPE       REM Open Task Manager directly
GUI SHIFT s             REM Windows Snipping Tool
ALT CTRL t              REM Open Terminal (Linux)
```

---

### Flipper Zero Exclusive Commands

These commands only work on Flipper Zero:

#### ALTCHAR / ALTCODE
Type characters by their ASCII code (useful for special characters):
```ducky
ALTCHAR 65     REM Types 'A' (ASCII 65)
ALTCHAR 64     REM Types '@' (ASCII 64)
ALTSTRING @#$% REM Types special chars via ALT codes
```

#### SYSRQ (Linux System Request)
```ducky
SYSRQ r        REM Raw keyboard mode
SYSRQ b        REM Reboot immediately
```

#### HOLD and RELEASE
```ducky
HOLD GUI       REM Hold down Windows key
DELAY 100
STRING r       REM Types 'r' while GUI is held
RELEASE GUI    REM Release Windows key
```

---

## Understanding the Execution Flow

When Flipper Zero runs a BadUSB payload:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PAYLOAD EXECUTION FLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. ENUMERATION (automatic)                                                  │
│     └── Flipper presents itself as USB HID Keyboard                          │
│     └── Computer loads generic keyboard driver                               │
│     └── Takes 1-3 seconds depending on system                                │
│                                                                              │
│  2. SCRIPT EXECUTION                                                         │
│     └── Flipper reads .txt file from SD card                                 │
│     └── Each line executed sequentially                                      │
│     └── STRING commands "type" characters                                    │
│     └── KEY commands "press" keys                                            │
│                                                                              │
│  3. COMPLETION                                                               │
│     └── Script ends                                                          │
│     └── Flipper remains connected (unless unplugged)                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Your First Payload: Hello World

Let's create a simple payload step-by-step:

### Goal
Open Notepad and type "Hello from Flipper Zero!"

### The Script
```ducky
REM Hello World Payload
REM Target: Windows
REM Author: Your Name
REM Date: 2025

REM Wait for USB enumeration
DELAY 2000

REM Open Run dialog
GUI r
DELAY 500

REM Type notepad and press Enter
STRING notepad
ENTER
DELAY 1000

REM Type our message
STRING Hello from Flipper Zero!
```

### Line-by-Line Breakdown

| Line | Command | Explanation |
|------|---------|-------------|
| 1-4 | REM | Header comments - who, what, when |
| 6 | DELAY 2000 | Wait 2 seconds for USB to be recognized |
| 8 | GUI r | Press Windows+R to open Run dialog |
| 9 | DELAY 500 | Wait for Run dialog to appear |
| 11 | STRING notepad | Type "notepad" in Run dialog |
| 12 | ENTER | Press Enter to run notepad |
| 13 | DELAY 1000 | Wait for Notepad to open |
| 15 | STRING ... | Type our message in Notepad |

---

## Red Team Perspective

### Why Attackers Use BadUSB

1. **Bypasses Network Security**: No network traffic to analyze during initial execution
2. **Speed**: Complete payload in seconds
3. **Reliability**: Keyboards always work (no driver issues)
4. **User Context**: Inherits victim's permissions
5. **Stealth**: No files downloaded initially (can be fileless)

### Common Attack Scenarios

| Scenario | Description |
|----------|-------------|
| Drop Attack | Leave "lost" USB drives in parking lots |
| Social Engineering | "Can you print this from my USB?" |
| Evil Maid | Hotel room access to unattended laptop |
| Supply Chain | Compromised USB devices from manufacturer |
| Insider Threat | Employee with physical access |

---

## Blue Team Perspective

### Detection Methods

1. **USB Device Policies**
   - Whitelist approved USB devices by VID/PID
   - Alert on new HID device connections

2. **Behavioral Analysis**
   - Detect rapid keystroke injection
   - Monitor for suspicious command patterns

3. **Endpoint Protection**
   - Block PowerShell download cradles
   - Monitor Run dialog usage

### Windows Event Logs to Monitor

| Event ID | Log | Description |
|----------|-----|-------------|
| 6416 | Security | New external device recognized |
| 4688 | Security | New process created |
| 4104 | PowerShell | Script block logging |

### Prevention Script (PowerShell)
```powershell
# Block new USB storage devices (run as admin)
# Note: This blocks storage, but HID keyboards still work
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4

# For HID blocking, you need USB device control software
# or Group Policy with device installation restrictions
```

---

## Practice Exercises

### Exercise 1: Modify Hello World
Change the Hello World payload to:
1. Open Notepad
2. Type your full name
3. Press Enter
4. Type today's date
5. Save the file (Hint: CTRL s)

### Exercise 2: Different Application
Create a payload that:
1. Opens Calculator (calc)
2. Types: 1+1=
3. Waits 2 seconds
4. Closes Calculator (ALT F4)

### Exercise 3: Cross-Platform
Create THREE versions of Hello World:
1. Windows (GUI r, notepad)
2. macOS (GUI SPACE, textedit)
3. Linux (ALT F2, gedit)

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     DUCKYSCRIPT QUICK REFERENCE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TIMING                        TYPING                                        │
│  ──────                        ──────                                        │
│  DELAY 1000 = 1 second         STRING text = type text                       │
│  DELAY 500 = 0.5 seconds       STRINGLN text = type + enter                  │
│                                                                              │
│  COMMON SHORTCUTS              NAVIGATION                                    │
│  ────────────────              ──────────                                    │
│  GUI r = Run dialog            UP DOWN LEFT RIGHT                            │
│  GUI d = Desktop               HOME END                                      │
│  GUI l = Lock                  TAB = Next field                              │
│  ALT F4 = Close                SHIFT TAB = Previous field                    │
│  ALT TAB = Switch              ENTER = Confirm/Execute                       │
│                                                                              │
│  MODIFIERS                     SPECIAL                                       │
│  ─────────                     ───────                                       │
│  CTRL = Control                REM = Comment                                 │
│  ALT = Alt                     REPEAT n = Repeat previous                    │
│  SHIFT = Shift                 DEFAULT_DELAY n = Delay all                   │
│  GUI = Win/Cmd                                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Next Steps

Now that you understand the fundamentals:

1. **[FZ-B01 Hello World](../02_Basic_Scripts/FZ-B01_Hello_World.md)** - Your first complete payload
2. **[Basic Challenges](../../Chapter_05_Skill_Levels/01_Basic/Challenges/)** - Test your knowledge
3. **[Command Reference](Command_Reference.md)** - Full command documentation

---

[← Back to Chapter 1](../README.md) | [Next: Complete Command Reference →](Command_Reference.md)
