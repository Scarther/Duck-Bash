# FZ-B01: Hello World - Windows

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B01 |
| **Name** | Hello World - Windows |
| **Difficulty** | Basic |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~5 seconds |
| **Prerequisites** | None |
| **MITRE ATT&CK** | T1059.001 (PowerShell) - though this uses notepad |

## What This Payload Does

This is the simplest possible BadUSB payload. It:
1. Opens the Windows Run dialog
2. Launches Notepad
3. Types a message

**Purpose**: Learn the basic structure of a DuckyScript payload and verify your Flipper Zero is working correctly.

---

## The Payload

```ducky
REM ################################################
REM # Payload: FZ-B01 - Hello World
REM # Target:  Windows 10/11
REM # Author:  Training Repository
REM # Version: 1.0
REM #
REM # Description:
REM # Opens Notepad and types a greeting message.
REM # This is the simplest possible payload for
REM # learning DuckyScript basics.
REM ################################################

REM Wait for USB enumeration to complete
REM This delay ensures the computer recognizes the Flipper
DELAY 2000

REM Open the Windows Run dialog
REM GUI = Windows key, r = the letter r
REM Windows+R is a universal shortcut on Windows
GUI r

REM Wait for the Run dialog to appear
REM 500ms is usually enough, increase if your system is slow
DELAY 500

REM Type "notepad" into the Run dialog
REM This will be typed exactly as shown
STRING notepad

REM Press Enter to execute the command
REM This launches Notepad
ENTER

REM Wait for Notepad to fully open
REM Applications take time to load, be patient
DELAY 1000

REM Type our message into Notepad
STRING Hello from Flipper Zero!
STRING
STRING This is your first BadUSB payload!
STRING If you can read this, your Flipper is working.
```

---

## Line-by-Line Breakdown

### Section 1: Header Comments (Lines 1-11)

```ducky
REM ################################################
REM # Payload: FZ-B01 - Hello World
REM # Target:  Windows 10/11
...
```

**What it does**: Nothing - these are comments.

**Why it matters**:
- Good payloads always start with documentation
- Future you (or teammates) will thank you
- Include: name, target OS, author, description
- `REM` stands for "remark" - computer ignores these lines

---

### Section 2: Initial Delay (Line 14)

```ducky
DELAY 2000
```

**What it does**: Pauses execution for 2000 milliseconds (2 seconds).

**Why it matters**:
When you plug in a USB device, the computer needs time to:
1. Detect the device
2. Query its descriptor
3. Load the appropriate driver
4. Make the device available

This process is called **USB enumeration**. Without this delay, your keystrokes might be lost because the "keyboard" isn't ready yet.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       USB ENUMERATION TIMELINE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  0ms        500ms        1000ms       1500ms       2000ms                    │
│  │           │            │            │            │                        │
│  ▼           ▼            ▼            ▼            ▼                        │
│  ┌───────────┬────────────┬────────────┬────────────┬──────────────────┐    │
│  │  DEVICE   │  DRIVER    │  DEVICE    │   READY    │  SAFE TO START   │    │
│  │  DETECTED │  LOADING   │  INIT      │   STATE    │  TYPING          │    │
│  └───────────┴────────────┴────────────┴────────────┴──────────────────┘    │
│                                                                              │
│  Too Fast (no delay): Keystrokes LOST                                        │
│  With DELAY 2000: All keystrokes RECEIVED                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Common values**:
- Fast systems (SSD, modern): 1000ms may work
- Normal systems: 2000ms recommended
- Slow systems (HDD, older): 3000-4000ms

---

### Section 3: Open Run Dialog (Lines 17-18)

```ducky
GUI r
```

**What it does**: Presses Windows key + R simultaneously.

**Why it matters**:
The Run dialog is the universal gateway to executing commands on Windows:
- Present on ALL Windows versions (XP through 11)
- Works regardless of Start menu configuration
- Provides direct command execution
- No clicking required

**Alternative approaches**:
| Method | Command | Pros | Cons |
|--------|---------|------|------|
| Run dialog | GUI r | Universal, fast | Visible briefly |
| PowerShell | GUI x, i | More power | Menu navigation |
| CMD | GUI r, cmd | Simple commands | Less powerful |
| Search | GUI, STRING... | Natural | Slower, varies by version |

---

### Section 4: Wait for Dialog (Line 22)

```ducky
DELAY 500
```

**What it does**: Waits half a second.

**Why it matters**:
Even though Windows+R is fast, the dialog box takes time to:
1. Render on screen
2. Gain input focus
3. Be ready for text input

Without this delay, your "notepad" text might:
- Be typed into the previous window
- Be partially lost
- Cause errors

**Tuning tip**: If payloads fail intermittently, increase delays slightly.

---

### Section 5: Type Application Name (Lines 25-26)

```ducky
STRING notepad
```

**What it does**: Types the literal text "notepad".

**Why it matters**:
- `STRING` types character-by-character
- No Enter key is pressed (that's separate)
- Case matters for some commands
- Spaces are typed too if included

**Common applications to launch**:
| Application | Command | Purpose |
|-------------|---------|---------|
| Notepad | notepad | Text editing, output display |
| PowerShell | powershell | Advanced commands |
| CMD | cmd | Basic commands |
| Calculator | calc | Testing |
| Browser | chrome/firefox/msedge | Web navigation |

---

### Section 6: Execute Command (Lines 29-30)

```ducky
ENTER
```

**What it does**: Presses the Enter key.

**Why it matters**:
- Separating STRING and ENTER gives control
- Can add delays between if needed
- Alternative: `STRINGLN notepad` combines both

---

### Section 7: Wait for Application (Line 34)

```ducky
DELAY 1000
```

**What it does**: Waits 1 second for Notepad to open.

**Why it matters**:
Applications take time to:
1. Load from disk
2. Initialize
3. Create window
4. Gain focus

If you type too fast, text might be lost or go to wrong window.

---

### Section 8: Type Message (Lines 37-40)

```ducky
STRING Hello from Flipper Zero!
STRING
STRING This is your first BadUSB payload!
STRING If you can read this, your Flipper is working.
```

**What it does**: Types multiple lines of text.

**Important notes**:
- Each STRING is on its own line in the script
- But output is continuous unless you add ENTER
- The blank `STRING ` creates a space/continuation

**To get actual new lines in output**:
```ducky
STRING Line 1
ENTER
STRING Line 2
ENTER
STRING Line 3
```

---

## Red Team Perspective

### Why Start with Hello World?

1. **Proof of Concept**: Verify physical access = code execution
2. **Timing Calibration**: Learn your target's speed
3. **Detection Testing**: See if security tools alert
4. **Trust Building**: Sometimes shown to prove capabilities

### Escalation Path

```
Hello World → System Info → Data Extraction → Persistence → Full Compromise

This payload proves:
✓ Physical access achieved
✓ USB ports not blocked
✓ HID devices accepted
✓ Code execution possible
```

### Making it Stealthier

For real operations, you'd want:
```ducky
REM Stealthier version - opens minimized, faster execution
DELAY 1000
GUI r
DELAY 200
STRING cmd /c echo Hello > %TEMP%\test.txt
ENTER
```

---

## Blue Team Perspective

### Detection Opportunities

Even this simple payload creates artifacts:

#### 1. USB Device Connection
**Windows Event Log**: System
**Event ID**: 20001 (UserPnp)
```
Device Install (USB\VID_XXXX&PID_XXXX\...)
```

#### 2. Process Creation
**Windows Event Log**: Security
**Event ID**: 4688
```
New Process: C:\Windows\System32\notepad.exe
Creator Process: C:\Windows\explorer.exe
```

#### 3. Behavioral Anomaly
- Run dialog opened
- Notepad launched immediately after
- Rapid text input (faster than human)

### Detection Script

```powershell
# Monitor for rapid HID input (simplified)
# Production systems would use more sophisticated detection

$threshold = 100  # characters per second
$sample_time = 5  # seconds

Write-Host "Monitoring keyboard input speed for $sample_time seconds..."
$start = Get-Date
$keystrokes = 0

# This is conceptual - real implementation needs hooks
# Just demonstrates the detection concept

# Alert thresholds
if ($keystrokes / $sample_time -gt $threshold) {
    Write-Warning "ALERT: Abnormally fast keyboard input detected!"
    Write-Warning "Possible BadUSB attack in progress"
}
```

### Prevention Measures

| Level | Control | Implementation |
|-------|---------|----------------|
| Physical | USB port locks | Physical blockers |
| Policy | USB device whitelist | Group Policy, Intune |
| Software | USB device control | Endpoint protection |
| Behavioral | Keystroke analysis | EDR solutions |

---

## Practice Exercises

### Exercise 1: Timing Adjustment
Modify the payload to work on a slower computer by:
1. Doubling all DELAY values
2. Test on a VM with limited resources
3. Find the minimum delays that still work

### Exercise 2: Add Timestamp
Modify the payload to:
1. Type "Hello from Flipper Zero!"
2. Press Enter
3. Type the current date (manually - STRING the date)
4. Press Enter twice
5. Type your name

### Exercise 3: Different Application
Create a new payload that:
1. Opens Calculator instead of Notepad
2. Types: 1337
3. Waits 2 seconds
4. Closes the calculator (ALT F4)

### Exercise 4: Cross-Platform
Create macOS and Linux versions:

**macOS hint**:
```ducky
GUI SPACE
DELAY 500
STRING textedit
ENTER
```

**Linux hint** (GNOME):
```ducky
ALT F2
DELAY 500
STRING gedit
ENTER
```

---

## Common Issues & Solutions

| Problem | Cause | Solution |
|---------|-------|----------|
| Nothing happens | USB enumeration delay too short | Increase initial DELAY |
| Text in wrong window | Application didn't open in time | Increase DELAY after ENTER |
| Missing characters | Typing too fast | Add DEFAULT_DELAY 10 at start |
| Wrong characters | Keyboard layout mismatch | Check Flipper keyboard setting |
| Run dialog doesn't open | GUI key not recognized | Try WINDOWS r instead |

---

## The Actual Payload File

Save this as `FZ-B01_Hello_World.txt` on your Flipper's SD card in `/badusb/`:

```ducky
REM FZ-B01: Hello World - Windows
REM Basic payload for testing and learning

DELAY 2000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING Hello from Flipper Zero!
```

---

## Summary

**What you learned**:
- Basic payload structure
- The importance of delays
- How to open applications via Run dialog
- How to type text with STRING
- Red team uses for simple payloads
- Blue team detection methods

**Next payload**: [FZ-B02: Hello World - macOS](FZ-B02_Hello_World_macOS.md)

---

[← Back to Basic Scripts](README.md) | [Next: FZ-B02 macOS Hello World →](FZ-B02_Hello_World_macOS.md)
