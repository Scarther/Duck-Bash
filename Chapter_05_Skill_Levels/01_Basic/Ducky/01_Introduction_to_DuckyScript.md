# Basic Level: Introduction to DuckyScript

## Lesson 1: What is DuckyScript?

Welcome to your first DuckyScript lesson! By the end of this lesson, you'll understand what DuckyScript is and write your first payload.

---

## Learning Objectives

By the end of this lesson, you will be able to:
- [ ] Explain what DuckyScript is and why it's used
- [ ] Identify the basic structure of a DuckyScript payload
- [ ] Write a simple "Hello World" payload
- [ ] Understand the relationship between DuckyScript and Bash

---

## What is DuckyScript?

DuckyScript is a **scripting language for keystroke injection**. It tells a device (like Flipper Zero) what keys to "press" on a target computer.

### Simple Analogy

Imagine you could record yourself typing on a keyboard and play it back at super speed. That's essentially what DuckyScript does!

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DUCKYSCRIPT CONCEPT                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   YOUR SCRIPT                FLIPPER ZERO               COMPUTER             │
│   ───────────                ────────────               ────────             │
│                                                                              │
│   STRING hello    ───▶    "Press h,e,l,l,o"    ───▶    "hello" appears      │
│   ENTER           ───▶    "Press Enter key"    ───▶    Command runs         │
│   DELAY 1000      ───▶    "Wait 1 second"      ───▶    (nothing visible)    │
│                                                                              │
│   The computer thinks a human is typing very fast!                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## DuckyScript vs Bash: Understanding the Difference

Throughout this training, you'll learn both DuckyScript AND Bash. Here's how they're different:

| Aspect | DuckyScript | Bash |
|--------|-------------|------|
| **What it does** | Simulates keystrokes | Runs system commands |
| **Where it runs** | On Flipper Zero | On the target computer |
| **Analogy** | Robot typing on keyboard | Speaking directly to computer |
| **Use case** | BadUSB attacks | WiFi Pineapple payloads |
| **Speed** | Limited by typing speed | As fast as system allows |

### Visual Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     DUCKYSCRIPT vs BASH                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DUCKYSCRIPT (Flipper Zero)           BASH (WiFi Pineapple)                 │
│  ──────────────────────────           ────────────────────────              │
│                                                                              │
│  ┌─────────┐                          ┌─────────┐                           │
│  │ Flipper │ ──USB──▶ Computer        │ Pager   │ ──WiFi──▶ Networks        │
│  └─────────┘                          └─────────┘                           │
│       │                                    │                                 │
│       ▼                                    ▼                                 │
│  "Types" commands                    Runs commands directly                  │
│  into computer                       on the Pager itself                     │
│       │                                    │                                 │
│       ▼                                    ▼                                 │
│  Computer executes                   Pager attacks wireless                  │
│  the "typed" commands                networks around it                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Your First DuckyScript Commands

Let's learn the essential commands:

### 1. REM - Comments

```ducky
REM This is a comment
REM The computer ignores these lines
REM Use them to explain your code
```

**What it does**: Nothing! Comments are notes for humans.

**Why use them**:
- Document what your payload does
- Explain complex sections
- Future you will thank you!

---

### 2. DELAY - Wait

```ducky
DELAY 1000
```

**What it does**: Pauses for specified milliseconds.

**Common values**:
| Code | Wait Time |
|------|-----------|
| `DELAY 500` | Half a second |
| `DELAY 1000` | One second |
| `DELAY 2000` | Two seconds |
| `DELAY 5000` | Five seconds |

**Why it matters**: Computers need time to:
- Recognize USB devices
- Open applications
- Process commands

---

### 3. STRING - Type Text

```ducky
STRING Hello World
```

**What it does**: Types the exact text shown.

**Important**:
- Does NOT press Enter
- Types exactly what you write
- Spaces are typed too

---

### 4. ENTER - Press Enter Key

```ducky
ENTER
```

**What it does**: Presses the Enter key.

**Use it to**:
- Submit commands
- Confirm dialogs
- Add line breaks

---

### 5. GUI - Windows/Command Key

```ducky
GUI r
```

**What it does**: Holds Windows key and presses another key.

**Common combinations**:
| Code | Shortcut | Action |
|------|----------|--------|
| `GUI r` | Win+R | Open Run dialog |
| `GUI d` | Win+D | Show desktop |
| `GUI l` | Win+L | Lock screen |
| `GUI e` | Win+E | Open File Explorer |

---

## Your First Payload: Hello World

Let's write a complete payload step by step!

### Goal
Open Notepad and type "Hello World"

### Step 1: Plan It Out

Before writing code, plan what a human would do:
1. Press Windows+R (open Run dialog)
2. Type "notepad"
3. Press Enter
4. Wait for Notepad to open
5. Type "Hello World"

### Step 2: Write the Code

```ducky
REM ========================================
REM Payload: Hello World
REM Target: Windows 10/11
REM Description: Opens Notepad and types a message
REM ========================================

REM Step 1: Wait for USB to be ready
DELAY 2000

REM Step 2: Open Run dialog (Windows+R)
GUI r

REM Step 3: Wait for Run dialog to appear
DELAY 500

REM Step 4: Type "notepad"
STRING notepad

REM Step 5: Press Enter to launch Notepad
ENTER

REM Step 6: Wait for Notepad to open
DELAY 1000

REM Step 7: Type our message
STRING Hello World!
STRING
STRING This is my first DuckyScript payload!
```

### Step 3: Understanding Each Line

| Line | Command | What Happens |
|------|---------|--------------|
| 1-5 | REM | Comments (ignored) |
| 8 | DELAY 2000 | Wait 2 seconds for USB |
| 11 | GUI r | Press Windows+R |
| 14 | DELAY 500 | Wait for dialog |
| 17 | STRING notepad | Type "notepad" |
| 20 | ENTER | Press Enter |
| 23 | DELAY 1000 | Wait for app |
| 26-28 | STRING | Type our message |

---

## Side-by-Side: DuckyScript vs Bash

The same task in both languages:

```
┌──────────────────────────────────┬──────────────────────────────────┐
│         DUCKYSCRIPT              │              BASH                │
├──────────────────────────────────┼──────────────────────────────────┤
│                                  │                                  │
│ REM Open notepad and type        │ # Open notepad and type          │
│                                  │                                  │
│ DELAY 2000                       │ sleep 2                          │
│                                  │                                  │
│ GUI r                            │ # No direct equivalent           │
│ DELAY 500                        │ # Bash runs ON the system        │
│ STRING notepad                   │ # not through keyboard           │
│ ENTER                            │                                  │
│ DELAY 1000                       │ # In Bash, you'd directly run:   │
│                                  │ notepad.exe &                    │
│ STRING Hello World!              │ sleep 1                          │
│                                  │ echo "Hello World!"              │
│                                  │                                  │
│ # This TYPES into any app        │ # This OUTPUTS to terminal       │
│                                  │                                  │
└──────────────────────────────────┴──────────────────────────────────┘
```

**Key difference**: DuckyScript types INTO applications. Bash runs commands directly.

---

## Red Team Perspective

### Why Learn Hello World?

Even this simple payload proves:
- Physical access = code execution
- USB ports are enabled
- HID devices are trusted
- Security controls can be tested

### Hello World Variations for Testing

| Purpose | Modification |
|---------|--------------|
| Visibility test | Leave Notepad open with message |
| Stealth test | Close Notepad after typing |
| Speed test | Minimize delays |
| Layout test | Type special characters |

---

## Blue Team Perspective

### What This Looks Like to Defenders

Even Hello World creates detectable artifacts:

1. **USB Device Log**: New HID keyboard connected
2. **Process Creation**: notepad.exe launched from explorer.exe
3. **Behavioral Anomaly**: Run dialog → Notepad → rapid typing

### Simple Detection

If you see in logs:
- New USB HID device
- Followed immediately by Run dialog
- Then rapid application launch
- Then text typed faster than humanly possible

...that's likely a BadUSB attack!

---

## Practice Exercises

### Exercise 1: Modify the Message
Change the Hello World payload to type:
- Your name
- Today's date
- A short poem

### Exercise 2: Different Application
Write a payload that opens:
- Calculator (`calc`)
- Notepad (`notepad`) - done!
- Paint (`mspaint`)

### Exercise 3: Add Your Name
Create a payload that:
1. Opens Notepad
2. Types "Created by: [Your Name]"
3. Types the current date (manually type it)

### Exercise 4: Time It
Modify the payload with different DELAY values:
- What's the minimum delay that works?
- What happens with no delays?

---

## Self-Check Quiz

1. What does `REM` do?
   - [ ] Removes a line
   - [ ] Adds a comment (correct)
   - [ ] Repeats a command

2. What does `DELAY 1000` mean?
   - [ ] Wait 1000 seconds
   - [ ] Wait 1000 milliseconds (correct)
   - [ ] Type 1000

3. What does `GUI r` do on Windows?
   - [ ] Restarts the computer
   - [ ] Opens Run dialog (correct)
   - [ ] Opens Settings

4. Why do we need delays in payloads?
   - [ ] To make it look human
   - [ ] To let the computer process (correct)
   - [ ] Delays aren't necessary

---

## Summary

**What you learned**:
- DuckyScript simulates keyboard input
- Basic commands: REM, DELAY, STRING, ENTER, GUI
- How to structure a simple payload
- The difference between DuckyScript and Bash

**Commands mastered**:
- [x] REM - Comments
- [x] DELAY - Waiting
- [x] STRING - Typing text
- [x] ENTER - Pressing Enter
- [x] GUI - Windows key combinations

---

## Next Lesson

**[Lesson 2: Understanding Delays and Timing](02_Delays_and_Timing.md)**

In the next lesson, you'll learn:
- Why timing matters
- How to calibrate delays
- DEFAULT_DELAY for reliability
- Troubleshooting timing issues

---

[← Back to Basic Ducky](README.md) | [Next: Delays and Timing →](02_Delays_and_Timing.md)
