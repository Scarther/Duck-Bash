# FZ-B02: Hello World - macOS

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B02 |
| **Name** | Hello World - macOS |
| **Difficulty** | Basic |
| **Target OS** | macOS 12+ |
| **Execution Time** | ~5 seconds |
| **Prerequisites** | None |

## What This Payload Does

Opens TextEdit through Spotlight search and types a greeting message.

---

## The Payload

```ducky
REM =============================================
REM BASIC: Hello World - macOS
REM Target: macOS 12+
REM Action: Opens TextEdit via Spotlight
REM Skill: Basic
REM =============================================

DELAY 2000
GUI SPACE
DELAY 700
STRING textedit
DELAY 500
ENTER
DELAY 1500
STRING Hello from Flipper Zero on Mac!
```

---

## Line-by-Line Breakdown

| Line | Command | Purpose |
|------|---------|---------|
| 1-6 | REM | Documentation header |
| 8 | DELAY 2000 | Wait for USB enumeration |
| 9 | GUI SPACE | Open Spotlight (Cmd+Space) |
| 10 | DELAY 700 | Wait for Spotlight to appear |
| 11 | STRING textedit | Type application name |
| 12 | DELAY 500 | Wait for Spotlight to find app |
| 13 | ENTER | Launch application |
| 14 | DELAY 1500 | Wait for TextEdit to load |
| 15 | STRING... | Type the message |

---

## macOS vs Windows Comparison

```
┌──────────────────────────────────┬──────────────────────────────────┐
│            WINDOWS               │             macOS                │
├──────────────────────────────────┼──────────────────────────────────┤
│                                  │                                  │
│ GUI r = Opens Run dialog         │ GUI SPACE = Opens Spotlight      │
│                                  │                                  │
│ ┌──────────────────┐             │ ┌────────────────────────────┐   │
│ │ Run           X  │             │ │    🔍 [                  ] │   │
│ │ Open: [      ]   │             │ │    Spotlight Search        │   │
│ └──────────────────┘             │ └────────────────────────────┘   │
│                                  │                                  │
│ Direct path/command execution    │ Search-based app launching       │
│ Shorter delays                   │ Longer delays (app indexing)     │
│ notepad                          │ textedit                         │
│                                  │                                  │
└──────────────────────────────────┴──────────────────────────────────┘
```

---

## Key Differences from Windows

1. **GUI SPACE vs GUI r**: macOS uses Spotlight, not a Run dialog
2. **Longer Delays**: macOS apps typically take longer to launch
3. **Extra Delay Before ENTER**: Spotlight needs time to index the search
4. **Application Names**: Different apps (TextEdit vs Notepad)

---

## Common macOS Shortcuts

| Shortcut | DuckyScript | Action |
|----------|-------------|--------|
| Cmd+Space | GUI SPACE | Spotlight |
| Cmd+Q | GUI q | Quit application |
| Cmd+W | GUI w | Close window |
| Cmd+Tab | GUI TAB | Switch apps |
| Cmd+Shift+3 | GUI SHIFT 3 | Screenshot |
| Ctrl+Cmd+Q | CTRL GUI q | Lock screen |

---

## Red Team Perspective

### macOS Considerations
- Spotlight indexes applications, making searches reliable
- TextEdit is always available (no additional software needed)
- macOS has stricter security (Gatekeeper, SIP, TCC)
- Terminal requires more permissions for sensitive operations

### Stealth Considerations
- Spotlight search is visible to user
- TextEdit opens with a visible window
- For covert operations, use Terminal with minimized window

---

## Blue Team Perspective

### Detection Opportunities

1. **USB Device Connection**
   - System Profiler shows new USB devices
   - Console.app logs USB events

2. **Spotlight Activation**
   - Rapid Spotlight open → type → enter pattern

3. **Application Launch**
   - TextEdit launched from Spotlight is logged

### macOS Security Controls

| Control | Protection |
|---------|------------|
| Gatekeeper | Blocks unsigned apps |
| SIP (System Integrity Protection) | Protects system files |
| TCC (Transparency, Consent, Control) | Restricts app permissions |
| Sandboxing | Limits app access |

---

## Practice Exercises

### Exercise 1: Different Applications
Modify the payload to open:
- Safari: `STRING safari`
- Terminal: `STRING terminal`
- Notes: `STRING notes`

### Exercise 2: Timing Optimization
Test different delay values on your Mac:
- What's the minimum Spotlight delay?
- What's the minimum app launch delay?

### Exercise 3: Lock Screen
Create a payload that locks the Mac:
```ducky
DELAY 1500
CTRL GUI q
```

---

## Payload File

Save as `FZ-B02_Hello_World_macOS.txt`:

```ducky
REM FZ-B02: Hello World - macOS
DELAY 2000
GUI SPACE
DELAY 700
STRING textedit
DELAY 500
ENTER
DELAY 1500
STRING Hello from Flipper Zero on Mac!
```

---

[← Back to Basic Scripts](README.md) | [Next: FZ-B03 Linux →](FZ-B03_Hello_World_Linux.md)
