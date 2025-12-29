# Firmware Ecosystem Guide

## Overview

This guide covers the various firmware options for Flipper Zero and other BadUSB devices, including official releases, custom firmware, and management tools.

---

## Flipper Zero Firmware Options

### Official Firmware

| Version | Source | Features |
|---------|--------|----------|
| Official | flipperzero.one | Stable, FCC compliant, regular updates |

**Installation via qFlipper:**
```bash
# Linux: Install qFlipper
flatpak install flathub one.flipperzero.qFlipper

# Or via apt (Debian/Ubuntu)
sudo apt install qflipper
```

### Custom Firmware Comparison

| Firmware | Focus | Key Differences |
|----------|-------|-----------------|
| Unleashed | Extended features | More Sub-GHz frequencies, extended protocols |
| RogueMaster | All-in-one | Includes many apps, animations |
| Xtreme | UI/UX | Enhanced interface, asset packs |

**Note**: Custom firmware may enable features not legal in all regions.

---

## Firmware Management

### qFlipper CLI Commands

```bash
#!/bin/bash
#######################################
# Flipper Zero Firmware Management
#######################################

# Check connected Flipper
qFlipper-cli info

# Backup current firmware and data
qFlipper-cli backup ./flipper_backup_$(date +%Y%m%d)

# Update to latest official firmware
qFlipper-cli update

# Restore from backup
qFlipper-cli restore ./flipper_backup_YYYYMMDD
```

### Manual Firmware Flash via DFU

```bash
#!/bin/bash
#######################################
# DFU Mode Firmware Flash
# For recovery or custom firmware
#######################################

FIRMWARE_FILE="$1"

if [ -z "$FIRMWARE_FILE" ]; then
    echo "Usage: $0 <firmware.dfu>"
    exit 1
fi

# Check for dfu-util
if ! command -v dfu-util &>/dev/null; then
    echo "[!] dfu-util not found. Installing..."
    sudo apt install dfu-util
fi

echo "[*] Put Flipper in DFU mode:"
echo "    1. Hold LEFT + BACK buttons"
echo "    2. While holding, connect USB"
echo "    3. Release when screen shows DFU mode"
echo ""
read -p "Press Enter when Flipper is in DFU mode..."

# Check DFU device
if ! dfu-util -l | grep -q "0483:df11"; then
    echo "[!] Flipper not detected in DFU mode"
    exit 1
fi

echo "[+] Flipper detected in DFU mode"
echo "[*] Flashing firmware: $FIRMWARE_FILE"

# Flash firmware
dfu-util -a 0 -D "$FIRMWARE_FILE"

echo "[+] Flash complete. Flipper will reboot."
```

---

## BadUSB Payload Structure

### DuckyScript File Format

```
/ext/badusb/
├── payloads/
│   ├── windows/
│   │   ├── info_gather.txt
│   │   └── reverse_shell.txt
│   ├── linux/
│   │   └── persistence.txt
│   └── macos/
│       └── screenshot.txt
└── my_payloads/
    └── custom.txt
```

### Payload Header Best Practices

```
REM =============================================
REM Payload: System Information Collector
REM Author: Security Training
REM Target: Windows 10/11
REM Version: 1.0
REM Date: 2024-01-01
REM =============================================
REM Description:
REM   Collects basic system information for
REM   authorized security assessments only.
REM =============================================
REM MITRE ATT&CK: T1082 (System Information Discovery)
REM =============================================

DELAY 2000
GUI r
...
```

---

## SD Card Management

### Directory Structure

```
/ext/                          # External storage root
├── apps/                      # FAP applications
│   ├── GPIO/
│   ├── Games/
│   ├── Media/
│   └── Tools/
├── apps_data/                 # Application data
├── badusb/                    # BadUSB payloads
├── dolphin/                   # Virtual pet data
├── ibutton/                   # iButton keys
├── infrared/                  # IR remotes
├── lfrfid/                    # 125 kHz RFID data
├── nfc/                       # NFC data
├── subghz/                    # Sub-GHz captures
└── update/                    # Firmware updates
```

### SD Card Health Check

```bash
#!/bin/bash
#######################################
# Flipper SD Card Health Check
#######################################

MOUNT_POINT="/media/$USER/Flipper SD"

if [ ! -d "$MOUNT_POINT" ]; then
    echo "[!] Flipper SD card not mounted"
    echo "[*] Connect Flipper via USB and enable Mass Storage mode"
    exit 1
fi

echo "[+] Flipper SD card found at: $MOUNT_POINT"
echo ""

# Check available space
echo "[*] Storage Status:"
df -h "$MOUNT_POINT"
echo ""

# Count files by type
echo "[*] Content Summary:"
echo "  BadUSB payloads: $(find "$MOUNT_POINT/badusb" -name "*.txt" 2>/dev/null | wc -l)"
echo "  FAP apps: $(find "$MOUNT_POINT/apps" -name "*.fap" 2>/dev/null | wc -l)"
echo "  NFC saves: $(find "$MOUNT_POINT/nfc" -name "*.nfc" 2>/dev/null | wc -l)"
echo "  Sub-GHz captures: $(find "$MOUNT_POINT/subghz" -name "*.sub" 2>/dev/null | wc -l)"
echo "  IR remotes: $(find "$MOUNT_POINT/infrared" -name "*.ir" 2>/dev/null | wc -l)"
echo ""

# Check for filesystem errors
echo "[*] Checking filesystem..."
sudo fsck -n "$(df "$MOUNT_POINT" | tail -1 | awk '{print $1}')" 2>/dev/null
```

---

## USB Rubber Ducky Firmware

### Ducky Firmware Versions

| Version | Features |
|---------|----------|
| 1.0 | Original, basic HID |
| 2.0 | Enhanced timing, storage |
| 3.0 | USB-C, expanded memory |

### Ducky Encoder Usage

```bash
#!/bin/bash
#######################################
# DuckyScript Encoder
# Convert .txt to inject.bin
#######################################

# Install Java if needed
if ! command -v java &>/dev/null; then
    echo "[!] Java required for encoder"
    sudo apt install default-jre
fi

# Download encoder if not present
ENCODER="duckencoder.jar"
if [ ! -f "$ENCODER" ]; then
    echo "[*] Downloading DuckEncoder..."
    wget https://github.com/hak5darren/USB-Rubber-Ducky/raw/master/Encoder/encoder.jar -O "$ENCODER"
fi

# Encode payload
INPUT="$1"
OUTPUT="${INPUT%.txt}.bin"
LAYOUT="${2:-us}"

if [ -z "$INPUT" ]; then
    echo "Usage: $0 <payload.txt> [keyboard_layout]"
    echo "Layouts: us, uk, de, fr, es, it, etc."
    exit 1
fi

echo "[*] Encoding: $INPUT"
echo "[*] Layout: $LAYOUT"
echo "[*] Output: $OUTPUT"

java -jar "$ENCODER" -i "$INPUT" -o "$OUTPUT" -l "$LAYOUT"

echo "[+] Encoded successfully"
ls -la "$OUTPUT"
```

---

## DigiSpark Firmware

### Arduino IDE Setup

```cpp
/*
 * DigiSpark BadUSB Setup
 * Board: Digispark (Default - 16.5mhz)
 *
 * Install:
 *   1. File > Preferences > Additional Board URLs:
 *      http://digistump.com/package_digistump_index.json
 *   2. Tools > Board Manager > Install Digistump AVR
 */

#include "DigiKeyboard.h"

void setup() {
    DigiKeyboard.delay(2000);  // Initial delay

    // Open Run dialog
    DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
    DigiKeyboard.delay(500);

    // Type command
    DigiKeyboard.print("notepad");
    DigiKeyboard.sendKeyStroke(KEY_ENTER);
    DigiKeyboard.delay(1000);

    // Type message
    DigiKeyboard.print("DigiSpark BadUSB Test");
}

void loop() {
    // Nothing in loop
}
```

### DigiSpark Key Codes

```cpp
// Common key codes for DigiSpark
#define KEY_A         0x04
#define KEY_ENTER     0x28
#define KEY_ESC       0x29
#define KEY_BACKSPACE 0x2A
#define KEY_TAB       0x2B
#define KEY_SPACE     0x2C

// Modifier keys
#define MOD_CTRL_LEFT   0x01
#define MOD_SHIFT_LEFT  0x02
#define MOD_ALT_LEFT    0x04
#define MOD_GUI_LEFT    0x08  // Windows/Command key
```

---

## Raspberry Pi Pico BadUSB

### CircuitPython Setup

```python
#!/usr/bin/env python3
"""
Raspberry Pi Pico BadUSB
Requires: CircuitPython + adafruit_hid library

Setup:
1. Flash CircuitPython UF2 to Pico
2. Copy adafruit_hid library to /lib/
3. Save this as code.py on CIRCUITPY drive
"""

import time
import board
import digitalio
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keycode import Keycode
from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS

# Initialize keyboard
kbd = Keyboard(usb_hid.devices)
layout = KeyboardLayoutUS(kbd)

# LED indicator
led = digitalio.DigitalInOut(board.LED)
led.direction = digitalio.Direction.OUTPUT

def blink(times=1):
    for _ in range(times):
        led.value = True
        time.sleep(0.1)
        led.value = False
        time.sleep(0.1)

def send_string(text):
    layout.write(text)

def press_keys(*keys):
    kbd.press(*keys)
    kbd.release_all()

# Main payload
time.sleep(2)  # Initial delay
blink(3)       # Indicate start

# Open Run dialog (Windows)
press_keys(Keycode.GUI, Keycode.R)
time.sleep(0.5)

# Type command
send_string("notepad")
press_keys(Keycode.ENTER)
time.sleep(1)

# Type message
send_string("Pico BadUSB Test")

blink(5)  # Indicate complete
```

---

## Firmware Security

### Verification Script

```bash
#!/bin/bash
#######################################
# Firmware Integrity Verification
#######################################

FIRMWARE_FILE="$1"

if [ -z "$FIRMWARE_FILE" ]; then
    echo "Usage: $0 <firmware_file>"
    exit 1
fi

echo "[*] Analyzing firmware: $FIRMWARE_FILE"
echo ""

# File type
echo "[*] File type:"
file "$FIRMWARE_FILE"
echo ""

# SHA256 hash
echo "[*] SHA256 hash:"
sha256sum "$FIRMWARE_FILE"
echo ""

# Check for known signatures
echo "[*] Checking for embedded signatures..."
if strings "$FIRMWARE_FILE" | grep -qiE "flipper|stm32|dfu"; then
    echo "[+] Contains expected firmware strings"
else
    echo "[!] Unusual firmware - may not be authentic"
fi

# Entropy analysis (high entropy = possibly encrypted/compressed)
echo ""
echo "[*] Entropy analysis:"
if command -v ent &>/dev/null; then
    ent "$FIRMWARE_FILE" | head -3
else
    echo "[!] Install 'ent' for entropy analysis"
fi

# Size check
SIZE=$(stat -f%z "$FIRMWARE_FILE" 2>/dev/null || stat -c%s "$FIRMWARE_FILE")
echo ""
echo "[*] File size: $SIZE bytes"

if [ "$SIZE" -lt 100000 ]; then
    echo "[!] Warning: Firmware seems too small"
elif [ "$SIZE" -gt 2000000 ]; then
    echo "[!] Warning: Firmware seems too large"
else
    echo "[+] Size appears normal"
fi
```

---

## Firmware Update Schedule

### Best Practices

1. **Check for updates weekly** - Security patches
2. **Read changelogs** - Understand what changed
3. **Backup before updating** - Preserve configs and data
4. **Test after updating** - Verify functionality
5. **Keep rollback option** - Store previous firmware

### Update Notification Script

```bash
#!/bin/bash
#######################################
# Check for Flipper Firmware Updates
#######################################

echo "[*] Checking for Flipper Zero firmware updates..."

# GitHub API for latest release
LATEST=$(curl -s https://api.github.com/repos/flipperdevices/flipperzero-firmware/releases/latest | \
    grep '"tag_name"' | cut -d'"' -f4)

echo "[+] Latest official release: $LATEST"
echo "[*] Release notes: https://github.com/flipperdevices/flipperzero-firmware/releases/tag/$LATEST"
```

---

[← Back to Technical Addendum](../README.md)
