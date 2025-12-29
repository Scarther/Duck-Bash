# BadUSB Hardware Comparison Guide

## Overview

This guide compares popular BadUSB devices for authorized security testing and research. Each device has unique capabilities, advantages, and use cases.

---

## Device Comparison Matrix

| Feature | Flipper Zero | USB Rubber Ducky | Bash Bunny | DigiSpark | Pico Ducky | O.MG Cable |
|---------|--------------|------------------|------------|-----------|------------|------------|
| **Price** | ~$170 | ~$80 | ~$120 | ~$5 | ~$10 | ~$180 |
| **Form Factor** | Standalone | USB Drive | USB Drive | Tiny PCB | Tiny PCB | USB Cable |
| **DuckyScript** | Yes (v1) | Yes (v3) | Yes | Arduino | Yes | Yes |
| **Multi-function** | Yes | No | Yes | No | No | Yes |
| **Storage** | SD Card | No | 8GB SSD | Limited | Limited | No |
| **Networking** | No | No | Ethernet | No | No | WiFi |
| **Stealth** | Medium | High | Medium | Very High | Very High | Very High |
| **Ease of Use** | High | High | Medium | Low | Medium | High |
| **Community** | Large | Large | Medium | Medium | Growing | Medium |

---

## Flipper Zero

### Overview

Multi-tool device with BadUSB capability plus RFID, NFC, IR, and Sub-GHz radio functions.

### Specifications

| Spec | Value |
|------|-------|
| CPU | STM32WB55 (ARM Cortex-M4) |
| RAM | 256KB |
| Storage | SD Card (up to 256GB) |
| Display | 1.4" LCD (128x64) |
| Battery | 2000mAh LiPo |
| USB | Type-C (USB 2.0) |

### Pros
- Multi-function (BadUSB is one of many capabilities)
- Active firmware development
- Large community and payload library
- Portable with built-in display
- No PC required for configuration

### Cons
- DuckyScript 1.0 only (limited features)
- More expensive than single-purpose tools
- Larger form factor
- May be restricted in some regions

### DuckyScript Example
```
REM Flipper Zero BadUSB Example
DELAY 1000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING Hello from Flipper Zero!
```

---

## USB Rubber Ducky (Hak5)

### Overview

The original keystroke injection tool. Industry standard for BadUSB attacks.

### Specifications

| Spec | Value |
|------|-------|
| MCU | Atmel AT32UC3B1256 |
| Storage | microSD |
| USB | USB-A |
| Encoder | DuckEncoder (or online) |

### Pros
- Industry standard
- DuckyScript 3.0 (full features)
- Well-documented
- Reliable and tested
- Looks like regular USB drive

### Cons
- Single function only
- Requires separate encoder
- No on-device display
- More expensive than DIY options

### DuckyScript 3.0 Example
```
REM USB Rubber Ducky Advanced Payload
ATTACKMODE HID STORAGE

DELAY 1000
GUI r
DELAY 500
STRING powershell
ENTER
DELAY 1500

VAR $TARGET = "192.168.1.100"

IF $_CAPSLOCK_ON THEN
    CAPSLOCK
END_IF

STRING Write-Host "Connecting to $TARGET"
ENTER
```

---

## Bash Bunny (Hak5)

### Overview

Multi-function attack platform with networking, storage, and keystroke injection.

### Specifications

| Spec | Value |
|------|-------|
| CPU | Quad-core ARM Cortex A7 |
| RAM | 512MB DDR3 |
| Storage | 8GB SSD |
| USB | USB-A |
| Modes | HID, Storage, Ethernet |
| LED | RGB (status indication) |

### Pros
- Multiple attack modes simultaneously
- Ethernet adapter for network attacks
- Built-in storage for loot
- Payload switching via physical toggle
- Full Linux environment

### Cons
- Larger form factor
- Requires more technical knowledge
- More expensive
- Obvious device shape

### Payload Example (BashBunny)
```bash
#!/bin/bash
# Bash Bunny Payload

# Set attack mode
ATTACKMODE HID STORAGE

# Wait for device recognition
sleep 2

# Type commands
Q GUI r
Q DELAY 500
Q STRING powershell
Q ENTER
Q DELAY 1500
Q STRING "Copy-Item C:\\Users\\*\\Documents\\*.docx D:\\"
Q ENTER

# LED indicator
LED FINISH
```

---

## DigiSpark (ATtiny85)

### Overview

Minimal, ultra-cheap BadUSB platform using ATtiny85 microcontroller.

### Specifications

| Spec | Value |
|------|-------|
| MCU | ATtiny85 |
| RAM | 512B |
| Flash | 8KB (6KB usable) |
| USB | USB-A (integrated) |
| GPIO | 6 pins |

### Pros
- Extremely cheap (~$5)
- Very small form factor
- Arduino IDE compatible
- Can be embedded in objects
- Readily available

### Cons
- Limited payload size (~6KB)
- Requires Arduino programming
- No DuckyScript (needs conversion)
- Timing can be unreliable
- No storage

### Arduino Example
```cpp
#include "DigiKeyboard.h"

void setup() {
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(1000);

  // Open Run dialog
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);

  // Type command
  DigiKeyboard.print("notepad");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);

  DigiKeyboard.print("Hello from DigiSpark!");
}

void loop() {
  // Do nothing
}
```

---

## Raspberry Pi Pico (Pico Ducky)

### Overview

Raspberry Pi Pico running CircuitPython for DuckyScript execution.

### Specifications

| Spec | Value |
|------|-------|
| MCU | RP2040 (Dual ARM Cortex-M0+) |
| RAM | 264KB |
| Flash | 2MB |
| USB | Micro-USB |
| GPIO | 26 pins |

### Pros
- Very affordable (~$4-10)
- Full DuckyScript support
- Large storage for payloads
- Active development
- Easy to program (CircuitPython)

### Cons
- Requires setup/flashing
- Micro-USB connector visible
- Needs enclosure for stealth
- Less refined than commercial options

### Setup
```bash
# Flash CircuitPython firmware
# Download from circuitpython.org/board/raspberry_pi_pico

# Copy payload files
cp payload.dd /Volumes/CIRCUITPY/
```

### Payload Example
```
REM Pico Ducky Payload
DELAY 1000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 1000
STRING echo Hello from Pico Ducky!
ENTER
```

---

## O.MG Cable

### Overview

Malicious USB cable with integrated implant. Looks exactly like a regular cable.

### Specifications

| Spec | Value |
|------|-------|
| Form Factor | USB Cable (A, C, Lightning) |
| Wireless | WiFi (ESP8266/ESP32) |
| Range | ~100m with antenna |
| Modes | HID, Geofencing, Exfil |
| Control | Web interface |

### Pros
- Ultimate stealth (looks like normal cable)
- WiFi control and exfiltration
- Geofencing capability
- Multiple cable types available
- Can trigger remotely

### Cons
- Most expensive option
- Requires wireless infrastructure
- Limited payload storage
- Shorter keystroke buffer

### Capabilities
- Keystroke injection (DuckyScript)
- WiFi hotspot/C2
- Geofencing triggers
- Self-destruct command
- Firmware updates OTA

---

## Use Case Recommendations

### For Beginners
1. **Flipper Zero** - Best learning platform, multi-function
2. **Raspberry Pi Pico** - Cheap, good documentation

### For Professionals
1. **USB Rubber Ducky** - Industry standard, DuckyScript 3.0
2. **Bash Bunny** - Advanced attacks, multi-mode

### For Red Team Engagements
1. **O.MG Cable** - Ultimate stealth
2. **DigiSpark** - Cheap, disposable, small

### For Training/Education
1. **Flipper Zero** - Visual, interactive
2. **Pico Ducky** - Cheap for classroom sets

---

## Procurement Notes

| Device | Source | Authenticity Concern |
|--------|--------|---------------------|
| Flipper Zero | Official store, Lab401 | Watch for clones |
| USB Rubber Ducky | Hak5 shop only | Clones exist |
| Bash Bunny | Hak5 shop only | Clones exist |
| DigiSpark | Amazon, AliExpress | Quality varies |
| Pico Ducky | Official RPi dealers | Genuine Pico only |
| O.MG Cable | Hak5 shop only | No third-party |

---

## Legal Considerations

All devices should only be used for:
- Authorized penetration testing
- Security research
- Educational purposes
- Personal learning (on own systems)

Unauthorized use may violate computer crime laws.

---

[← Back to Main](../README.md)
