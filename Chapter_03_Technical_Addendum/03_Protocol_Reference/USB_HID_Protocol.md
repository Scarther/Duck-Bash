# USB HID Protocol Reference

## Overview

This document provides detailed information about the USB Human Interface Device (HID) protocol as it relates to BadUSB keyboard emulation attacks.

---

## USB Protocol Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                          │
│                  (BadUSB Payload / DuckyScript)                 │
├─────────────────────────────────────────────────────────────────┤
│                        HID CLASS                                │
│              (Keyboard/Mouse/Gamepad Reports)                   │
├─────────────────────────────────────────────────────────────────┤
│                      USB TRANSPORT                              │
│              (Control/Interrupt Endpoints)                      │
├─────────────────────────────────────────────────────────────────┤
│                    PHYSICAL LAYER                               │
│                    (USB Signaling)                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## USB Enumeration Process

### Connection Sequence

```
Host                                Device
  │                                    │
  │──── Reset Signal ─────────────────►│
  │                                    │
  │◄─── Device Descriptor Request ─────│
  │──── Device Descriptor Response ───►│
  │                                    │
  │◄─── Set Address ───────────────────│
  │──── Address Acknowledgment ───────►│
  │                                    │
  │◄─── Config Descriptor Request ─────│
  │──── Config Descriptor Response ───►│
  │                                    │
  │◄─── HID Report Descriptor Req ─────│
  │──── HID Report Descriptor Resp ───►│
  │                                    │
  │◄─── Set Configuration ─────────────│
  │──── Configuration Complete ───────►│
  │                                    │
  │     [Device Ready for HID I/O]     │
  │                                    │
```

### Timing Considerations

| Phase | Typical Duration | BadUSB Consideration |
|-------|------------------|---------------------|
| Reset | 10-50 ms | Unavoidable delay |
| Enumeration | 100-500 ms | OS dependent |
| Driver Load | 500-2000 ms | Varies by device class |
| Ready State | 1-3 seconds | **DELAY needed in payload** |

---

## USB Descriptors

### Device Descriptor

```c
// Standard USB Device Descriptor (18 bytes)
typedef struct {
    uint8_t  bLength;            // 18
    uint8_t  bDescriptorType;    // 0x01 (Device)
    uint16_t bcdUSB;             // 0x0200 (USB 2.0)
    uint8_t  bDeviceClass;       // 0x00 (Defined at interface)
    uint8_t  bDeviceSubClass;    // 0x00
    uint8_t  bDeviceProtocol;    // 0x00
    uint8_t  bMaxPacketSize0;    // 64
    uint16_t idVendor;           // VID (e.g., 0x046D for Logitech)
    uint16_t idProduct;          // PID (e.g., 0xC52B)
    uint16_t bcdDevice;          // Device version
    uint8_t  iManufacturer;      // String index
    uint8_t  iProduct;           // String index
    uint8_t  iSerialNumber;      // String index
    uint8_t  bNumConfigurations; // 1
} USB_DeviceDescriptor;
```

### HID Descriptor

```c
// HID Class Descriptor (9 bytes)
typedef struct {
    uint8_t  bLength;            // 9
    uint8_t  bDescriptorType;    // 0x21 (HID)
    uint16_t bcdHID;             // 0x0111 (HID 1.11)
    uint8_t  bCountryCode;       // 0 or country code
    uint8_t  bNumDescriptors;    // 1
    uint8_t  bDescriptorType2;   // 0x22 (Report)
    uint16_t wDescriptorLength;  // Report descriptor length
} USB_HIDDescriptor;
```

---

## Keyboard HID Report

### Report Format (8 bytes)

```
Byte 0: Modifier keys (bitmap)
Byte 1: Reserved (always 0x00)
Bytes 2-7: Key codes (up to 6 simultaneous keys)

┌─────────┬──────────┬────────┬────────┬────────┬────────┬────────┬────────┐
│Modifiers│ Reserved │ Key 1  │ Key 2  │ Key 3  │ Key 4  │ Key 5  │ Key 6  │
└─────────┴──────────┴────────┴────────┴────────┴────────┴────────┴────────┘
```

### Modifier Byte Bitmap

| Bit | Modifier | Description |
|-----|----------|-------------|
| 0 | LEFT_CTRL | Left Control |
| 1 | LEFT_SHIFT | Left Shift |
| 2 | LEFT_ALT | Left Alt |
| 3 | LEFT_GUI | Left Windows/Command |
| 4 | RIGHT_CTRL | Right Control |
| 5 | RIGHT_SHIFT | Right Shift |
| 6 | RIGHT_ALT | Right Alt (AltGr) |
| 7 | RIGHT_GUI | Right Windows |

### Example Reports

```
# Press 'a' key
[0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]

# Release all keys
[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

# Press Shift + 'a' (types 'A')
[0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]

# Press Ctrl + Alt + Delete
[0x05, 0x00, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x00]

# Press GUI + 'r' (Windows Run dialog)
[0x08, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00]
```

---

## USB HID Key Codes

### Letters (US Layout)

| Key | Code | Key | Code | Key | Code |
|-----|------|-----|------|-----|------|
| A | 0x04 | J | 0x0D | S | 0x16 |
| B | 0x05 | K | 0x0E | T | 0x17 |
| C | 0x06 | L | 0x0F | U | 0x18 |
| D | 0x07 | M | 0x10 | V | 0x19 |
| E | 0x08 | N | 0x11 | W | 0x1A |
| F | 0x09 | O | 0x12 | X | 0x1B |
| G | 0x0A | P | 0x13 | Y | 0x1C |
| H | 0x0B | Q | 0x14 | Z | 0x1D |
| I | 0x0C | R | 0x15 | | |

### Numbers

| Key | Code | Key | Code |
|-----|------|-----|------|
| 1 | 0x1E | 6 | 0x23 |
| 2 | 0x1F | 7 | 0x24 |
| 3 | 0x20 | 8 | 0x25 |
| 4 | 0x21 | 9 | 0x26 |
| 5 | 0x22 | 0 | 0x27 |

### Special Keys

| Key | Code | Key | Code |
|-----|------|-----|------|
| Enter | 0x28 | Tab | 0x2B |
| Escape | 0x29 | Space | 0x2C |
| Backspace | 0x2A | Delete | 0x4C |
| Caps Lock | 0x39 | Insert | 0x49 |
| F1 | 0x3A | Home | 0x4A |
| F2 | 0x3B | End | 0x4D |
| F3 | 0x3C | Page Up | 0x4B |
| F4 | 0x3D | Page Down | 0x4E |
| F5 | 0x3E | Right Arrow | 0x4F |
| F6 | 0x3F | Left Arrow | 0x50 |
| F7 | 0x40 | Down Arrow | 0x51 |
| F8 | 0x41 | Up Arrow | 0x52 |
| F9 | 0x42 | Print Screen | 0x46 |
| F10 | 0x43 | Scroll Lock | 0x47 |
| F11 | 0x44 | Pause | 0x48 |
| F12 | 0x45 | | |

### Symbols (US Layout)

| Key | Code | With Shift |
|-----|------|------------|
| - | 0x2D | _ |
| = | 0x2E | + |
| [ | 0x2F | { |
| ] | 0x30 | } |
| \ | 0x31 | \| |
| ; | 0x33 | : |
| ' | 0x34 | " |
| ` | 0x35 | ~ |
| , | 0x36 | < |
| . | 0x37 | > |
| / | 0x38 | ? |

---

## DuckyScript to HID Translation

### Translation Table

| DuckyScript | HID Action |
|-------------|------------|
| `STRING abc` | Send keys [0x04, 0x05, 0x06] sequentially |
| `ENTER` | Send key [0x28] |
| `GUI r` | Send [Modifier: 0x08, Key: 0x15] |
| `CTRL ALT DELETE` | Send [Modifier: 0x05, Key: 0x4C] |
| `DELAY 1000` | Wait 1000ms before next key |
| `SHIFT` | Add 0x02 to modifier byte |

### Implementation Example

```python
#!/usr/bin/env python3
"""
DuckyScript to HID Report Translator
For educational/analysis purposes
"""

# HID key code mapping
KEY_CODES = {
    'a': 0x04, 'b': 0x05, 'c': 0x06, 'd': 0x07, 'e': 0x08,
    'f': 0x09, 'g': 0x0A, 'h': 0x0B, 'i': 0x0C, 'j': 0x0D,
    'k': 0x0E, 'l': 0x0F, 'm': 0x10, 'n': 0x11, 'o': 0x12,
    'p': 0x13, 'q': 0x14, 'r': 0x15, 's': 0x16, 't': 0x17,
    'u': 0x18, 'v': 0x19, 'w': 0x1A, 'x': 0x1B, 'y': 0x1C,
    'z': 0x1D, '1': 0x1E, '2': 0x1F, '3': 0x20, '4': 0x21,
    '5': 0x22, '6': 0x23, '7': 0x24, '8': 0x25, '9': 0x26,
    '0': 0x27, ' ': 0x2C, '-': 0x2D, '=': 0x2E, '[': 0x2F,
    ']': 0x30, '\\': 0x31, ';': 0x33, "'": 0x34, '`': 0x35,
    ',': 0x36, '.': 0x37, '/': 0x38
}

MODIFIERS = {
    'CTRL': 0x01, 'SHIFT': 0x02, 'ALT': 0x04, 'GUI': 0x08,
    'WINDOWS': 0x08, 'COMMAND': 0x08
}

def char_to_hid(char):
    """Convert character to HID report"""
    modifier = 0x00

    if char.isupper():
        modifier = 0x02  # SHIFT
        char = char.lower()

    key_code = KEY_CODES.get(char, 0x00)

    return [modifier, 0x00, key_code, 0x00, 0x00, 0x00, 0x00, 0x00]

def parse_ducky_line(line):
    """Parse a DuckyScript line to HID reports"""
    reports = []
    parts = line.strip().split(' ', 1)
    command = parts[0].upper()

    if command == 'STRING' and len(parts) > 1:
        for char in parts[1]:
            reports.append(char_to_hid(char))
            reports.append([0]*8)  # Key release

    elif command == 'ENTER':
        reports.append([0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00])
        reports.append([0]*8)

    elif command in ['GUI', 'WINDOWS']:
        if len(parts) > 1:
            key = parts[1].lower()
            key_code = KEY_CODES.get(key, 0x00)
            reports.append([0x08, 0x00, key_code, 0x00, 0x00, 0x00, 0x00, 0x00])
            reports.append([0]*8)

    elif command == 'DELAY':
        # Return delay indicator
        if len(parts) > 1:
            reports.append(('DELAY', int(parts[1])))

    return reports

# Example usage
if __name__ == '__main__':
    ducky_script = """
    DELAY 2000
    GUI r
    DELAY 500
    STRING cmd
    ENTER
    """

    print("DuckyScript to HID Translation:")
    print("-" * 50)

    for line in ducky_script.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('REM'):
            continue

        reports = parse_ducky_line(line)
        print(f"\n{line}:")
        for report in reports:
            if isinstance(report, tuple):
                print(f"  {report[0]}: {report[1]}ms")
            else:
                print(f"  {[hex(b) for b in report]}")
```

---

## USB Traffic Analysis

### Capture with Wireshark

```bash
#!/bin/bash
#######################################
# Capture USB HID Traffic
#######################################

# Load USB monitoring kernel module
sudo modprobe usbmon

# Find USB bus
echo "[*] Available USB buses:"
ls /sys/kernel/debug/usb/usbmon/

# Identify target device
echo ""
echo "[*] Connected USB devices:"
lsusb

echo ""
echo "[*] To capture, run Wireshark and select usbmonX interface"
echo "[*] Filter: usb.transfer_type == 0x01 (Interrupt)"
echo "[*] Or filter by device: usb.device_address == X"
```

### Wireshark Display Filters

```
# All HID traffic
usb.transfer_type == 0x01

# Specific device
usb.device_address == 5

# Keyboard data
usb.bInterfaceClass == 0x03 and usb.bInterfaceProtocol == 0x01

# Show data payload
usb.capdata
```

### Decode HID Report Script

```bash
#!/bin/bash
#######################################
# Decode USB HID Keyboard Report
#######################################

decode_report() {
    local report="$1"

    # Parse 8-byte report
    local mod=$(echo "$report" | cut -d' ' -f1)
    local key1=$(echo "$report" | cut -d' ' -f3)

    # Decode modifier
    case "$mod" in
        "00") mod_str="" ;;
        "01") mod_str="CTRL+" ;;
        "02") mod_str="SHIFT+" ;;
        "04") mod_str="ALT+" ;;
        "08") mod_str="GUI+" ;;
        "05") mod_str="CTRL+ALT+" ;;
        *) mod_str="MOD($mod)+" ;;
    esac

    # Decode key (simplified)
    case "$key1" in
        "00") key_str="[release]" ;;
        "04") key_str="a" ;;
        "05") key_str="b" ;;
        # ... (complete mapping)
        "28") key_str="ENTER" ;;
        "2c") key_str="SPACE" ;;
        *) key_str="KEY($key1)" ;;
    esac

    echo "${mod_str}${key_str}"
}

# Example usage
echo "Report: 08 00 15 00 00 00 00 00"
decode_report "08 00 15 00 00 00 00 00"
# Output: GUI+r
```

---

## HID Report Descriptor Parser

```bash
#!/bin/bash
#######################################
# Parse HID Report Descriptor
# Shows structure of HID device
#######################################

DEVICE_PATH="$1"

if [ -z "$DEVICE_PATH" ]; then
    echo "Usage: $0 /dev/hidraw0"
    echo ""
    echo "Available HID devices:"
    ls -la /dev/hidraw* 2>/dev/null
    exit 1
fi

# Read report descriptor
echo "[*] Reading HID Report Descriptor from: $DEVICE_PATH"

# Get descriptor via sysfs
SYSFS_PATH=$(udevadm info -q path -n "$DEVICE_PATH" 2>/dev/null)
if [ -n "$SYSFS_PATH" ]; then
    REPORT_DESC="/sys${SYSFS_PATH}/device/report_descriptor"
    if [ -f "$REPORT_DESC" ]; then
        echo "[+] Found report descriptor"
        echo "[*] Raw bytes:"
        xxd "$REPORT_DESC"
    fi
fi
```

---

## Security Implications

### Attack Vectors via HID

| Attack | Method | Detection |
|--------|--------|-----------|
| Keystroke Injection | Emulate keyboard | Timing analysis |
| UAC Bypass | Alt+Y, GUI shortcuts | Process monitoring |
| PowerShell Download | Type commands | Script logging |
| Credential Theft | Type to phishing | User awareness |

### Defense Mechanisms

1. **USB Device Control** - Whitelist allowed VID/PIDs
2. **HID Report Analysis** - Monitor keystroke rates
3. **Endpoint Protection** - Block suspicious processes
4. **User Training** - Report unknown USB devices

---

[← Back to Technical Addendum](../README.md)
