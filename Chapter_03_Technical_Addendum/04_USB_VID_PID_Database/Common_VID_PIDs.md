# USB VID/PID Database for Device Spoofing

## Overview

USB Vendor ID (VID) and Product ID (PID) are used to identify USB devices. BadUSB attacks often spoof legitimate device identifiers to avoid detection.

---

## Flipper Zero Default vs Spoofed

| Mode | VID | PID | Description |
|------|-----|-----|-------------|
| Default | 0483 | 5740 | Flipper Zero (detectable) |
| Spoofed | Varies | Varies | Impersonates legitimate device |

---

## Common Keyboard VID/PIDs for Spoofing

### Microsoft
```
ID 045E:0745  Microsoft Corp - Nano Transceiver
ID 045E:07A5  Microsoft Corp - Wireless Receiver
ID 045E:07B2  Microsoft Corp - 2.4GHz Transceiver
ID 045E:0800  Microsoft Corp - Wireless keyboard/mouse
ID 045E:082C  Microsoft Corp - Ergonomic Keyboard
```

### Logitech
```
ID 046D:C31C  Logitech - Keyboard K120
ID 046D:C52B  Logitech - Unifying Receiver
ID 046D:C534  Logitech - Unifying Receiver (newer)
ID 046D:C539  Logitech - Lightspeed Receiver
ID 046D:C52E  Logitech - MK270 Wireless Combo
```

### Dell
```
ID 413C:2003  Dell - Keyboard
ID 413C:2107  Dell - KB216 Keyboard
ID 413C:2113  Dell - KB522 Business Keyboard
ID 413C:8161  Dell - Integrated Keyboard
```

### HP
```
ID 03F0:0024  HP - KU-0316 Keyboard
ID 03F0:034A  HP - Elite Keyboard
ID 03F0:0324  HP - USB Keyboard
ID 03F0:1027  HP - Virtual Keyboard
```

### Lenovo
```
ID 17EF:6009  Lenovo - ThinkPad Keyboard
ID 17EF:6047  Lenovo - ThinkPad Compact Keyboard
ID 17EF:608D  Lenovo - Keyboard II
ID 17EF:6099  Lenovo - Traditional Keyboard
```

### Apple
```
ID 05AC:024F  Apple - Aluminum Keyboard (ANSI)
ID 05AC:0250  Apple - Aluminum Keyboard (ISO)
ID 05AC:0267  Apple - Magic Keyboard
ID 05AC:029C  Apple - Magic Keyboard with Touch ID
```

---

## DuckyScript Spoofing Examples

### Spoof as Logitech Unifying Receiver
```
ID 046D:C52B Logitech:Unifying Receiver
```

### Spoof as Dell Keyboard
```
ID 413C:2107 Dell:Keyboard
```

### Spoof as Microsoft Keyboard
```
ID 045E:0745 Microsoft:Nano Transceiver
```

### Spoof as Generic HID
```
ID 0000:0000 Generic:USB Keyboard
```

---

## Known BadUSB Device Identifiers (Block List)

### Devices to Block/Alert On
```bash
# Flipper Zero
0483:5740

# USB Rubber Ducky
1532:0110
05AC:021E  # Older Ducky

# DigiSpark
16D0:0753

# Arduino Leonardo (can be BadUSB)
2341:8036
2341:8037

# Teensy (can be BadUSB)
16C0:0483
16C0:0486

# Raspberry Pi Pico
2E8A:0005
```

---

## Blue Team: Detection Script

```bash
#!/bin/bash
#######################################
# USB VID/PID Monitor
# Detect known BadUSB devices
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Known BadUSB VID:PID combinations
BADUSB_DEVICES=(
    "0483:5740"  # Flipper Zero
    "1532:0110"  # Rubber Ducky
    "16D0:0753"  # DigiSpark
    "2341:8036"  # Arduino Leonardo
    "2341:8037"  # Arduino Leonardo
    "16C0:0483"  # Teensy
    "16C0:0486"  # Teensy
    "2E8A:0005"  # Raspberry Pi Pico
)

echo -e "${YELLOW}[*] Scanning for known BadUSB devices...${NC}"

# Get current USB devices
USB_DEVICES=$(lsusb)

ALERTS=0

for device in "${BADUSB_DEVICES[@]}"; do
    VID=$(echo "$device" | cut -d':' -f1)
    PID=$(echo "$device" | cut -d':' -f2)

    if echo "$USB_DEVICES" | grep -qi "$VID:$PID"; then
        echo -e "${RED}[ALERT] Potential BadUSB detected: $device${NC}"
        lsusb -d "$device" 2>/dev/null
        ((ALERTS++))
    fi
done

if [ $ALERTS -eq 0 ]; then
    echo -e "${GREEN}[OK] No known BadUSB devices detected${NC}"
else
    echo -e "${RED}[!] Found $ALERTS potential BadUSB device(s)${NC}"
fi

echo ""
echo -e "${YELLOW}[*] All connected USB devices:${NC}"
lsusb
```

---

## Red Team: Choosing a Spoof Target

### Selection Criteria
1. **Match the environment** - Use devices common in target org
2. **Avoid detection** - Don't use known BadUSB VIDs
3. **Be realistic** - Match expected device types
4. **Consider geography** - US offices likely have US keyboard layouts

### Reconnaissance
```bash
# On a compromised machine, enumerate USB devices:
lsusb
# or
cat /sys/bus/usb/devices/*/idVendor
cat /sys/bus/usb/devices/*/idProduct
```

---

## Reference Links

- [USB ID Database](http://www.linux-usb.org/usb.ids)
- [USB Vendor IDs](https://usb-ids.gowdy.us/)

---

[← Back to Technical Addendum](../README.md)
