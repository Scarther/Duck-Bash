# USB VID/PID Database

## Common Keyboard VID/PIDs for Spoofing

### Microsoft Devices
| VID | PID | Device |
|-----|-----|--------|
| 0x045E | 0x0745 | Microsoft Natural Ergonomic 4000 |
| 0x045E | 0x0750 | Microsoft Wired Keyboard 600 |
| 0x045E | 0x0752 | Microsoft Wired Keyboard 400 |
| 0x045E | 0x07A5 | Microsoft Wireless Keyboard 2000 |
| 0x045E | 0x07B2 | Microsoft Sculpt Ergonomic |
| 0x045E | 0x0800 | Microsoft Surface Keyboard |

### Logitech Devices
| VID | PID | Device |
|-----|-----|--------|
| 0x046D | 0xC31C | Logitech K120 |
| 0x046D | 0xC318 | Logitech Illuminated Keyboard |
| 0x046D | 0xC52B | Logitech Unifying Receiver |
| 0x046D | 0xC534 | Logitech Unifying Receiver |
| 0x046D | 0xC539 | Logitech Lightspeed Receiver |
| 0x046D | 0xC52E | Logitech MK270 |

### Dell Devices
| VID | PID | Device |
|-----|-----|--------|
| 0x413C | 0x2003 | Dell USB Keyboard |
| 0x413C | 0x2005 | Dell USB Keyboard |
| 0x413C | 0x2010 | Dell USB Keyboard RT7D50 |
| 0x413C | 0x2107 | Dell KB212-B |
| 0x413C | 0x2113 | Dell KB216 |

### HP Devices
| VID | PID | Device |
|-----|-----|--------|
| 0x03F0 | 0x0024 | HP KU-0316 |
| 0x03F0 | 0x034A | HP USB Keyboard |
| 0x03F0 | 0x1024 | HP Keyboard |
| 0x03F0 | 0x2B4A | HP Business Keyboard |

### Lenovo Devices
| VID | PID | Device |
|-----|-----|--------|
| 0x17EF | 0x6009 | Lenovo ThinkPad USB Keyboard |
| 0x17EF | 0x6047 | Lenovo ThinkPad Compact USB |
| 0x17EF | 0x608D | Lenovo Calliope USB Keyboard |

### Apple Devices
| VID | PID | Device |
|-----|-----|--------|
| 0x05AC | 0x0220 | Apple Keyboard (Aluminum) |
| 0x05AC | 0x0221 | Apple Keyboard (ANSI) |
| 0x05AC | 0x024F | Apple Keyboard with NumPad |
| 0x05AC | 0x0250 | Apple Wireless Keyboard |
| 0x05AC | 0x0267 | Apple Magic Keyboard |

---

## USB Class Codes

### Device Classes
| Class | Description | Use Case |
|-------|-------------|----------|
| 0x00 | Defined at Interface | Most devices |
| 0x02 | CDC (Communications) | Serial, Modem |
| 0x03 | HID | Keyboard, Mouse |
| 0x07 | Printer | Printers |
| 0x08 | Mass Storage | USB drives |
| 0x09 | Hub | USB hubs |
| 0x0A | CDC-Data | Serial data |
| 0x0E | Video | Webcams |
| 0xE0 | Wireless Controller | Bluetooth |
| 0xEF | Miscellaneous | Composite |
| 0xFF | Vendor Specific | Custom |

### HID Subclass/Protocol
```
Subclass:
  0x00 = No Subclass
  0x01 = Boot Interface

Protocol (Boot Interface):
  0x00 = None
  0x01 = Keyboard
  0x02 = Mouse
```

---

## DuckyScript VID/PID Configuration

### Flipper Zero BadUSB
```
# In payload file header:
ID 046D:C31C  # Logitech K120
```

### USB Rubber Ducky
```
# In config.txt on MicroSD:
VID 0x046D
PID 0xC31C
MAN Logitech
PROD USB Keyboard
SERIAL 123456
```

---

## Spoofing Recommendations

### By Target Environment

| Environment | Recommended VID/PID | Device |
|-------------|---------------------|--------|
| Corporate (Dell) | 0x413C:0x2113 | Dell KB216 |
| Corporate (HP) | 0x03F0:0x034A | HP USB Keyboard |
| Corporate (Lenovo) | 0x17EF:0x6009 | ThinkPad USB |
| Home/Generic | 0x046D:0xC31C | Logitech K120 |
| Mac Environment | 0x05AC:0x0267 | Apple Magic KB |
| Server Room | 0x413C:0x2003 | Dell Server KB |

### Detection Evasion Tips
```
1. Match VID/PID to existing keyboards in environment
2. Use common manufacturer for the target organization
3. Avoid exotic or gaming keyboard identifiers
4. Match USB descriptor strings (Manufacturer, Product)
5. Consider USB hub if target expects hub-connected device
```

---

## Quick Lookup Script

```bash
#!/bin/bash
# Look up USB VID/PID on connected devices

echo "Connected USB Devices:"
echo "======================"

lsusb | while read line; do
    vid_pid=$(echo "$line" | grep -oE "[0-9a-f]{4}:[0-9a-f]{4}")
    vid=$(echo "$vid_pid" | cut -d: -f1)
    pid=$(echo "$vid_pid" | cut -d: -f2)
    desc=$(echo "$line" | sed 's/.*ID [0-9a-f:]\+ //')

    printf "VID: 0x%s  PID: 0x%s  %s\n" "$vid" "$pid" "$desc"
done
```

---

## USB Descriptor Strings

### Common Manufacturer Strings
```
Microsoft:  "Microsoft"
Logitech:   "Logitech"
Dell:       "Dell", "DELL"
HP:         "Hewlett-Packard", "HP"
Lenovo:     "Lenovo"
Apple:      "Apple Inc."
Generic:    "USB", "USB Device"
```

### Example Full Descriptor
```c
// String Descriptor Example
const char* manufacturer = "Logitech";
const char* product = "USB Keyboard";
const char* serial = "0001";
```

---

[← Protocol Reference](../03_Protocol_Reference/) | [Back to Technical Addendum](../README.md) | [Next: Keyboard Layouts →](../05_Keyboard_Layouts/)
