# Flipper Zero Hardware Deep Dive

## Overview

This document provides detailed hardware specifications, pinouts, and technical information for the Flipper Zero device used in BadUSB attacks.

---

## Device Specifications

| Component | Specification |
|-----------|--------------|
| MCU | STM32WB55RG (ARM Cortex-M4 + Cortex-M0+) |
| Clock Speed | 64 MHz (M4), 32 MHz (M0+) |
| Flash | 1 MB |
| RAM | 256 KB SRAM |
| Display | 1.4" 128x64 monochrome LCD |
| Battery | 2000 mAh LiPo |
| USB | USB 2.0 Type-C (OTG capable) |
| Sub-GHz Radio | CC1101 (300-928 MHz) |
| NFC | ST25R3916 (13.56 MHz) |
| RFID | 125 kHz reader/emulator |
| IR | 38 kHz transmitter/receiver |
| iButton | 1-Wire interface |
| GPIO | 18 pins exposed |

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         FLIPPER ZERO                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │   CC1101    │    │  STM32WB55  │    │   ST25R3916 │            │
│   │  Sub-GHz    │◄──►│  Main MCU   │◄──►│    NFC      │            │
│   │  300-928MHz │    │  M4 + M0+   │    │  13.56 MHz  │            │
│   └─────────────┘    └──────┬──────┘    └─────────────┘            │
│                             │                                       │
│   ┌─────────────┐          │          ┌─────────────┐              │
│   │  125 kHz    │◄─────────┼─────────►│    IR       │              │
│   │  RFID       │          │          │  TX/RX      │              │
│   └─────────────┘          │          └─────────────┘              │
│                             │                                       │
│   ┌─────────────┐    ┌─────┴─────┐    ┌─────────────┐              │
│   │   GPIO      │◄──►│    USB    │◄──►│   Display   │              │
│   │  18 pins    │    │  Type-C   │    │  128x64 LCD │              │
│   └─────────────┘    └───────────┘    └─────────────┘              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## GPIO Pinout

### Pin Header Layout

```
                    TOP VIEW (Screen facing up)
    ┌─────────────────────────────────────────────────┐
    │  ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐     │
    │  │1│ │2│ │3│ │4│ │5│ │6│ │7│ │8│ │9│ │10│     │
    │  └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘      │
    │  ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐              │
    │  │11││12││13││14││15││16││17││18│              │
    │  └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘ └─┘              │
    └─────────────────────────────────────────────────┘
```

### Pin Assignments

| Pin | Name | Function | Notes |
|-----|------|----------|-------|
| 1 | 5V | Power Output | From USB when connected |
| 2 | A7 | ADC/GPIO | Analog input capable |
| 3 | A6 | ADC/GPIO | Analog input capable |
| 4 | A4 | ADC/GPIO | Analog input capable |
| 5 | B3 | GPIO/SPI | SPI1_SCK alternate |
| 6 | B2 | GPIO | General purpose |
| 7 | C3 | GPIO | General purpose |
| 8 | GND | Ground | Common ground |
| 9 | 3V3 | Power Output | 3.3V regulated |
| 10 | C1 | GPIO/ADC | Analog input capable |
| 11 | C0 | GPIO/ADC | Analog input capable |
| 12 | TX | UART TX | Serial transmit |
| 13 | RX | UART RX | Serial receive |
| 14 | SIO | iButton | 1-Wire data |
| 15 | SDA | I2C Data | I2C1_SDA |
| 16 | SCL | I2C Clock | I2C1_SCL |
| 17 | PA0 | GPIO | General purpose |
| 18 | PA1 | GPIO | General purpose |

---

## USB Interface Details

### USB Modes

| Mode | VID | PID | Description |
|------|-----|-----|-------------|
| Normal | 0483 | 5740 | CDC Serial + BadUSB |
| DFU | 0483 | DF11 | Firmware update mode |
| BadUSB | 0483 | 5740 | HID Keyboard emulation |
| Mass Storage | 0483 | 5740 | MicroSD access |

### USB Descriptor (BadUSB Mode)

```c
// USB HID Report Descriptor for Keyboard
static const uint8_t hid_report_descriptor[] = {
    0x05, 0x01,        // Usage Page (Generic Desktop)
    0x09, 0x06,        // Usage (Keyboard)
    0xA1, 0x01,        // Collection (Application)

    // Modifier keys
    0x05, 0x07,        //   Usage Page (Key Codes)
    0x19, 0xE0,        //   Usage Minimum (224)
    0x29, 0xE7,        //   Usage Maximum (231)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x95, 0x08,        //   Report Count (8)
    0x75, 0x01,        //   Report Size (1)
    0x81, 0x02,        //   Input (Data, Variable, Absolute)

    // Reserved byte
    0x95, 0x01,        //   Report Count (1)
    0x75, 0x08,        //   Report Size (8)
    0x81, 0x01,        //   Input (Constant)

    // Key codes
    0x95, 0x06,        //   Report Count (6)
    0x75, 0x08,        //   Report Size (8)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x65,        //   Logical Maximum (101)
    0x05, 0x07,        //   Usage Page (Key Codes)
    0x19, 0x00,        //   Usage Minimum (0)
    0x29, 0x65,        //   Usage Maximum (101)
    0x81, 0x00,        //   Input (Data, Array)

    0xC0               // End Collection
};
```

---

## CC1101 Sub-GHz Radio

### Supported Frequencies

| Region | Frequency Range | Common Uses |
|--------|-----------------|-------------|
| 315 MHz | 300-348 MHz | US garage doors, car keys |
| 433 MHz | 387-464 MHz | EU/Asia remotes, sensors |
| 868 MHz | 779-928 MHz | EU ISM band |
| 915 MHz | 779-928 MHz | US ISM band |

### RF Parameters

```
Maximum TX Power: +10 dBm
Sensitivity: -110 dBm
Data Rates: 1.2 - 500 kbps
Modulations: ASK/OOK, 2-FSK, 4-FSK, GFSK, MSK
```

---

## NFC Capabilities

### Supported Standards

| Standard | Frequency | Use Cases |
|----------|-----------|-----------|
| ISO 14443-A | 13.56 MHz | MIFARE, NFC-A |
| ISO 14443-B | 13.56 MHz | NFC-B cards |
| ISO 15693 | 13.56 MHz | NFC-V, vicinity cards |
| FeliCa | 13.56 MHz | Sony contactless |

### Operating Modes

- **Reader Mode**: Read NFC tags and cards
- **Writer Mode**: Write to writable tags
- **Emulator Mode**: Emulate NFC tags
- **Detect Mode**: Detect card type/UID

---

## RFID 125 kHz

### Supported Protocols

| Protocol | Description |
|----------|-------------|
| EM4100 | Read-only, 40-bit ID |
| HID Prox | HID proximity cards |
| Indala | Motorola/Indala cards |
| AWID | AWID proximity |
| IoProx | Kantech IoProx |
| FDX-B | Animal identification |

---

## Power Management

### Battery Specifications

```
Type: Lithium Polymer (LiPo)
Capacity: 2000 mAh
Voltage: 3.7V nominal
Charge Current: 500 mA (USB)
Protection: Over-charge, over-discharge
```

### Power Consumption

| Mode | Current Draw | Estimated Runtime |
|------|--------------|-------------------|
| Active (Screen on) | ~50 mA | ~40 hours |
| Sub-GHz TX | ~90 mA | ~22 hours |
| Sub-GHz RX | ~30 mA | ~66 hours |
| Sleep | ~300 μA | ~277 days |
| USB Connected | Charging | N/A |

---

## Diagnostic Commands

### Check Hardware Health

```bash
#!/bin/bash
# Check Flipper Zero when connected via USB

# Find Flipper serial device
FLIPPER=$(ls /dev/ttyACM* 2>/dev/null | head -1)

if [ -z "$FLIPPER" ]; then
    echo "[!] Flipper Zero not detected"
    echo "[*] Check USB connection"
    lsusb | grep -i "0483:5740"
    exit 1
fi

echo "[+] Flipper detected at: $FLIPPER"

# Check USB details
echo ""
echo "[*] USB Device Information:"
lsusb -d 0483:5740 -v 2>/dev/null | grep -E "idVendor|idProduct|bcdDevice|iManufacturer|iProduct"

# Check serial port settings
echo ""
echo "[*] Serial Port Settings:"
stty -F "$FLIPPER" -a 2>/dev/null | head -3
```

### Monitor USB HID Events

```bash
#!/bin/bash
# Monitor HID keyboard events from Flipper BadUSB

echo "[*] Monitoring keyboard HID events..."
echo "[*] Press Ctrl+C to stop"
echo ""

# Find keyboard event device
for dev in /dev/input/event*; do
    NAME=$(cat /sys/class/input/$(basename $dev)/device/name 2>/dev/null)
    if echo "$NAME" | grep -qi "flipper\|badusb\|keyboard"; then
        echo "[+] Found device: $NAME at $dev"
        echo "[*] Raw HID events:"
        cat "$dev" | xxd | head -50
        break
    fi
done
```

---

## Security Considerations

### Physical Security

1. **Tamper Evidence**: No hardware tamper detection
2. **JTAG/SWD**: Debug ports accessible (disabled in firmware)
3. **Flash Protection**: Read protection available but not enforced by default

### Attack Surface

| Vector | Risk | Mitigation |
|--------|------|------------|
| Malicious Firmware | High | Verify firmware signatures |
| SD Card Payloads | Medium | Review payloads before loading |
| USB Connection | Low | Standard USB security |
| RF Interference | Low | FCC Part 15 compliance |

---

## Hardware Mods (Reference Only)

### Common Modifications

| Mod | Purpose | Risk |
|-----|---------|------|
| External Antenna | Extended Sub-GHz range | Warranty void, FCC violation |
| Battery Upgrade | Longer runtime | Fire risk if improper |
| GPIO Expansion | Additional sensors | Shorts can damage MCU |

**Warning**: Hardware modifications may void warranty, violate regulations, and damage the device.

---

## Troubleshooting

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Not recognized via USB | Driver issue | Install CDC drivers |
| BadUSB not working | Missing firmware | Flash latest firmware |
| Screen flickering | Low battery | Charge device |
| Sub-GHz weak signal | Antenna issue | Check antenna connection |
| GPIO not responding | Wrong pin mode | Check pin configuration |

---

[← Back to Technical Addendum](../README.md)
