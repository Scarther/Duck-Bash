# Hardware Deep Dive

## Flipper Zero Hardware

### Processor & Memory
| Component | Specification |
|-----------|---------------|
| **MCU** | STM32WB55RG |
| **Core** | ARM Cortex-M4 @ 64 MHz |
| **Flash** | 1 MB |
| **RAM** | 256 KB SRAM |
| **Co-processor** | ARM Cortex-M0+ for BLE |

### Radio Capabilities
| Radio | Frequency | Protocols |
|-------|-----------|-----------|
| Sub-GHz | 300-928 MHz | Custom, garage doors, remotes |
| NFC | 13.56 MHz | ISO14443, NTAG, Mifare |
| RFID | 125 kHz | EM4100, HID Prox |
| Bluetooth | 2.4 GHz | BLE 5.0 |
| IR | 850-950 nm | Consumer remotes |

### GPIO Pinout
```
┌─────────────────────────────────────────┐
│           FLIPPER ZERO GPIO             │
├─────────────────────────────────────────┤
│                                         │
│  Pin 1:  3.3V        Pin 2:  GND       │
│  Pin 3:  PA7/ADC     Pin 4:  PA6/ADC   │
│  Pin 5:  PA4/DAC     Pin 6:  PB3/SPI   │
│  Pin 7:  PB2/SPI     Pin 8:  PC3       │
│  Pin 9:  PA14/SWCLK  Pin 10: PA13/SWDIO│
│  Pin 11: TX          Pin 12: RX        │
│  Pin 13: PC1         Pin 14: PC0       │
│  Pin 15: 5V (iButton)Pin 16: GND       │
│  Pin 17: ID (1-Wire) Pin 18: 3.3V      │
│                                         │
│  I2C: SDA=Pin13, SCL=Pin14             │
│  SPI: MOSI=Pin6, MISO=Pin7, SCK=Pin8   │
│  UART: TX=Pin11, RX=Pin12              │
│                                         │
└─────────────────────────────────────────┘
```

### USB Controller
- **Interface**: USB 2.0 Full Speed
- **Connector**: USB Type-C
- **Modes**: CDC (Serial), HID (Keyboard/Mouse), Mass Storage
- **VID**: 0x0483 (STMicroelectronics)
- **PID**: 0x5740 (default)

---

## WiFi Pineapple Hardware

### Mark VII Specifications
| Component | Specification |
|-----------|---------------|
| **Processor** | MediaTek MT7621AT (880 MHz MIPS) |
| **RAM** | 256 MB DDR3 |
| **Storage** | 2 GB EMMC + MicroSD |
| **WiFi** | Dual-band 802.11ac (2x2 MIMO) |
| **Ethernet** | 2x Gigabit RJ45 |
| **USB** | 1x USB 3.0 |
| **Power** | 12V DC, USB-C PD |

### Nano Specifications
| Component | Specification |
|-----------|---------------|
| **Processor** | Atheros AR9331 (400 MHz MIPS) |
| **RAM** | 64 MB DDR2 |
| **Storage** | 16 MB Flash + MicroSD |
| **WiFi** | 2.4 GHz 802.11b/g/n |
| **USB** | 1x USB 2.0 |
| **Power** | USB (5V 2A) |

### Radio Chipsets
```
┌─────────────────────────────────────────┐
│         WIFI PINEAPPLE RADIOS           │
├─────────────────────────────────────────┤
│                                         │
│  MARK VII:                              │
│  ├── Radio 0: MT7615 (2.4/5 GHz)       │
│  │   └── Monitor mode: Yes             │
│  │   └── Injection: Yes                │
│  │   └── AP mode: Yes                  │
│  └── Radio 1: MT7612 (5 GHz)           │
│                                         │
│  NANO:                                  │
│  └── Radio 0: AR9331 (2.4 GHz only)    │
│      └── Monitor mode: Yes             │
│      └── Injection: Yes                │
│      └── AP mode: Yes                  │
│                                         │
│  Recommended USB Adapters:              │
│  ├── Alfa AWUS036ACH (RTL8812AU)       │
│  ├── Alfa AWUS036ACHM (MT7612U)        │
│  └── Panda PAU09 (RT5572)              │
│                                         │
└─────────────────────────────────────────┘
```

---

## USB Rubber Ducky Hardware

### Original Ducky
| Component | Specification |
|-----------|---------------|
| **MCU** | AT32UC3B1256 |
| **Architecture** | AVR32 @ 60 MHz |
| **Flash** | 256 KB internal |
| **Storage** | MicroSD (FAT32) |
| **USB** | USB 2.0 HID |

### DuckyScript Processing
```
MicroSD Card
    │
    ▼
┌─────────────┐
│ inject.bin  │ ◄── Compiled payload
└─────────────┘
    │
    ▼
┌─────────────┐
│ Ducky MCU   │ ──▶ USB HID Reports
└─────────────┘
    │
    ▼
┌─────────────┐
│ Target PC   │
└─────────────┘
```

---

## Antenna Specifications

### Flipper Zero Internal Antennas
| Band | Type | Gain |
|------|------|------|
| Sub-GHz | Ceramic chip | 0 dBi |
| NFC | PCB loop | N/A |
| 125 kHz | Ferrite rod | N/A |
| BLE | PCB trace | 0 dBi |
| IR | LED array | N/A |

### WiFi Pineapple Antennas
| Model | Connector | Gain | Notes |
|-------|-----------|------|-------|
| Stock (Mark VII) | RP-SMA | 5 dBi | Omnidirectional |
| Stock (Nano) | Internal | 2 dBi | PCB trace |
| Alfa 9 dBi | RP-SMA | 9 dBi | Omnidirectional |
| Yagi | N-type | 15+ dBi | Directional |
| Panel | N-type | 14 dBi | Directional |

---

## Power Requirements

### Current Draw
| Device | Idle | Active | Peak |
|--------|------|--------|------|
| Flipper Zero | 30 mA | 100 mA | 200 mA |
| Pineapple Nano | 200 mA | 500 mA | 1A |
| Pineapple Mark VII | 500 mA | 1.5A | 3A |
| USB Rubber Ducky | 50 mA | 100 mA | 150 mA |

### Battery Considerations
```
Flipper Zero:
├── Internal: 2000 mAh LiPo
├── Runtime: ~8-12 hours typical
└── Charging: USB-C 5V/500mA

WiFi Pineapple Field Kit:
├── External battery pack recommended
├── 10000 mAh = ~4 hours (Nano)
├── 20000 mAh = ~8 hours (Nano)
└── Mark VII requires 12V or USB-C PD
```

---

## Physical Security

### Tamper Resistance
| Device | Physical Security |
|--------|-------------------|
| Flipper Zero | None (open hardware) |
| Rubber Ducky | Case screws |
| Pineapple | Standard enclosure |

### Concealment Options
```
Common Disguises:
├── USB flash drive enclosure
├── USB charger/hub
├── USB-C adapter
├── Power bank
└── Custom 3D printed cases

Size Comparison:
├── Rubber Ducky: 60x20x10mm
├── Flipper Zero: 100x40x25mm
├── Pineapple Nano: 110x75x25mm
└── Pineapple Mark VII: 150x110x30mm
```

---

[← Back to Technical Addendum](../README.md) | [Next: Firmware Ecosystem →](../02_Firmware_Ecosystem/)
