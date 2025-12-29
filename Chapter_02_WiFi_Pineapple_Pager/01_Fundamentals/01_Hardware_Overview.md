# Hardware Overview

## WiFi Pineapple Models

### Mark VII (Current Generation)

```
┌─────────────────────────────────────────────────────────────┐
│                   WiFi PINEAPPLE MARK VII                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌────────────────────────────────────────────────┐        │
│   │                    TOP VIEW                     │        │
│   │   [USB]  [ETH]  [POWER]     [SMA] [SMA]        │        │
│   │                                                 │        │
│   │   ○ PWR  ○ ETH  ○ WLAN                         │        │
│   │   (LED Indicators)                             │        │
│   │                                                 │        │
│   │              [microSD]                          │        │
│   └────────────────────────────────────────────────┘        │
│                                                              │
│   SPECIFICATIONS:                                           │
│   ├── CPU: MediaTek MT7621AT (880 MHz, MIPS, dual-core)    │
│   ├── RAM: 256 MB DDR3                                      │
│   ├── Storage: 2 GB EMMC + microSD slot                    │
│   ├── WiFi Radio 1: MediaTek MT7612EN (802.11a/b/g/n/ac)   │
│   ├── WiFi Radio 2: MediaTek MT7612EN (802.11a/b/g/n/ac)   │
│   ├── Antennas: 2x RP-SMA (replaceable)                    │
│   ├── USB: 1x USB 2.0 Host                                  │
│   ├── Ethernet: 1x 10/100 Mbps                              │
│   └── Power: 5V 2.5A via USB-C                              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Older Models Reference

| Model | CPU | RAM | WiFi | Notes |
|-------|-----|-----|------|-------|
| Mark V | Atheros AR9331 | 64 MB | 1x b/g/n | Legacy |
| Nano | AR9331 | 64 MB | 1x b/g/n | Compact |
| Tetra | AR9344/AR9580 | 64 MB | 2x | Dual-band |
| Mark VII | MT7621AT | 256 MB | 2x ac | Current |

---

## Interface Details

### Wireless Interfaces

```bash
# List wireless interfaces
iw dev

# Example output:
# phy#0
#     Interface wlan0
#         type managed
#         channel 6 (2437 MHz)
# phy#1
#     Interface wlan1
#         type managed
#         channel 36 (5180 MHz)
```

#### wlan0 - Management Interface
- **Purpose**: Web interface access, client mode
- **Default IP**: 172.16.42.1
- **Use**: Don't use for attacks

#### wlan1 - Attack Interface
- **Purpose**: PineAP, monitor mode, injection
- **Modes**: Managed, Monitor, AP
- **Use**: Primary attack interface

#### wlan2+ - USB Adapters
- **Purpose**: Extended capabilities
- **Recommended**: RTL8812AU, AR9271
- **Use**: Long-range, specific attacks

### Ethernet Interface

```bash
# Check ethernet status
ip link show eth0
ethtool eth0
```

- **Use Cases**: Internet sharing, wired attacks
- **Speed**: 10/100 Mbps
- **Configuration**: DHCP or static

### USB Port

```bash
# List USB devices
lsusb

# Check USB storage
ls /dev/sd*
```

- **Supports**: USB adapters, storage, 4G modems
- **Power**: 500mA max per port

---

## LED Indicators

```
┌─────────────────────────────────────────────────────────────┐
│                    LED MEANINGS                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   POWER LED (●):                                            │
│   ├── Solid Blue: System running                            │
│   ├── Blinking Blue: Booting                                │
│   ├── Solid Red: Error/Recovery                             │
│   └── Off: No power                                         │
│                                                              │
│   ETHERNET LED (●):                                         │
│   ├── Solid: Link established                               │
│   ├── Blinking: Traffic                                     │
│   └── Off: No connection                                    │
│                                                              │
│   WLAN LED (●):                                             │
│   ├── Solid: Radio active                                   │
│   ├── Blinking: Traffic/Activity                            │
│   └── Off: Radio disabled                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Controlling LEDs via Script

```bash
# LED paths
LED_BLUE="/sys/class/leds/pineapple:blue:system/brightness"
LED_RED="/sys/class/leds/pineapple:red:system/brightness"

# Turn on
echo 1 > $LED_BLUE

# Turn off
echo 0 > $LED_BLUE

# Blink
while true; do
    echo 1 > $LED_BLUE
    sleep 0.5
    echo 0 > $LED_BLUE
    sleep 0.5
done
```

---

## Storage

### Internal Storage (EMMC)

```bash
# Check internal storage
df -h /

# Typical layout
/           - Root filesystem (~2GB)
/overlay    - Writable overlay
```

### SD Card

```bash
# Mount SD card (usually auto-mounted)
mount /dev/mmcblk0p1 /sd

# Check SD card
df -h /sd

# Format SD card (if needed)
mkfs.ext4 /dev/mmcblk0p1
```

#### Recommended SD Card Usage
```
/sd/
├── loot/           # Captured data
│   ├── handshakes/
│   ├── captures/
│   └── credentials/
├── payloads/       # Additional payloads
├── wordlists/      # Cracking dictionaries
└── modules/        # Extra modules
```

---

## Power Requirements

### Power Sources

| Source | Voltage | Current | Notes |
|--------|---------|---------|-------|
| USB-C Adapter | 5V | 2.5A | Recommended |
| USB Battery | 5V | 2A+ | Portable |
| USB Port | 5V | 0.5A | Insufficient! |

### Power Consumption

| Mode | Current Draw |
|------|--------------|
| Idle | ~400mA |
| Scanning | ~600mA |
| Evil Twin | ~800mA |
| Full Attack | ~1200mA |

### Battery Runtime Estimates

```bash
# Calculate runtime
# Runtime (hours) = Battery (mAh) / Current (mA)

# Example: 10000mAh battery
# Idle: 10000/400 = 25 hours
# Active: 10000/800 = 12.5 hours
```

---

## Recommended Accessories

### External WiFi Adapters

| Adapter | Chipset | Monitor | Injection | Notes |
|---------|---------|---------|-----------|-------|
| Alfa AWUS036ACH | RTL8812AU | ✓ | ✓ | Dual-band, long range |
| Alfa AWUS036NHA | AR9271 | ✓ | ✓ | Best 2.4GHz injection |
| Panda PAU09 | RT5572 | ✓ | ✓ | Dual-band budget |
| TP-Link TL-WN722N v1 | AR9271 | ✓ | ✓ | Budget friendly |

### Antennas

```
┌─────────────────────────────────────────────────────────────┐
│                    ANTENNA TYPES                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   OMNIDIRECTIONAL (Stock):                                  │
│   ├── Range: ~100m                                          │
│   ├── Pattern: 360° coverage                                │
│   └── Use: General purpose                                  │
│                                                              │
│   YAGI (Directional):                                       │
│   ├── Range: 500m+                                          │
│   ├── Pattern: Focused beam                                 │
│   └── Use: Long-range, targeting                            │
│                                                              │
│   PANEL (Directional):                                      │
│   ├── Range: 300m+                                          │
│   ├── Pattern: Wide focused                                 │
│   └── Use: Building coverage                                │
│                                                              │
│   PARABOLIC (High-gain):                                    │
│   ├── Range: 1km+                                           │
│   ├── Pattern: Very focused                                 │
│   └── Use: Extreme range                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Hardware Troubleshooting

### Common Issues

| Issue | Possible Cause | Solution |
|-------|----------------|----------|
| Won't boot | Insufficient power | Use 2.5A+ adapter |
| No WiFi | Driver issue | Reinstall firmware |
| SD not detected | Formatting | Use ext4 filesystem |
| USB not working | Power limit | Use powered hub |
| Overheating | High load | Add heatsink/airflow |

### Recovery Mode

```bash
# Enter recovery:
# 1. Power off
# 2. Hold reset button
# 3. Power on
# 4. Hold 10 seconds
# 5. Release when LED blinks

# Connect via:
ssh root@192.168.1.1
```

---

[← Back to Fundamentals](README.md) | [Next: Software Architecture →](02_Software_Architecture.md)
