# Firmware Ecosystem

## Flipper Zero Firmware

### Official Firmware
| Version | Release | Notes |
|---------|---------|-------|
| 0.x.x | Ongoing | Official releases from Flipper Devices |

#### Update Methods
```bash
# Via qFlipper desktop app (recommended)
# Download: https://flipperzero.one/update

# Via SD card
1. Download firmware .dfu file
2. Copy to SD card root
3. Navigate: Settings → About → Firmware Update

# Via CLI
flipper_cli update /path/to/firmware.dfu
```

### Custom Firmware Options

#### Unleashed Firmware
```
Features:
├── Unlocked frequency ranges
├── Additional protocols
├── Extended Sub-GHz capabilities
├── Rolling code support
└── Extra plugins

Repository: github.com/DarkFlippers/unleashed-firmware
```

#### RogueMaster Firmware
```
Features:
├── All Unleashed features
├── Additional apps
├── UI customizations
├── Game collection
└── Frequent updates

Repository: github.com/RogueMaster/flipperzero-firmware-wPlugins
```

#### Xtreme Firmware
```
Features:
├── Animation pack
├── Extended settings
├── Protocol enhancements
├── Custom themes
└── Plugin collection
```

### Firmware Comparison

| Feature | Official | Unleashed | RogueMaster |
|---------|----------|-----------|-------------|
| Sub-GHz | Limited | Extended | Extended |
| BadUSB | Yes | Enhanced | Enhanced |
| Plugins | Basic | Many | Most |
| Updates | Stable | Frequent | Very Frequent |
| Support | Official | Community | Community |
| Risk | Low | Medium | Medium |

---

## WiFi Pineapple Firmware

### OpenWrt Base
```
WiFi Pineapple runs modified OpenWrt:
├── Custom kernel modules
├── PineAP daemon
├── Web interface
├── Module system
└── API endpoints
```

### Firmware Update
```bash
# Via web interface
1. Navigate to: Management → Firmware
2. Upload .bin file
3. Wait for reboot

# Via command line
sysupgrade -n /tmp/firmware.bin

# Recovery mode
1. Hold reset during boot
2. Access recovery web UI
3. Upload firmware
```

### Version History
| Model | Current | Base |
|-------|---------|------|
| Mark VII | 2.x.x | OpenWrt 21.x |
| Tetra | 2.x.x | OpenWrt 19.x |
| Nano | 2.x.x | OpenWrt 18.x |

---

## USB Rubber Ducky Firmware

### Official Firmware
```
Payload Storage:
├── MicroSD card (FAT32)
├── inject.bin (compiled payload)
└── config.txt (optional settings)

Compile Payloads:
# Using duck encoder
java -jar duckencoder.jar -i payload.txt -o inject.bin
```

### Alternative Firmware
```
O.MG Cable Firmware:
├── Advanced features
├── WiFi connectivity
├── Exfiltration support
└── Custom payloads
```

---

## Firmware Security

### Flipper Zero
```
Security Features:
├── Signed firmware updates
├── Secure boot (partial)
├── OTA update verification
└── Factory reset option

Risks:
├── Custom firmware = no signature
├── Malicious plugins possible
├── Backdoored firmware risk
└── Always verify sources
```

### WiFi Pineapple
```
Security Features:
├── SSH key authentication
├── Web UI password
├── Firmware verification
└── Recovery mode

Risks:
├── Default credentials
├── Unencrypted storage
├── Network exposure
└── Module security
```

### Best Practices
```
1. Verify firmware sources
2. Check signatures/hashes
3. Keep firmware updated
4. Backup before updating
5. Test in lab environment
6. Use strong credentials
7. Limit network exposure
8. Monitor for anomalies
```

---

## Building Custom Firmware

### Flipper Zero SDK
```bash
# Clone repository
git clone https://github.com/flipperdevices/flipperzero-firmware
cd flipperzero-firmware

# Setup toolchain
./fbt

# Build firmware
./fbt COMPACT=1 DEBUG=0 updater_package

# Build specific app
./fbt fap_appname
```

### WiFi Pineapple SDK
```bash
# OpenWrt build system
git clone https://github.com/openwrt/openwrt
cd openwrt

# Select target
make menuconfig

# Build
make -j$(nproc)
```

---

## Firmware Backup

### Flipper Zero Backup
```bash
# Via qFlipper
# Click backup button in qFlipper app

# Via SD card
# Copy entire SD card contents

# Key directories:
/ext/
├── apps/
├── infrared/
├── nfc/
├── subghz/
├── badusb/
└── settings/
```

### WiFi Pineapple Backup
```bash
# Full system backup
tar -czvf /sd/backup_$(date +%Y%m%d).tar.gz \
    /etc/config \
    /etc/pineapple \
    /root/payloads \
    /sd/loot

# Configuration only
uci export > /sd/uci_backup.conf
```

---

[← Hardware Deep Dive](../01_Hardware_Deep_Dive/) | [Back to Technical Addendum](../README.md) | [Next: Protocol Reference →](../03_Protocol_Reference/)
