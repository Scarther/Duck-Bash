# PP-B08: Interface Status

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B08 |
| **Name** | Interface Status |
| **Difficulty** | Basic |
| **Type** | Info |
| **Purpose** | Check wireless interface status |

## What This Payload Does

Provides detailed information about all wireless interfaces including mode, channel, capabilities, and driver details. Essential for verifying your setup before running operations.

---

## Understanding WiFi Interfaces

```
┌─────────────────────────────────────────────────────────────┐
│              PINEAPPLE INTERFACE LAYOUT                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   TYPICAL CONFIGURATION:                                    │
│                                                              │
│   wlan0 (Built-in)                 wlan1 (Built-in/USB)     │
│   ├── Mode: Master (AP)            ├── Mode: Monitor        │
│   ├── Purpose: Management          ├── Purpose: Attacks     │
│   ├── Channel: Fixed               ├── Channel: Hopping     │
│   └── SSID: "Pineapple_XXXX"       └── SSID: N/A           │
│                                                              │
│   wlan2+ (USB Adapter)                                      │
│   ├── Mode: Various                                         │
│   ├── Purpose: Extended range                               │
│   └── Capabilities: Depends on chipset                      │
│                                                              │
│   OPERATING MODES:                                          │
│   ─────────────────                                         │
│   • Managed    - Normal client mode                         │
│   • Master     - Access Point mode                          │
│   • Monitor    - Passive capture mode                       │
│   • Ad-Hoc     - Peer-to-peer mode                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B08
# Name: Interface Status
# Description: Comprehensive wireless interface information
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
LOG_FILE="/tmp/pp-b08.log"
OUTPUT_FILE="/tmp/interface_status.txt"

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

section() {
    echo "" | tee -a "$OUTPUT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
    echo " $1" | tee -a "$OUTPUT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$OUTPUT_FILE"
}

# ============================================
# MAIN
# ============================================
log "Starting PP-B08: Interface Status"

# Clear output
> "$OUTPUT_FILE"

{
    echo "╔════════════════════════════════════════════════════╗"
    echo "║        WIRELESS INTERFACE STATUS                   ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
} | tee -a "$OUTPUT_FILE"

# ============================================
# LIST ALL INTERFACES
# ============================================
section "INTERFACE SUMMARY"

# Get list of wireless interfaces
WLAN_INTERFACES=$(ls /sys/class/net | grep -E "^wlan|^mon|^ath")

if [ -z "$WLAN_INTERFACES" ]; then
    echo "No wireless interfaces found!" | tee -a "$OUTPUT_FILE"
    exit 1
fi

{
    printf "%-12s %-10s %-18s %-8s %-10s\n" "Interface" "State" "MAC Address" "Channel" "Mode"
    echo "─────────────────────────────────────────────────────────────────────"
} | tee -a "$OUTPUT_FILE"

for iface in $WLAN_INTERFACES; do
    # Get state
    STATE=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")

    # Get MAC
    MAC=$(cat /sys/class/net/$iface/address 2>/dev/null || echo "unknown")

    # Get channel
    CHANNEL=$(iw dev $iface info 2>/dev/null | grep channel | awk '{print $2}')
    [ -z "$CHANNEL" ] && CHANNEL="-"

    # Get mode
    MODE=$(iw dev $iface info 2>/dev/null | grep type | awk '{print $2}')
    [ -z "$MODE" ] && MODE=$(iwconfig $iface 2>/dev/null | grep Mode | awk -F'Mode:' '{print $2}' | awk '{print $1}')
    [ -z "$MODE" ] && MODE="unknown"

    printf "%-12s %-10s %-18s %-8s %-10s\n" "$iface" "$STATE" "$MAC" "$CHANNEL" "$MODE"
done | tee -a "$OUTPUT_FILE"

# ============================================
# DETAILED INTERFACE INFO
# ============================================
for iface in $WLAN_INTERFACES; do
    section "INTERFACE: $iface"

    {
        echo "--- Basic Info ---"
        echo "State:       $(cat /sys/class/net/$iface/operstate 2>/dev/null)"
        echo "MAC:         $(cat /sys/class/net/$iface/address 2>/dev/null)"
        echo "MTU:         $(cat /sys/class/net/$iface/mtu 2>/dev/null)"
        echo "TX Queue:    $(cat /sys/class/net/$iface/tx_queue_len 2>/dev/null)"

        echo ""
        echo "--- iw dev info ---"
        iw dev $iface info 2>/dev/null

        echo ""
        echo "--- iwconfig ---"
        iwconfig $iface 2>/dev/null

        echo ""
        echo "--- IP Address ---"
        ip addr show $iface 2>/dev/null | grep -E "inet|link"

        # Get driver info
        DRIVER_PATH="/sys/class/net/$iface/device/driver"
        if [ -L "$DRIVER_PATH" ]; then
            DRIVER=$(basename $(readlink "$DRIVER_PATH"))
            echo ""
            echo "--- Driver ---"
            echo "Driver:      $DRIVER"
        fi

        # Get device info
        if [ -f "/sys/class/net/$iface/device/uevent" ]; then
            echo ""
            echo "--- Device ---"
            grep -E "DRIVER|PCI_ID|USB" /sys/class/net/$iface/device/uevent 2>/dev/null
        fi
    } | tee -a "$OUTPUT_FILE"
done

# ============================================
# WIRELESS CAPABILITIES
# ============================================
section "WIRELESS CAPABILITIES"

{
    echo "--- Supported Modes ---"
    iw list 2>/dev/null | grep -A 10 "Supported interface modes:" | head -12

    echo ""
    echo "--- Supported Bands ---"
    iw list 2>/dev/null | grep -E "Band|Frequencies:" | head -10

    echo ""
    echo "--- TX Power Levels ---"
    iwconfig 2>/dev/null | grep -i "tx-power"
} | tee -a "$OUTPUT_FILE"

# ============================================
# MONITOR MODE CAPABILITY
# ============================================
section "MONITOR MODE CHECK"

{
    MONITOR_CAPABLE=false

    for iface in $WLAN_INTERFACES; do
        PHY=$(iw dev $iface info 2>/dev/null | grep wiphy | awk '{print "phy"$2}')

        if [ -n "$PHY" ]; then
            if iw phy $PHY info 2>/dev/null | grep -q "monitor"; then
                echo "✓ $iface ($PHY): Monitor mode SUPPORTED"
                MONITOR_CAPABLE=true
            else
                echo "✗ $iface ($PHY): Monitor mode NOT supported"
            fi
        fi
    done

    if [ "$MONITOR_CAPABLE" = false ]; then
        echo ""
        echo "WARNING: No interfaces support monitor mode!"
        echo "Consider adding a compatible USB adapter."
    fi
} | tee -a "$OUTPUT_FILE"

# ============================================
# INJECTION CAPABILITY
# ============================================
section "INJECTION CAPABILITY"

{
    for iface in $WLAN_INTERFACES; do
        # Check if interface supports injection (has AP mode usually means injection)
        PHY=$(iw dev $iface info 2>/dev/null | grep wiphy | awk '{print "phy"$2}')

        if [ -n "$PHY" ]; then
            MODES=$(iw phy $PHY info 2>/dev/null | grep -A 20 "Supported interface modes:" | grep -E "^\s+\*")

            if echo "$MODES" | grep -qE "AP|monitor"; then
                echo "✓ $iface: Injection likely SUPPORTED"
            else
                echo "? $iface: Injection capability UNKNOWN"
            fi
        fi
    done

    echo ""
    echo "Note: Use aireplay-ng --test to verify injection"
} | tee -a "$OUTPUT_FILE"

# ============================================
# CURRENT CONNECTIONS
# ============================================
section "CURRENT CONNECTIONS"

{
    echo "--- Connected Clients (if AP mode) ---"

    for iface in $WLAN_INTERFACES; do
        if iw dev $iface info 2>/dev/null | grep -q "type AP"; then
            echo "[$iface] AP Mode - Checking clients..."
            iw dev $iface station dump 2>/dev/null | grep -E "Station|signal|tx bytes|rx bytes" || echo "  No clients connected"
        fi
    done

    echo ""
    echo "--- Associated AP (if client mode) ---"

    for iface in $WLAN_INTERFACES; do
        if iw dev $iface info 2>/dev/null | grep -q "type managed"; then
            echo "[$iface] Client Mode"
            iw dev $iface link 2>/dev/null
        fi
    done
} | tee -a "$OUTPUT_FILE"

# ============================================
# RECOMMENDED USB ADAPTERS
# ============================================
section "RECOMMENDED ADAPTERS"

{
    echo "For best results, use adapters with these chipsets:"
    echo ""
    echo "  Chipset          | Monitor | Injection | Driver"
    echo "  ─────────────────┼─────────┼───────────┼─────────"
    echo "  Atheros AR9271   | ✓       | ✓         | ath9k_htc"
    echo "  Ralink RT3070    | ✓       | ✓         | rt2800usb"
    echo "  Realtek RTL8812AU| ✓       | ✓         | rtl8812au"
    echo "  Realtek RTL8187  | ✓       | ✓         | rtl8187"
    echo "  MediaTek MT7612U | ✓       | ✓         | mt76x2u"
    echo ""
    echo "Popular adapters:"
    echo "  • Alfa AWUS036ACH (RTL8812AU)"
    echo "  • Alfa AWUS036NHA (AR9271)"
    echo "  • TP-Link TL-WN722N v1 (AR9271)"
    echo "  • Panda PAU09 (RT5572)"
} | tee -a "$OUTPUT_FILE"

# ============================================
# OUTPUT
# ============================================
echo ""
log "Interface status report saved to: $OUTPUT_FILE"
exit 0
```

---

## Understanding the Output

### Interface Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Managed** | Normal client mode | Connecting to networks |
| **Master** | Access Point mode | Hosting Evil Twin |
| **Monitor** | Passive capture | Packet sniffing |
| **IBSS** | Ad-hoc mode | Peer-to-peer |

### Common Drivers

| Driver | Chipset | Notes |
|--------|---------|-------|
| ath9k_htc | AR9271 | Excellent injection |
| rt2800usb | RT3070/RT5370 | Good general purpose |
| rtl8812au | RTL8812AU | 5GHz support |
| rtl8187 | RTL8187L | Legacy but reliable |
| mt76x2u | MT7612U | Modern, fast |

---

## Switching Modes

### Enable Monitor Mode
```bash
# Method 1: airmon-ng
airmon-ng start wlan1

# Method 2: iw
ip link set wlan1 down
iw dev wlan1 set type monitor
ip link set wlan1 up

# Method 3: iwconfig (legacy)
ifconfig wlan1 down
iwconfig wlan1 mode monitor
ifconfig wlan1 up
```

### Enable AP Mode
```bash
# Using hostapd
cat > /tmp/hostapd.conf << EOF
interface=wlan0
ssid=TestAP
channel=6
EOF
hostapd /tmp/hostapd.conf
```

---

## Testing Injection

```bash
# Test injection capability
aireplay-ng --test wlan1mon

# Expected output for working injection:
# Injection is working!
# Found 5 APs
# Injection test: 30/30 success
```

---

## Red Team Notes

- Always verify interface capabilities before operations
- Know which interface is for management vs attacks
- USB adapters with external antennas provide better range
- Some chipsets work better for specific attacks

## Blue Team Notes

- Monitor mode interfaces indicate potential attack preparation
- Multiple wireless interfaces on one device is suspicious
- Look for MAC address changes indicating spoofing

---

## Payload File

Save as `PP-B08_Interface_Status.sh`:

```bash
#!/bin/bash
# PP-B08: Interface Status (Compact)
echo "=== Wireless Interfaces ==="
for iface in $(ls /sys/class/net | grep wlan); do
    MODE=$(iw dev $iface info 2>/dev/null | grep type | awk '{print $2}')
    MAC=$(cat /sys/class/net/$iface/address)
    STATE=$(cat /sys/class/net/$iface/operstate)
    echo "$iface: $MODE | $MAC | $STATE"
done
```

---

[← PP-B07 Battery Check](PP-B07_Battery_Check.md) | [Back to Basic Payloads](README.md) | [Next: PP-B09 Log Viewer →](PP-B09_Log_Viewer.md)
