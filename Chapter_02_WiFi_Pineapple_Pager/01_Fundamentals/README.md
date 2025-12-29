# Chapter 2.1: WiFi Pineapple Pager Fundamentals

## What is the WiFi Pineapple Pager?

The WiFi Pineapple Pager is a compact, portable wireless auditing platform designed for security professionals. Unlike the Flipper Zero (which uses keyboard injection), the Pager directly interacts with wireless networks.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   FLIPPER ZERO vs WIFI PINEAPPLE PAGER                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FLIPPER ZERO                           WIFI PINEAPPLE PAGER                │
│  ────────────                           ────────────────────                │
│                                                                              │
│  ┌─────────┐                            ┌─────────┐                         │
│  │   FZ    │──USB──▶ [Computer]         │  Pager  │~~WiFi~~▶ [Networks]     │
│  └─────────┘                            └─────────┘                         │
│       │                                      │                               │
│       ▼                                      ▼                               │
│  Types commands                         Captures packets                     │
│  as keyboard                            Creates rogue APs                    │
│                                         Deauths clients                      │
│                                                                              │
│  Attack Vector: Physical USB             Attack Vector: Wireless             │
│  Language: DuckyScript                   Language: Bash                      │
│  Target: Single computer                 Target: WiFi networks               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The Four Core Suites

The WiFi Pineapple operates through **four integrated suites** that work together for wireless security testing:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WIFI PINEAPPLE CORE SUITES                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│   │    ALERT    │    │  PAYLOADS   │    │    RECON    │    │   PINEAP    │ │
│   │   SUITE     │    │   SUITE     │    │   SUITE     │    │   SUITE     │ │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘ │
│          │                  │                  │                  │        │
│          ▼                  ▼                  ▼                  ▼        │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│   │ Notifications│    │ Automated   │    │ Network     │    │ Evil Twin   │ │
│   │ LED Alerts   │    │ Scripts     │    │ Scanning    │    │ KARMA       │ │
│   │ Remote Push  │    │ Boot/Button │    │ Client Find │    │ Beacon Resp │ │
│   │ Logging      │    │ Scheduling  │    │ Probe Harv. │    │ Filtering   │ │
│   └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Suite Breakdown

| Suite | Purpose | Key Features |
|-------|---------|--------------|
| **[Alert](09_Alert_Suite.md)** | Notifications & Monitoring | LED patterns, Pushover, Email, Webhook, SMS, event triggers |
| **[Payloads](10_Payloads_Suite.md)** | Automated Execution | Boot payloads, button triggers, scheduled tasks, payload library |
| **[Recon](11_Recon_Suite.md)** | Reconnaissance | Passive/active scanning, client discovery, probe harvesting |
| **[PineAP](05_PineAP_Module.md)** | Rogue AP Framework | Evil Twin, KARMA attacks, beacon response, client manipulation |

### How the Suites Work Together

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TYPICAL ATTACK WORKFLOW                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. RECON identifies targets                                                │
│      └─▶ Scans for networks, discovers clients, harvests probes             │
│                                                                              │
│   2. PINEAP launches attack                                                  │
│      └─▶ Creates Evil Twin, enables KARMA, captures victims                 │
│                                                                              │
│   3. ALERT notifies operator                                                 │
│      └─▶ LED blinks, push notification when client connects                 │
│                                                                              │
│   4. PAYLOADS automate everything                                            │
│      └─▶ Boot payload runs full chain automatically                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Hardware Overview

### Specifications

| Component | Specification |
|-----------|---------------|
| **Processor** | MediaTek MT7628 (580MHz MIPS) |
| **RAM** | 128MB DDR2 |
| **Storage** | 16MB NOR Flash + MicroSD |
| **WiFi** | 2.4GHz 802.11b/g/n |
| **Antennas** | 2x Internal |
| **Battery** | Internal Li-Po (~4-6 hours) |
| **Interface** | USB-C (charging + serial) |
| **Display** | Small OLED or LED indicators |

### Key Features

1. **Portable Form Factor**: Fits in pocket, battery-powered
2. **Passive Reconnaissance**: Scan networks without connecting
3. **Active Attacks**: Deauth, Evil Twin, handshake capture
4. **Alert System**: Notifications via LED, vibration, or remote
5. **Payload System**: Custom Bash scripts for automation

---

## Understanding Wireless Attacks

### The WiFi Attack Surface

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        WIFI ATTACK CATEGORIES                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  RECONNAISSANCE                  DISRUPTION                                 │
│  ──────────────                  ──────────                                 │
│  • Network scanning              • Deauthentication                          │
│  • Client enumeration            • Channel jamming                           │
│  • Probe request capture         • Beacon flooding                           │
│  • Signal mapping                • Resource exhaustion                       │
│                                                                              │
│  CREDENTIAL CAPTURE              IMPERSONATION                              │
│  ──────────────────              ────────────                               │
│  • WPA handshake capture         • Evil Twin AP                              │
│  • PMKID extraction              • Captive portal                            │
│  • EAP credential harvest        • SSL stripping (historical)                │
│  • Probe request analysis        • DNS spoofing                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The Payload System

### What are Payloads?

On the WiFi Pineapple Pager, **payloads are Bash scripts** that automate wireless attacks and reconnaissance.

### Payload Types

| Type | Trigger | Description |
|------|---------|-------------|
| **User Payload** | Manual | Run by pressing button or command |
| **Alert Payload** | Event | Run when something happens (handshake captured, client connected) |
| **Background Payload** | Automatic | Run continuously in background |

### Payload Locations

```
/root/payloads/          # User payloads
/root/payloads/alerts/   # Alert payloads
/root/loot/              # Captured data
```

---

## Bash Scripting for WiFi Pineapple

### Why Bash?

The WiFi Pineapple runs **OpenWrt Linux**, so payloads are written in Bash. This gives you full Linux power:
- File manipulation
- Network tools (aircrack-ng, tcpdump)
- Process control
- Conditional logic

### Basic Bash Structure

```bash
#!/bin/bash
# Payload: Example Script
# Description: Template for Pager payloads

# Configuration
INTERFACE="wlan0"
LOOT_DIR="/root/loot"
LOG_FILE="$LOOT_DIR/example.log"

# Create directories if needed
mkdir -p "$LOOT_DIR"

# Main logic here
echo "Payload started at $(date)" >> "$LOG_FILE"

# Your code...

# Notify completion
NOTIFY "Payload complete"
```

---

## Core Commands

### Pager-Specific Commands

```bash
# Send notification to user
NOTIFY "Message to display"

# Play alert sound
NOTIFY_SOUND

# Set LED color
LED RED      # Alert state
LED GREEN    # Success state
LED BLUE     # Processing state

# Vibrate (if supported)
NOTIFY_VIBRATE
```

### Wireless Commands

```bash
# Enable monitor mode
airmon-ng start wlan0

# Scan for networks
airodump-ng wlan0mon

# Capture handshakes
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Send deauth packets
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Create rogue AP
hostapd /path/to/config.conf
```

---

## Your First Pager Payload

### Goal: Simple Network Scanner

This payload scans for nearby WiFi networks and saves the results.

```bash
#!/bin/bash
#####################################################
# Payload: PP-B01 - Simple Network Scan
# Target: All nearby 2.4GHz networks
# Description: Basic WiFi reconnaissance
#####################################################

# ===== CONFIGURATION =====
INTERFACE="wlan0"
SCAN_TIME=10
LOOT_DIR="/root/loot/scans"
OUTPUT_FILE="$LOOT_DIR/scan_$(date +%Y%m%d_%H%M%S).txt"

# ===== SETUP =====
# Create loot directory
mkdir -p "$LOOT_DIR"

# Notify start
NOTIFY "Starting network scan..."
LED BLUE

# ===== MAIN LOGIC =====
# Put interface in monitor mode
airmon-ng start "$INTERFACE" > /dev/null 2>&1
MONITOR_IF="${INTERFACE}mon"

# Run scan for specified time
timeout "$SCAN_TIME" airodump-ng "$MONITOR_IF" -w /tmp/scan --output-format csv > /dev/null 2>&1

# ===== PROCESS RESULTS =====
# Parse the CSV output
if [ -f /tmp/scan-01.csv ]; then
    # Extract network info (BSSID, Channel, ESSID)
    grep -E "^([0-9A-F]{2}:){5}[0-9A-F]{2}" /tmp/scan-01.csv | \
    cut -d',' -f1,4,14 | \
    sed 's/,/ | /g' > "$OUTPUT_FILE"

    # Count networks found
    NETWORK_COUNT=$(wc -l < "$OUTPUT_FILE")

    # Notify completion
    LED GREEN
    NOTIFY "Scan complete: $NETWORK_COUNT networks found"
else
    LED RED
    NOTIFY "Scan failed - no data captured"
fi

# ===== CLEANUP =====
# Disable monitor mode
airmon-ng stop "$MONITOR_IF" > /dev/null 2>&1

# Remove temp files
rm -f /tmp/scan-01.csv

# Return to normal
LED OFF
```

### Line-by-Line Breakdown

| Section | Lines | Purpose |
|---------|-------|---------|
| Header | 1-5 | Documentation |
| Configuration | 7-11 | Variables for easy modification |
| Setup | 13-18 | Prepare environment |
| Main Logic | 20-26 | Perform the scan |
| Process Results | 28-42 | Parse and save data |
| Cleanup | 44-50 | Reset device state |

---

## Side-by-Side: DuckyScript vs Bash

Both achieve network reconnaissance, but differently:

```
┌──────────────────────────────────┬──────────────────────────────────┐
│      DUCKYSCRIPT (Flipper)       │         BASH (Pager)             │
├──────────────────────────────────┼──────────────────────────────────┤
│                                  │                                  │
│ REM Get WiFi info on Windows     │ # Get WiFi info directly         │
│                                  │                                  │
│ DELAY 2000                       │ # No delay needed - direct       │
│ GUI r                            │                                  │
│ DELAY 500                        │                                  │
│ STRING cmd /k netsh wlan show    │ airodump-ng wlan0mon             │
│ STRING  networks                 │                                  │
│ ENTER                            │ # Results captured directly      │
│                                  │                                  │
│ # Types command into Windows     │ # Runs command on Pager          │
│ # Gets info FROM target PC       │ # Scans networks FROM the air    │
│                                  │                                  │
└──────────────────────────────────┴──────────────────────────────────┘
```

**Key difference**:
- DuckyScript queries the **target computer's** WiFi settings
- Bash (Pager) scans **WiFi signals in the air** directly

---

## Red Team Perspective

### Why Use WiFi Pineapple Pager?

| Scenario | Capability |
|----------|------------|
| External Assessment | Scan corporate networks from parking lot |
| Physical Pentest | Deploy near target during site visit |
| Wireless Audit | Capture handshakes for password testing |
| Social Engineering | Create convincing fake network |
| Red Team Op | Persistent wireless foothold |

### Common Attack Chains

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WIFI PINEAPPLE ATTACK FLOW                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. RECON              2. TARGET            3. CAPTURE                       │
│  ──────                ──────               ───────                          │
│  Scan all networks     Select target AP     Capture handshake                │
│  Identify clients      Note channel         Send deauth                      │
│  Note security type    Identify clients     Wait for reconnect               │
│       │                     │                    │                           │
│       └──────────┬──────────┘                    │                           │
│                  ▼                               ▼                           │
│            4. CRACK                        5. ACCESS                         │
│            ─────                           ──────                            │
│            Offline attack                  Connect to network                │
│            Dictionary/brute                Pivot to internal                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Blue Team Perspective

### Detecting Rogue Devices

Signs of a WiFi Pineapple or similar device:

1. **New Unknown APs**: Especially matching legitimate SSIDs
2. **Deauth Storms**: Many deauthentication packets
3. **MAC Anomalies**: Same BSSID appearing on different channels
4. **Probe Response Floods**: Responding to all probe requests
5. **Signal Anomalies**: Familiar SSID from unusual location

### Wireless IDS Indicators

```bash
# Signs in wireless logs
# 1. Unusual MAC address patterns
# 2. Multiple APs with same SSID
# 3. Deauth packets from unknown sources
# 4. Probe responses to rare SSIDs
```

### Detection Script

```bash
#!/bin/bash
# Basic rogue AP detection

# Known legitimate APs (add your own)
KNOWN_APS=("AA:BB:CC:DD:EE:FF" "11:22:33:44:55:66")

# Scan for APs
airodump-ng wlan0mon -w /tmp/check --output-format csv &
sleep 30
kill %1

# Check for unknown APs with company SSID
while IFS=',' read -r bssid _ _ _ _ _ _ _ _ _ _ _ _ essid _; do
    if [[ "$essid" == *"CompanyWiFi"* ]]; then
        is_known=false
        for known in "${KNOWN_APS[@]}"; do
            if [[ "$bssid" == "$known" ]]; then
                is_known=true
                break
            fi
        done
        if ! $is_known; then
            echo "ALERT: Unknown AP with company SSID: $bssid"
        fi
    fi
done < /tmp/check-01.csv
```

---

## Practice Exercises

### Exercise 1: Simple Scan
Write a payload that:
1. Scans for 15 seconds
2. Counts networks found
3. Notifies with LED (green = found networks, red = none)

### Exercise 2: Target Specific Channel
Modify the scan payload to:
1. Only scan channel 6
2. Save more detailed output
3. Include timestamps

### Exercise 3: Alert Payload
Create an alert payload that triggers when:
1. A specific SSID is seen
2. Logs the timestamp and signal strength
3. Sends a notification

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BASH QUICK REFERENCE FOR PAGER                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  VARIABLES                         FILE OPERATIONS                          │
│  ─────────                         ───────────────                          │
│  VAR="value"                       mkdir -p /path                           │
│  echo "$VAR"                       cat file.txt                             │
│  export VAR                        echo "text" > file                       │
│                                    echo "text" >> file                      │
│                                                                              │
│  CONTROL FLOW                      WIRELESS                                 │
│  ────────────                      ────────                                 │
│  if [ condition ]; then            airmon-ng start wlan0                    │
│    commands                        airodump-ng wlan0mon                     │
│  fi                                aireplay-ng -0 5 -a BSSID iface          │
│                                                                              │
│  for i in list; do                 PAGER SPECIFIC                           │
│    commands                        ──────────────                           │
│  done                              NOTIFY "message"                         │
│                                    LED RED|GREEN|BLUE|OFF                   │
│  while [ condition ]; do                                                    │
│    commands                                                                 │
│  done                                                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Fundamentals Documentation Index

### Core Suites (Primary)
| # | Document | Description |
|---|----------|-------------|
| 05 | **[PineAP Module](05_PineAP_Module.md)** | Rogue AP framework - Evil Twin, KARMA, beacon response |
| 09 | **[Alert Suite](09_Alert_Suite.md)** | Notifications - LED, push, email, webhook, SMS |
| 10 | **[Payloads Suite](10_Payloads_Suite.md)** | Automation - boot, button, scheduled payloads |
| 11 | **[Recon Suite](11_Recon_Suite.md)** | Reconnaissance - scanning, discovery, harvesting |

### Supporting Documentation
| # | Document | Description |
|---|----------|-------------|
| 01 | **[Hardware Overview](01_Hardware_Overview.md)** | Device specifications, interfaces, LEDs |
| 02 | **[Software Architecture](02_Software_Architecture.md)** | OpenWrt, filesystem, services |
| 03 | **[Aircrack-ng Suite](03_Aircrack_Suite.md)** | Wireless attack toolkit |
| 04 | **[Network Tools](04_Network_Tools.md)** | tcpdump, iptables, hostapd, dnsmasq, nmap |
| 06 | **[Bash Scripting](06_Bash_Scripting.md)** | Payload development guide |
| 07 | **[API Reference](07_API_Reference.md)** | REST API for automation |
| 08 | **[Module Development](08_Module_Development.md)** | Creating custom modules |

---

## Next Steps

Now that you understand the fundamentals:

### Learn the Core Suites
1. **[Alert Suite](09_Alert_Suite.md)** - Set up notifications and monitoring
2. **[Payloads Suite](10_Payloads_Suite.md)** - Create automated attack scripts
3. **[Recon Suite](11_Recon_Suite.md)** - Master wireless reconnaissance
4. **[PineAP Module](05_PineAP_Module.md)** - Deploy rogue AP attacks

### Build Your First Payloads
1. **[PP-B01: Hello World](../02_Basic_Payloads/PP-B01_Hello_World.md)** - Your first complete payload
2. **[PP-B04: Basic Scan](../02_Basic_Payloads/PP-B04_Basic_Scan.md)** - Simple network scanning
3. **[PP-I01: Evil Twin](../03_Intermediate_Payloads/PP-I01_Evil_Twin.md)** - Rogue access point

### Deepen Your Skills
1. **[Bash Scripting Guide](06_Bash_Scripting.md)** - Payload development techniques
2. **[Aircrack-ng Suite](03_Aircrack_Suite.md)** - Wireless attack tools
3. **[API Reference](07_API_Reference.md)** - Automation via REST API

---

[← Back to Chapter 2](../README.md) | [Next: Hardware Overview →](01_Hardware_Overview.md)
