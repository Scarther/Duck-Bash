# PP-B06: System Status

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B06 |
| **Name** | System Status |
| **Difficulty** | Basic |
| **Type** | Info |
| **Purpose** | Display comprehensive system status |

## What This Payload Does

Provides a comprehensive overview of the WiFi Pineapple's system status including hardware resources, network configuration, running services, and operational readiness.

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B06
# Name: System Status
# Description: Comprehensive system status report
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
OUTPUT_FILE="/tmp/system_status.txt"
LOG_FILE="/tmp/pp-b06.log"

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

section() {
    echo "" >> "$OUTPUT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUTPUT_FILE"
    echo " $1" >> "$OUTPUT_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$OUTPUT_FILE"
}

# ============================================
# MAIN
# ============================================
log "Starting PP-B06: System Status"

# Clear output file
> "$OUTPUT_FILE"

# Header
{
    echo "╔════════════════════════════════════════════════════╗"
    echo "║         WiFi PINEAPPLE SYSTEM STATUS               ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
} >> "$OUTPUT_FILE"

# ============================================
# SYSTEM INFORMATION
# ============================================
section "SYSTEM INFORMATION"

{
    echo "Hostname:     $(hostname)"
    echo "Kernel:       $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Uptime:       $(uptime -p 2>/dev/null || uptime | awk -F'up ' '{print $2}' | cut -d',' -f1-2)"

    # OpenWrt version
    if [ -f /etc/openwrt_release ]; then
        echo "OpenWrt:      $(grep DISTRIB_DESCRIPTION /etc/openwrt_release | cut -d"'" -f2)"
    fi

    # Pineapple version
    if [ -f /pineapple/version ]; then
        echo "Pineapple:    $(cat /pineapple/version)"
    fi
} >> "$OUTPUT_FILE"

# ============================================
# CPU STATUS
# ============================================
section "CPU STATUS"

{
    # Load averages
    echo "Load Average: $(cat /proc/loadavg | cut -d' ' -f1-3)"

    # CPU info
    if [ -f /proc/cpuinfo ]; then
        echo "CPU Model:    $(grep 'model name\|system type' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)"
        echo "CPU MHz:      $(grep 'cpu MHz\|BogoMIPS' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)"
    fi

    # Temperature (if available)
    if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
        TEMP=$(cat /sys/class/thermal/thermal_zone0/temp)
        echo "Temperature:  $((TEMP/1000))°C"
    fi
} >> "$OUTPUT_FILE"

# ============================================
# MEMORY STATUS
# ============================================
section "MEMORY STATUS"

{
    if command -v free >/dev/null 2>&1; then
        free -h 2>/dev/null || free -m
    else
        # Fallback for minimal systems
        echo "MemTotal:     $(grep MemTotal /proc/meminfo | awk '{print $2" "$3}')"
        echo "MemFree:      $(grep MemFree /proc/meminfo | awk '{print $2" "$3}')"
        echo "MemAvailable: $(grep MemAvailable /proc/meminfo | awk '{print $2" "$3}')"
        echo "Buffers:      $(grep Buffers /proc/meminfo | awk '{print $2" "$3}')"
        echo "Cached:       $(grep "^Cached:" /proc/meminfo | awk '{print $2" "$3}')"
    fi
} >> "$OUTPUT_FILE"

# ============================================
# STORAGE STATUS
# ============================================
section "STORAGE STATUS"

{
    df -h 2>/dev/null | grep -E "^/dev|Filesystem"

    echo ""
    echo "SD Card Status:"
    if mount | grep -q "/sd"; then
        echo "  Mounted: Yes"
        df -h /sd 2>/dev/null | tail -1 | awk '{print "  Size: "$2"  Used: "$3"  Free: "$4"  Use%: "$5}'
    else
        echo "  Mounted: No (or not present)"
    fi
} >> "$OUTPUT_FILE"

# ============================================
# NETWORK INTERFACES
# ============================================
section "NETWORK INTERFACES"

{
    echo "--- IP Configuration ---"
    ip addr show 2>/dev/null | grep -E "^[0-9]|inet " | while read line; do
        if echo "$line" | grep -q "^[0-9]"; then
            iface=$(echo "$line" | awk -F': ' '{print $2}')
            echo ""
            echo "Interface: $iface"
        else
            ip=$(echo "$line" | awk '{print $2}')
            echo "  IP: $ip"
        fi
    done

    echo ""
    echo "--- Wireless Interfaces ---"
    iwconfig 2>/dev/null | grep -E "wlan|Mode|ESSID|Frequency" | while read line; do
        echo "  $line"
    done

    echo ""
    echo "--- Routing Table ---"
    ip route 2>/dev/null | head -5
} >> "$OUTPUT_FILE"

# ============================================
# WIRELESS STATUS
# ============================================
section "WIRELESS STATUS"

{
    for iface in $(ls /sys/class/net | grep wlan); do
        echo "Interface: $iface"

        # Mode
        MODE=$(iwconfig $iface 2>/dev/null | grep Mode | awk -F'Mode:' '{print $2}' | awk '{print $1}')
        echo "  Mode: ${MODE:-Unknown}"

        # MAC Address
        MAC=$(cat /sys/class/net/$iface/address 2>/dev/null)
        echo "  MAC: ${MAC:-Unknown}"

        # Status
        STATE=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
        echo "  State: ${STATE:-Unknown}"

        # Connected SSID (if applicable)
        SSID=$(iwconfig $iface 2>/dev/null | grep ESSID | awk -F'"' '{print $2}')
        [ -n "$SSID" ] && echo "  SSID: $SSID"

        echo ""
    done
} >> "$OUTPUT_FILE"

# ============================================
# RUNNING SERVICES
# ============================================
section "RUNNING SERVICES"

{
    echo "--- Critical Services ---"

    # Check common services
    for service in hostapd dnsmasq sshd nginx php-fpm; do
        if pgrep -x "$service" >/dev/null 2>&1; then
            PID=$(pgrep -x "$service" | head -1)
            echo "  ✓ $service (PID: $PID)"
        else
            echo "  ✗ $service (not running)"
        fi
    done

    echo ""
    echo "--- All Running Processes ---"
    ps w 2>/dev/null | head -15 || ps aux 2>/dev/null | head -15

    echo ""
    echo "--- Listening Ports ---"
    netstat -tlnp 2>/dev/null | grep LISTEN | head -10 || \
        ss -tlnp 2>/dev/null | grep LISTEN | head -10
} >> "$OUTPUT_FILE"

# ============================================
# PINEAPPLE MODULES
# ============================================
section "PINEAPPLE MODULES"

{
    if [ -d /pineapple/modules ]; then
        echo "Installed Modules:"
        ls -1 /pineapple/modules 2>/dev/null | while read module; do
            if [ -d "/pineapple/modules/$module" ]; then
                echo "  • $module"
            fi
        done
    else
        echo "Module directory not found"
    fi
} >> "$OUTPUT_FILE"

# ============================================
# SECURITY STATUS
# ============================================
section "SECURITY STATUS"

{
    echo "--- Firewall Status ---"
    if command -v iptables >/dev/null 2>&1; then
        RULES=$(iptables -L -n 2>/dev/null | wc -l)
        echo "  iptables rules: $RULES"
    fi

    echo ""
    echo "--- SSH Configuration ---"
    if [ -f /etc/ssh/sshd_config ]; then
        echo "  Root Login: $(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')"
        echo "  Password Auth: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')"
    fi

    echo ""
    echo "--- Open Sessions ---"
    who 2>/dev/null || echo "  No active sessions"

    echo ""
    echo "--- Recent Auth Attempts ---"
    if [ -f /var/log/auth.log ]; then
        tail -5 /var/log/auth.log 2>/dev/null
    elif [ -f /var/log/messages ]; then
        grep -i "auth\|login" /var/log/messages 2>/dev/null | tail -5
    fi
} >> "$OUTPUT_FILE"

# ============================================
# OPERATIONAL READINESS
# ============================================
section "OPERATIONAL READINESS"

{
    READY=true
    echo "Pre-flight Checklist:"

    # Check monitor mode capability
    if iw list 2>/dev/null | grep -q "monitor"; then
        echo "  ✓ Monitor mode supported"
    else
        echo "  ✗ Monitor mode not supported"
        READY=false
    fi

    # Check injection capability
    if iw list 2>/dev/null | grep -q "AP\|IBSS"; then
        echo "  ✓ Packet injection capable"
    else
        echo "  ✗ Packet injection not available"
        READY=false
    fi

    # Check aircrack suite
    if command -v airodump-ng >/dev/null 2>&1; then
        echo "  ✓ Aircrack-ng installed"
    else
        echo "  ✗ Aircrack-ng not found"
        READY=false
    fi

    # Check internet connectivity
    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo "  ✓ Internet connectivity"
    else
        echo "  ✗ No internet connectivity"
    fi

    # Check SD card
    if mount | grep -q "/sd"; then
        echo "  ✓ SD card mounted"
    else
        echo "  ⚠ SD card not mounted"
    fi

    echo ""
    if [ "$READY" = true ]; then
        echo "STATUS: OPERATIONAL READY"
    else
        echo "STATUS: NOT READY - Check failed items"
    fi
} >> "$OUTPUT_FILE"

# ============================================
# OUTPUT
# ============================================
cat "$OUTPUT_FILE"

log "System status report generated: $OUTPUT_FILE"
exit 0
```

---

## Understanding the Output

### System Information
Shows basic device identification and software versions.

### CPU Status
- **Load Average**: Three numbers showing 1, 5, and 15 minute CPU load
- Values above 1.0 indicate system is busy

### Memory Status
```
              total        used        free      shared  buff/cache   available
Mem:          128M         45M         10M        512K        72M         75M
```
- **total**: Total physical RAM
- **available**: Memory available for new applications (more useful than "free")

### Storage Status
- Root filesystem typically small (16-32MB)
- SD card provides expanded storage
- Keep 10% free for operation

---

## Red Team Notes

- Run status check before deploying payloads
- Verify all required tools are present
- Check available storage for captures
- Confirm network connectivity for exfiltration

## Blue Team Notes

- Unknown devices checking system status may indicate reconnaissance
- Monitor for new SSH connections to unusual IPs
- Check for unexpected services running

---

## Payload File

Save as `PP-B06_System_Status.sh`:

```bash
#!/bin/bash
# PP-B06: System Status (Compact)
echo "=== System Status ==="
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
echo "Memory: $(free -m 2>/dev/null | awk '/Mem/{print $3"/"$2"MB"}')"
echo "Storage: $(df -h / | awk 'NR==2{print $5" used"}')"
echo "Interfaces: $(ip link show | grep -c "state UP") active"
iwconfig 2>/dev/null | grep -E "wlan|Mode"
```

---

[← PP-B05 Deauth Test](PP-B05_Deauth_Test.md) | [Back to Basic Payloads](README.md) | [Next: PP-B07 Battery Check →](PP-B07_Battery_Check.md)
