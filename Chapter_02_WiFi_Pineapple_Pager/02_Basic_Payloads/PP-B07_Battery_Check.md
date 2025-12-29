# PP-B07: Battery Check

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B07 |
| **Name** | Battery Check |
| **Difficulty** | Basic |
| **Type** | Info |
| **Purpose** | Monitor battery status and health |

## What This Payload Does

Monitors battery status on portable WiFi Pineapple devices, providing charge level, power consumption, and estimated runtime for field operations.

---

## Understanding Power Management

```
┌─────────────────────────────────────────────────────────────┐
│              PINEAPPLE POWER SOURCES                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐  │
│   │   Battery   │     │  USB Power  │     │  AC Adapter │  │
│   │   Pack      │     │  Bank       │     │             │  │
│   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘  │
│          │                   │                   │          │
│          └───────────────────┴───────────────────┘          │
│                              │                               │
│                    ┌─────────▼─────────┐                    │
│                    │   WiFi Pineapple  │                    │
│                    │   5V @ 2A typical │                    │
│                    └───────────────────┘                    │
│                                                              │
│   POWER CONSUMPTION:                                        │
│   • Idle: ~300mA (1.5W)                                     │
│   • Scanning: ~500mA (2.5W)                                 │
│   • Evil Twin + Clients: ~800mA (4W)                        │
│   • Full Load: ~1200mA (6W)                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B07
# Name: Battery Check
# Description: Monitor battery status and estimate runtime
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
LOG_FILE="/tmp/pp-b07.log"
BATTERY_LOG="/sd/loot/battery_history.csv"

# Power consumption estimates (mA)
POWER_IDLE=300
POWER_SCAN=500
POWER_EVIL_TWIN=800
POWER_FULL=1200

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Find battery sysfs paths
find_battery() {
    local paths=(
        "/sys/class/power_supply/battery"
        "/sys/class/power_supply/BAT0"
        "/sys/class/power_supply/BAT1"
        "/sys/class/power_supply/axp20x-battery"
    )

    for path in "${paths[@]}"; do
        if [ -d "$path" ]; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

# Get battery percentage
get_battery_percent() {
    local path="$1"

    if [ -f "$path/capacity" ]; then
        cat "$path/capacity"
    elif [ -f "$path/charge_now" ] && [ -f "$path/charge_full" ]; then
        local now=$(cat "$path/charge_now")
        local full=$(cat "$path/charge_full")
        echo $((now * 100 / full))
    else
        echo "unknown"
    fi
}

# Get battery status
get_battery_status() {
    local path="$1"

    if [ -f "$path/status" ]; then
        cat "$path/status"
    else
        echo "Unknown"
    fi
}

# Get current draw (mA)
get_current_now() {
    local path="$1"

    if [ -f "$path/current_now" ]; then
        # Value is in microamps, convert to mA
        local ua=$(cat "$path/current_now")
        echo $((ua / 1000))
    else
        echo "0"
    fi
}

# Get voltage
get_voltage() {
    local path="$1"

    if [ -f "$path/voltage_now" ]; then
        # Value is in microvolts, convert to V
        local uv=$(cat "$path/voltage_now")
        echo "scale=2; $uv / 1000000" | bc 2>/dev/null || echo $((uv / 1000000))
    else
        echo "0"
    fi
}

# Estimate runtime
estimate_runtime() {
    local percent="$1"
    local current="$2"
    local capacity="${3:-2000}"  # Default 2000mAh battery

    if [ "$current" -gt 0 ] && [ "$percent" != "unknown" ]; then
        local remaining_mah=$((capacity * percent / 100))
        local hours=$((remaining_mah / current))
        local minutes=$(((remaining_mah % current) * 60 / current))
        echo "${hours}h ${minutes}m"
    else
        echo "Unknown"
    fi
}

# Get battery health
get_battery_health() {
    local path="$1"

    if [ -f "$path/health" ]; then
        cat "$path/health"
    elif [ -f "$path/charge_full" ] && [ -f "$path/charge_full_design" ]; then
        local full=$(cat "$path/charge_full")
        local design=$(cat "$path/charge_full_design")
        if [ "$design" -gt 0 ]; then
            local health=$((full * 100 / design))
            if [ "$health" -gt 80 ]; then
                echo "Good ($health%)"
            elif [ "$health" -gt 50 ]; then
                echo "Fair ($health%)"
            else
                echo "Poor ($health%)"
            fi
        else
            echo "Unknown"
        fi
    else
        echo "Unknown"
    fi
}

# ============================================
# MAIN
# ============================================
log "Starting PP-B07: Battery Check"

echo "╔════════════════════════════════════════════════════╗"
echo "║           BATTERY STATUS REPORT                    ║"
echo "╚════════════════════════════════════════════════════╝"
echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Find battery
BATTERY_PATH=$(find_battery)

if [ -z "$BATTERY_PATH" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " NO BATTERY DETECTED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "This device may be:"
    echo "  • Running on external power only"
    echo "  • Using USB power bank without smart battery"
    echo "  • Battery sysfs interface not available"
    echo ""

    # Check USB power
    if [ -d "/sys/class/power_supply/usb" ]; then
        echo "USB Power Status:"
        if [ -f "/sys/class/power_supply/usb/online" ]; then
            USB_ONLINE=$(cat /sys/class/power_supply/usb/online)
            echo "  Connected: $([ "$USB_ONLINE" = "1" ] && echo "Yes" || echo "No")"
        fi
    fi

    # Estimate based on activity
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " RUNTIME ESTIMATES (10000mAh power bank)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Idle Mode:      ~$((10000 / POWER_IDLE)) hours"
    echo "  Scanning:       ~$((10000 / POWER_SCAN)) hours"
    echo "  Evil Twin:      ~$((10000 / POWER_EVIL_TWIN)) hours"
    echo "  Full Load:      ~$((10000 / POWER_FULL)) hours"

    exit 0
fi

log "Battery found at: $BATTERY_PATH"

# Get battery information
PERCENT=$(get_battery_percent "$BATTERY_PATH")
STATUS=$(get_battery_status "$BATTERY_PATH")
CURRENT=$(get_current_now "$BATTERY_PATH")
VOLTAGE=$(get_voltage "$BATTERY_PATH")
HEALTH=$(get_battery_health "$BATTERY_PATH")

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " BATTERY STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Visual battery indicator
if [ "$PERCENT" != "unknown" ]; then
    BLOCKS=$((PERCENT / 10))
    BAR=""
    for i in $(seq 1 10); do
        if [ $i -le $BLOCKS ]; then
            BAR="${BAR}█"
        else
            BAR="${BAR}░"
        fi
    done

    # Color indicator
    if [ "$PERCENT" -ge 60 ]; then
        INDICATOR="●"  # Good
    elif [ "$PERCENT" -ge 20 ]; then
        INDICATOR="◐"  # Warning
    else
        INDICATOR="○"  # Critical
    fi

    echo "  [${BAR}] ${PERCENT}% ${INDICATOR}"
else
    echo "  Battery Level: Unknown"
fi

echo ""
echo "  Status:        $STATUS"
echo "  Voltage:       ${VOLTAGE}V"
echo "  Current:       ${CURRENT}mA"
echo "  Health:        $HEALTH"

# Runtime estimation
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " RUNTIME ESTIMATES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$PERCENT" != "unknown" ] && [ "$PERCENT" -gt 0 ]; then
    echo "  Current Rate:   $(estimate_runtime $PERCENT $CURRENT)"
    echo "  At Idle:        $(estimate_runtime $PERCENT $POWER_IDLE)"
    echo "  At Scan:        $(estimate_runtime $PERCENT $POWER_SCAN)"
    echo "  At Evil Twin:   $(estimate_runtime $PERCENT $POWER_EVIL_TWIN)"
else
    echo "  Unable to estimate (battery data unavailable)"
fi

# Warnings
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " ALERTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ALERTS=0
if [ "$PERCENT" != "unknown" ]; then
    if [ "$PERCENT" -lt 10 ]; then
        echo "  ⚠ CRITICAL: Battery critically low!"
        ALERTS=$((ALERTS + 1))
    elif [ "$PERCENT" -lt 20 ]; then
        echo "  ⚠ WARNING: Battery low, consider charging"
        ALERTS=$((ALERTS + 1))
    fi
fi

if [ "$CURRENT" -gt 1000 ]; then
    echo "  ⚠ High power draw detected (${CURRENT}mA)"
    ALERTS=$((ALERTS + 1))
fi

if [ "$ALERTS" -eq 0 ]; then
    echo "  ✓ No alerts"
fi

# Log to history
if [ -d "$(dirname $BATTERY_LOG)" ]; then
    # Create header if file doesn't exist
    if [ ! -f "$BATTERY_LOG" ]; then
        echo "timestamp,percent,status,current_ma,voltage" > "$BATTERY_LOG"
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S'),$PERCENT,$STATUS,$CURRENT,$VOLTAGE" >> "$BATTERY_LOG"
fi

echo ""
log "Battery check complete"
exit 0
```

---

## Field Operation Planning

### Power Bank Recommendations

| Capacity | Idle | Scanning | Evil Twin | Full Load |
|----------|------|----------|-----------|-----------|
| 5,000mAh | 16h | 10h | 6h | 4h |
| 10,000mAh | 33h | 20h | 12h | 8h |
| 20,000mAh | 66h | 40h | 25h | 16h |
| 26,800mAh | 89h | 53h | 33h | 22h |

### Extending Battery Life

```bash
# Reduce CPU frequency (if supported)
echo powersave > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# Disable unused interfaces
ip link set eth0 down 2>/dev/null

# Reduce WiFi TX power
iwconfig wlan1 txpower 10  # 10dBm instead of default

# Disable LEDs
echo 0 > /sys/class/leds/*/brightness

# Stop non-essential services
/etc/init.d/nginx stop
/etc/init.d/php7-fpm stop
```

---

## Continuous Monitoring Script

```bash
#!/bin/bash
# Battery monitor daemon

THRESHOLD=15
CHECK_INTERVAL=60

while true; do
    PERCENT=$(cat /sys/class/power_supply/battery/capacity 2>/dev/null)

    if [ -n "$PERCENT" ] && [ "$PERCENT" -lt "$THRESHOLD" ]; then
        # Alert: Low battery
        echo "[BATTERY LOW] $PERCENT% remaining" | logger

        # LED warning
        for i in 1 2 3; do
            echo 1 > /sys/class/leds/pineapple:red:system/brightness
            sleep 0.5
            echo 0 > /sys/class/leds/pineapple:red:system/brightness
            sleep 0.5
        done

        # Optional: webhook notification
        # curl -X POST "http://server/alert?battery=$PERCENT"
    fi

    sleep $CHECK_INTERVAL
done
```

---

## Red Team Notes

- Always start operations with full charge
- Carry backup power banks
- Know your runtime for planned activities
- Set low battery alerts to avoid mid-operation shutdown
- Consider solar charging for extended deployments

## Blue Team Notes

- Rogue devices may have limited battery life
- Power banks in unusual locations may indicate drops
- Monitor for new devices appearing after hours

---

## Payload File

Save as `PP-B07_Battery_Check.sh`:

```bash
#!/bin/bash
# PP-B07: Battery Check (Compact)
BAT="/sys/class/power_supply/battery"
[ -d "$BAT" ] || BAT="/sys/class/power_supply/BAT0"
if [ -d "$BAT" ]; then
    PCT=$(cat $BAT/capacity 2>/dev/null || echo "?")
    STS=$(cat $BAT/status 2>/dev/null || echo "?")
    echo "Battery: ${PCT}% ($STS)"
else
    echo "No battery detected - external power"
fi
```

---

[← PP-B06 System Status](PP-B06_System_Status.md) | [Back to Basic Payloads](README.md) | [Next: PP-B08 Interface Status →](PP-B08_Interface_Status.md)
