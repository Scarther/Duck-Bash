# Alert Suite Reference

## Overview

The Alert suite provides real-time notification capabilities for the WiFi Pineapple, enabling automated alerts for security events like client connections, handshake captures, and system status changes.

---

## Alert Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ALERT ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────────────────────────────────────────┐       │
│   │                 ALERT DAEMON                     │       │
│   │     (Monitors events and triggers alerts)        │       │
│   └───────────────────┬─────────────────────────────┘       │
│                       │                                      │
│   ┌───────────────────┴─────────────────────────────┐       │
│   │                                                   │       │
│   ▼                   ▼                   ▼          │       │
│ ┌─────────┐     ┌─────────┐       ┌─────────────┐   │       │
│ │  LED    │     │  Sound  │       │   Remote    │   │       │
│ │ Alerts  │     │ Alerts  │       │   Notify    │   │       │
│ └─────────┘     └─────────┘       └─────────────┘   │       │
│                                                              │
│   NOTIFICATION METHODS:                                      │
│   ├── LED Patterns - Visual indicators                      │
│   ├── Buzzer/Sound - Audio alerts                           │
│   ├── Email - SMTP notifications                            │
│   ├── SMS/Pushover - Mobile alerts                          │
│   ├── Webhook - HTTP callbacks                              │
│   └── Log - Local event logging                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Alert Types

### 1. Client Alerts
Triggered when clients connect/disconnect.

```bash
#!/bin/bash
# Client connection alert

ALERT_LOG="/sd/loot/alerts/clients.log"
KNOWN_CLIENTS="/tmp/known_clients.txt"

mkdir -p "$(dirname $ALERT_LOG)"
touch "$KNOWN_CLIENTS"

# Monitor DHCP leases for new clients
monitor_clients() {
    while true; do
        if [ -f /tmp/dnsmasq.leases ]; then
            while read timestamp mac ip hostname clientid; do
                if ! grep -q "$mac" "$KNOWN_CLIENTS" 2>/dev/null; then
                    # New client detected
                    echo "$mac" >> "$KNOWN_CLIENTS"
                    trigger_alert "CLIENT" "$mac" "$ip" "$hostname"
                fi
            done < /tmp/dnsmasq.leases
        fi
        sleep 5
    done
}

trigger_alert() {
    local type="$1"
    local mac="$2"
    local ip="$3"
    local hostname="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log event
    echo "[$timestamp] $type: MAC=$mac IP=$ip Host=$hostname" >> "$ALERT_LOG"

    # LED alert
    led_blink "blue" 3

    # Optional: Send remote notification
    # send_pushover "New client: $mac ($hostname)"
}

led_blink() {
    local color="$1"
    local count="$2"
    local led_path="/sys/class/leds/pineapple:${color}:system/brightness"

    if [ -f "$led_path" ]; then
        for i in $(seq 1 $count); do
            echo 1 > "$led_path"
            sleep 0.3
            echo 0 > "$led_path"
            sleep 0.2
        done
    fi
}

monitor_clients
```

### 2. Handshake Alerts
Triggered when WPA handshakes are captured.

```bash
#!/bin/bash
# Handshake capture alert

CAPTURE_DIR="/sd/loot/handshakes"
ALERT_FILE="/tmp/last_handshake"

monitor_handshakes() {
    inotifywait -m -e create -e modify "$CAPTURE_DIR" 2>/dev/null | while read path action file; do
        if [[ "$file" == *.cap ]]; then
            # Verify handshake
            if aircrack-ng "$path$file" 2>&1 | grep -q "1 handshake"; then
                local ssid=$(aircrack-ng "$path$file" 2>&1 | grep "BSSID" | head -1 | awk '{print $NF}')

                echo "$file" > "$ALERT_FILE"
                trigger_handshake_alert "$file" "$ssid"
            fi
        fi
    done
}

trigger_handshake_alert() {
    local file="$1"
    local ssid="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log
    echo "[$timestamp] HANDSHAKE: $ssid - $file" >> /sd/loot/alerts/handshakes.log

    # LED pattern (success)
    led_pattern "success"

    # Remote notification
    send_notification "Handshake captured: $ssid"
}

led_pattern() {
    local pattern="$1"

    case "$pattern" in
        "success")
            # Green blink pattern
            for i in {1..5}; do
                echo 1 > /sys/class/leds/pineapple:green:system/brightness
                sleep 0.2
                echo 0 > /sys/class/leds/pineapple:green:system/brightness
                sleep 0.1
            done
            ;;
        "warning")
            # Yellow/amber pattern
            for i in {1..3}; do
                echo 1 > /sys/class/leds/pineapple:amber:system/brightness
                sleep 0.5
                echo 0 > /sys/class/leds/pineapple:amber:system/brightness
                sleep 0.3
            done
            ;;
        "error")
            # Red pattern
            for i in {1..5}; do
                echo 1 > /sys/class/leds/pineapple:red:system/brightness
                sleep 0.1
                echo 0 > /sys/class/leds/pineapple:red:system/brightness
                sleep 0.1
            done
            ;;
    esac
}

monitor_handshakes
```

### 3. System Alerts
Triggered for system events (battery, storage, errors).

```bash
#!/bin/bash
# System status alerts

BATTERY_THRESHOLD=20
STORAGE_THRESHOLD=90
CHECK_INTERVAL=60

monitor_system() {
    while true; do
        check_battery
        check_storage
        check_services
        sleep $CHECK_INTERVAL
    done
}

check_battery() {
    local battery_file="/sys/class/power_supply/battery/capacity"

    if [ -f "$battery_file" ]; then
        local level=$(cat "$battery_file")

        if [ "$level" -lt "$BATTERY_THRESHOLD" ]; then
            trigger_system_alert "BATTERY_LOW" "Battery at ${level}%"
        fi
    fi
}

check_storage() {
    # Check SD card usage
    local usage=$(df /sd 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')

    if [ -n "$usage" ] && [ "$usage" -gt "$STORAGE_THRESHOLD" ]; then
        trigger_system_alert "STORAGE_LOW" "SD card at ${usage}%"
    fi
}

check_services() {
    local services=("hostapd" "dnsmasq" "nginx")

    for service in "${services[@]}"; do
        if ! pgrep -x "$service" >/dev/null; then
            trigger_system_alert "SERVICE_DOWN" "$service not running"
        fi
    done
}

trigger_system_alert() {
    local type="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] SYSTEM: $type - $message" >> /sd/loot/alerts/system.log

    case "$type" in
        "BATTERY_LOW")
            led_pattern "warning"
            ;;
        "STORAGE_LOW")
            led_pattern "warning"
            ;;
        "SERVICE_DOWN")
            led_pattern "error"
            ;;
    esac
}

monitor_system
```

---

## Remote Notification Methods

### Pushover Integration

```bash
#!/bin/bash
# Pushover notification sender

PUSHOVER_TOKEN="your_app_token"
PUSHOVER_USER="your_user_key"

send_pushover() {
    local message="$1"
    local title="${2:-WiFi Pineapple Alert}"
    local priority="${3:-0}"

    curl -s \
        --form-string "token=$PUSHOVER_TOKEN" \
        --form-string "user=$PUSHOVER_USER" \
        --form-string "title=$title" \
        --form-string "message=$message" \
        --form-string "priority=$priority" \
        https://api.pushover.net/1/messages.json
}

# Usage
send_pushover "New client connected: AA:BB:CC:DD:EE:FF" "Client Alert"
```

### Email Alerts (SMTP)

```bash
#!/bin/bash
# Email notification via SMTP

SMTP_SERVER="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USER="your_email@gmail.com"
SMTP_PASS="your_app_password"
RECIPIENT="alerts@example.com"

send_email() {
    local subject="$1"
    local body="$2"

    # Using curl for SMTP
    curl --ssl-reqd \
        --url "smtps://${SMTP_SERVER}:465" \
        --user "${SMTP_USER}:${SMTP_PASS}" \
        --mail-from "$SMTP_USER" \
        --mail-rcpt "$RECIPIENT" \
        -T - << EOF
From: WiFi Pineapple <$SMTP_USER>
To: <$RECIPIENT>
Subject: $subject

$body

--
Automated alert from WiFi Pineapple
Timestamp: $(date)
EOF
}

# Usage
send_email "Handshake Captured" "Successfully captured handshake for SSID: TargetNetwork"
```

### Webhook Notifications

```bash
#!/bin/bash
# Webhook notification (Slack, Discord, custom)

WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

send_webhook() {
    local message="$1"
    local title="${2:-Alert}"

    # Slack format
    curl -s -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "{
            \"text\": \"*${title}*\n${message}\",
            \"username\": \"WiFi Pineapple\",
            \"icon_emoji\": \":pineapple:\"
        }"
}

# Discord webhook
send_discord() {
    local message="$1"
    local webhook="$DISCORD_WEBHOOK_URL"

    curl -s -X POST "$webhook" \
        -H "Content-Type: application/json" \
        -d "{
            \"content\": \"**WiFi Pineapple Alert**\n${message}\"
        }"
}

# Generic POST webhook
send_generic_webhook() {
    local message="$1"
    local data="$2"

    curl -s -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "{
            \"event\": \"pineapple_alert\",
            \"message\": \"${message}\",
            \"data\": ${data},
            \"timestamp\": \"$(date -Iseconds)\"
        }"
}
```

### SMS via Twilio

```bash
#!/bin/bash
# SMS notification via Twilio

TWILIO_SID="your_account_sid"
TWILIO_TOKEN="your_auth_token"
TWILIO_FROM="+1234567890"
TWILIO_TO="+0987654321"

send_sms() {
    local message="$1"

    curl -s -X POST "https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json" \
        --data-urlencode "Body=$message" \
        --data-urlencode "From=$TWILIO_FROM" \
        --data-urlencode "To=$TWILIO_TO" \
        -u "${TWILIO_SID}:${TWILIO_TOKEN}"
}

# Usage
send_sms "Pineapple Alert: New client connected"
```

---

## LED Control Reference

### LED Paths

```bash
# Common LED paths on WiFi Pineapple
/sys/class/leds/pineapple:blue:system/brightness
/sys/class/leds/pineapple:green:system/brightness
/sys/class/leds/pineapple:red:system/brightness
/sys/class/leds/pineapple:amber:system/brightness

# Control
echo 1 > /sys/class/leds/pineapple:blue:system/brightness  # ON
echo 0 > /sys/class/leds/pineapple:blue:system/brightness  # OFF
```

### LED Utility Functions

```bash
#!/bin/bash
# LED utility functions

LED_BASE="/sys/class/leds"

led_on() {
    local color="$1"
    echo 1 > "${LED_BASE}/pineapple:${color}:system/brightness" 2>/dev/null
}

led_off() {
    local color="$1"
    echo 0 > "${LED_BASE}/pineapple:${color}:system/brightness" 2>/dev/null
}

led_all_off() {
    for color in blue green red amber; do
        led_off "$color"
    done
}

led_blink() {
    local color="$1"
    local count="${2:-3}"
    local on_time="${3:-0.3}"
    local off_time="${4:-0.2}"

    for i in $(seq 1 $count); do
        led_on "$color"
        sleep "$on_time"
        led_off "$color"
        sleep "$off_time"
    done
}

led_pulse() {
    local color="$1"
    local duration="${2:-5}"
    local end_time=$(($(date +%s) + duration))

    while [ $(date +%s) -lt $end_time ]; do
        led_on "$color"
        sleep 0.5
        led_off "$color"
        sleep 0.5
    done
}

# Status indicator patterns
led_status_ok() {
    led_all_off
    led_on "green"
}

led_status_busy() {
    led_all_off
    led_pulse "blue" &
}

led_status_error() {
    led_all_off
    led_on "red"
}

led_status_warning() {
    led_all_off
    led_on "amber"
}
```

---

## Complete Alert Module

```bash
#!/bin/bash
#
# Comprehensive Alert Module for WiFi Pineapple
# Monitors multiple events and sends notifications
#

# ============================================
# CONFIGURATION
# ============================================

CONFIG_FILE="/etc/pineapple/alerts.conf"
LOG_DIR="/sd/loot/alerts"
KNOWN_CLIENTS="/tmp/alert_known_clients.txt"

# Notification settings (load from config if exists)
ENABLE_LED="true"
ENABLE_EMAIL="false"
ENABLE_PUSHOVER="false"
ENABLE_WEBHOOK="false"
ENABLE_SMS="false"

# Thresholds
BATTERY_WARN=30
BATTERY_CRITICAL=10
STORAGE_WARN=80
STORAGE_CRITICAL=95

# ============================================
# LOAD CONFIG
# ============================================

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# ============================================
# CORE FUNCTIONS
# ============================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    mkdir -p "$LOG_DIR"
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/alert_module.log"
}

send_notification() {
    local title="$1"
    local message="$2"
    local priority="${3:-normal}"

    log "NOTIFY" "$title: $message"

    # LED notification
    if [ "$ENABLE_LED" = "true" ]; then
        case "$priority" in
            "critical") led_blink "red" 5 ;;
            "high") led_blink "amber" 3 ;;
            "normal") led_blink "blue" 2 ;;
            "low") led_blink "green" 1 ;;
        esac
    fi

    # Remote notifications
    [ "$ENABLE_PUSHOVER" = "true" ] && send_pushover "$message" "$title"
    [ "$ENABLE_EMAIL" = "true" ] && send_email "$title" "$message"
    [ "$ENABLE_WEBHOOK" = "true" ] && send_webhook "$message" "$title"
    [ "$ENABLE_SMS" = "true" ] && [ "$priority" = "critical" ] && send_sms "$title: $message"
}

# ============================================
# EVENT MONITORS
# ============================================

monitor_clients() {
    log "INFO" "Starting client monitor"
    touch "$KNOWN_CLIENTS"

    while true; do
        if [ -f /tmp/dnsmasq.leases ]; then
            while read timestamp mac ip hostname clientid; do
                if ! grep -q "$mac" "$KNOWN_CLIENTS" 2>/dev/null; then
                    echo "$mac" >> "$KNOWN_CLIENTS"

                    # Get OUI vendor
                    local oui=$(echo "$mac" | cut -d: -f1-3 | tr ':' '-' | tr 'a-f' 'A-F')

                    send_notification "New Client" "MAC: $mac IP: $ip Host: $hostname" "normal"

                    # Log detailed info
                    echo "$(date '+%Y-%m-%d %H:%M:%S'),$mac,$ip,$hostname,$oui" >> "$LOG_DIR/clients.csv"
                fi
            done < /tmp/dnsmasq.leases
        fi
        sleep 5
    done
}

monitor_handshakes() {
    log "INFO" "Starting handshake monitor"

    local capture_dirs=("/sd/loot/handshakes" "/tmp/captures")

    for dir in "${capture_dirs[@]}"; do
        if [ -d "$dir" ]; then
            inotifywait -m -e create -e modify "$dir" 2>/dev/null | while read path action file; do
                if [[ "$file" == *.cap ]]; then
                    sleep 2  # Wait for file to complete

                    if aircrack-ng "${path}${file}" 2>&1 | grep -q "handshake"; then
                        send_notification "Handshake Captured" "File: $file" "high"
                    fi
                fi
            done &
        fi
    done
}

monitor_system() {
    log "INFO" "Starting system monitor"

    while true; do
        # Battery check
        if [ -f /sys/class/power_supply/battery/capacity ]; then
            local battery=$(cat /sys/class/power_supply/battery/capacity)

            if [ "$battery" -lt "$BATTERY_CRITICAL" ]; then
                send_notification "Critical Battery" "Battery at ${battery}%" "critical"
            elif [ "$battery" -lt "$BATTERY_WARN" ]; then
                send_notification "Low Battery" "Battery at ${battery}%" "high"
            fi
        fi

        # Storage check
        local storage=$(df /sd 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
        if [ -n "$storage" ]; then
            if [ "$storage" -gt "$STORAGE_CRITICAL" ]; then
                send_notification "Critical Storage" "SD card at ${storage}%" "critical"
            elif [ "$storage" -gt "$STORAGE_WARN" ]; then
                send_notification "Low Storage" "SD card at ${storage}%" "high"
            fi
        fi

        # Service check
        for service in hostapd dnsmasq; do
            if ! pgrep -x "$service" >/dev/null 2>&1; then
                send_notification "Service Down" "$service is not running" "high"
            fi
        done

        sleep 60
    done
}

monitor_probes() {
    log "INFO" "Starting probe monitor"

    local probe_log="/tmp/pineap_probes.log"

    if [ -f "$probe_log" ]; then
        tail -F "$probe_log" 2>/dev/null | while read line; do
            if echo "$line" | grep -qE "^[0-9A-Fa-f:]{17}"; then
                local mac=$(echo "$line" | awk '{print $1}')
                local ssid=$(echo "$line" | awk '{print $2}')

                log "PROBE" "MAC: $mac probed for: $ssid"

                # Check for high-value targets
                if echo "$ssid" | grep -qiE "(corp|secure|vpn|admin)"; then
                    send_notification "Interesting Probe" "MAC: $mac searching for: $ssid" "normal"
                fi
            fi
        done
    fi
}

# ============================================
# MAIN
# ============================================

main() {
    log "INFO" "Alert module starting"

    mkdir -p "$LOG_DIR"

    # Start all monitors in background
    monitor_clients &
    monitor_handshakes &
    monitor_system &
    monitor_probes &

    log "INFO" "All monitors started"

    # Keep main process running
    wait
}

# Cleanup on exit
cleanup() {
    log "INFO" "Alert module stopping"
    pkill -P $$
    exit 0
}

trap cleanup SIGINT SIGTERM

# Run
main
```

---

## API Integration

### Alert API Endpoints

```bash
# Base URL
API="http://172.16.42.1:1471/api"

# Get alert status
curl -s "$API/alerts/status"

# Enable/disable alert types
curl -s -X POST "$API/alerts/client/enable"
curl -s -X POST "$API/alerts/handshake/enable"
curl -s -X POST "$API/alerts/system/enable"

# Configure notification methods
curl -s -X POST "$API/alerts/config" \
    -d "pushover_token=xxx" \
    -d "pushover_user=xxx" \
    -d "email_enabled=true"

# View recent alerts
curl -s "$API/alerts/recent?limit=50"

# Clear alert history
curl -s -X POST "$API/alerts/clear"
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────┐
│                  ALERT SUITE QUICK REFERENCE                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ALERT TYPES:                                                │
│    - Client connection/disconnection                        │
│    - Handshake capture                                       │
│    - System status (battery, storage, services)             │
│    - Probe request detection                                 │
│                                                              │
│  NOTIFICATION METHODS:                                       │
│    - LED patterns (visual)                                   │
│    - Pushover (mobile push)                                  │
│    - Email (SMTP)                                            │
│    - Webhook (Slack, Discord, custom)                       │
│    - SMS (Twilio)                                            │
│                                                              │
│  LED COLORS:                                                 │
│    Blue  - Normal activity                                   │
│    Green - Success/OK                                        │
│    Amber - Warning                                           │
│    Red   - Error/Critical                                    │
│                                                              │
│  KEY FILES:                                                  │
│    /etc/pineapple/alerts.conf                               │
│    /sd/loot/alerts/*.log                                    │
│    /tmp/known_clients.txt                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← Module Development](08_Module_Development.md) | [Back to Fundamentals](README.md) | [Next: Payloads Suite →](10_Payloads_Suite.md)
