# PP-B09: Log Viewer

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B09 |
| **Name** | Log Viewer |
| **Difficulty** | Basic |
| **Type** | Info |
| **Purpose** | View and analyze system logs |

## What This Payload Does

Provides a consolidated view of system logs, filtering for security-relevant events. Essential for troubleshooting and understanding device activity.

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B09
# Name: Log Viewer
# Description: View and analyze system logs
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
LOG_FILE="/tmp/pp-b09.log"
MAX_LINES=50
FOLLOW_MODE=false

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -a, --all        Show all logs"
    echo "  -s, --system     Show system logs"
    echo "  -w, --wireless   Show wireless logs"
    echo "  -n, --network    Show network logs"
    echo "  -e, --errors     Show error logs only"
    echo "  -f, --follow     Follow logs in real-time"
    echo "  -l, --lines N    Number of lines (default: 50)"
    echo "  -h, --help       Show this help"
    exit 0
}

section() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ============================================
# PARSE ARGUMENTS
# ============================================
SHOW_ALL=false
SHOW_SYSTEM=false
SHOW_WIRELESS=false
SHOW_NETWORK=false
SHOW_ERRORS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--all)       SHOW_ALL=true; shift ;;
        -s|--system)    SHOW_SYSTEM=true; shift ;;
        -w|--wireless)  SHOW_WIRELESS=true; shift ;;
        -n|--network)   SHOW_NETWORK=true; shift ;;
        -e|--errors)    SHOW_ERRORS=true; shift ;;
        -f|--follow)    FOLLOW_MODE=true; shift ;;
        -l|--lines)     MAX_LINES="$2"; shift 2 ;;
        -h|--help)      usage ;;
        *)              shift ;;
    esac
done

# Default to all if nothing specified
if ! $SHOW_ALL && ! $SHOW_SYSTEM && ! $SHOW_WIRELESS && ! $SHOW_NETWORK && ! $SHOW_ERRORS; then
    SHOW_ALL=true
fi

# ============================================
# MAIN
# ============================================
log "Starting PP-B09: Log Viewer"

echo "╔════════════════════════════════════════════════════╗"
echo "║              LOG VIEWER                            ║"
echo "╚════════════════════════════════════════════════════╝"
echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Lines per section: $MAX_LINES"

# ============================================
# SYSTEM LOGS
# ============================================
if $SHOW_ALL || $SHOW_SYSTEM; then
    section "SYSTEM LOGS"

    # dmesg (kernel messages)
    echo "--- Kernel Messages (dmesg) ---"
    dmesg 2>/dev/null | tail -$MAX_LINES

    echo ""
    echo "--- System Messages ---"
    if [ -f /var/log/messages ]; then
        tail -$MAX_LINES /var/log/messages
    elif [ -f /var/log/syslog ]; then
        tail -$MAX_LINES /var/log/syslog
    else
        logread 2>/dev/null | tail -$MAX_LINES || echo "No system log available"
    fi
fi

# ============================================
# WIRELESS LOGS
# ============================================
if $SHOW_ALL || $SHOW_WIRELESS; then
    section "WIRELESS LOGS"

    echo "--- hostapd Logs ---"
    if [ -f /var/log/hostapd.log ]; then
        tail -$MAX_LINES /var/log/hostapd.log
    else
        # Try to extract from system log
        if [ -f /var/log/messages ]; then
            grep -i "hostapd\|wlan\|wifi\|80211" /var/log/messages 2>/dev/null | tail -$MAX_LINES
        else
            logread 2>/dev/null | grep -i "hostapd\|wlan\|wifi\|80211" | tail -$MAX_LINES
        fi
    fi

    echo ""
    echo "--- PineAP Logs ---"
    if [ -f /tmp/pineap.log ]; then
        tail -$MAX_LINES /tmp/pineap.log
    else
        echo "No PineAP log found"
    fi

    echo ""
    echo "--- Aircrack Logs ---"
    for logfile in /tmp/airodump*.log /tmp/aireplay*.log; do
        if [ -f "$logfile" ]; then
            echo "[$(basename $logfile)]"
            tail -20 "$logfile"
        fi
    done
fi

# ============================================
# NETWORK LOGS
# ============================================
if $SHOW_ALL || $SHOW_NETWORK; then
    section "NETWORK LOGS"

    echo "--- DHCP/DNS Logs (dnsmasq) ---"
    if [ -f /var/log/dnsmasq.log ]; then
        tail -$MAX_LINES /var/log/dnsmasq.log
    else
        if [ -f /var/log/messages ]; then
            grep -i "dnsmasq" /var/log/messages 2>/dev/null | tail -$MAX_LINES
        else
            logread 2>/dev/null | grep -i "dnsmasq" | tail -$MAX_LINES
        fi
    fi

    echo ""
    echo "--- DHCP Leases ---"
    if [ -f /tmp/dnsmasq.leases ]; then
        echo "Active leases:"
        cat /tmp/dnsmasq.leases
    else
        echo "No active leases"
    fi

    echo ""
    echo "--- Firewall Logs ---"
    if [ -f /var/log/firewall.log ]; then
        tail -$MAX_LINES /var/log/firewall.log
    else
        dmesg 2>/dev/null | grep -i "iptables\|nftables\|firewall" | tail -20
    fi
fi

# ============================================
# ERROR LOGS
# ============================================
if $SHOW_ALL || $SHOW_ERRORS; then
    section "ERRORS & WARNINGS"

    echo "--- System Errors ---"
    if [ -f /var/log/messages ]; then
        grep -iE "error|fail|warn|critical" /var/log/messages 2>/dev/null | tail -$MAX_LINES
    else
        logread 2>/dev/null | grep -iE "error|fail|warn|critical" | tail -$MAX_LINES
    fi

    echo ""
    echo "--- Kernel Errors ---"
    dmesg 2>/dev/null | grep -iE "error|fail|warn|critical" | tail -20

    echo ""
    echo "--- OOM Events ---"
    dmesg 2>/dev/null | grep -i "out of memory\|oom\|killed" | tail -10
fi

# ============================================
# PAYLOAD EXECUTION LOGS
# ============================================
if $SHOW_ALL; then
    section "PAYLOAD LOGS"

    echo "--- Recent Payload Executions ---"
    ls -lt /tmp/pp-*.log 2>/dev/null | head -10

    echo ""
    for logfile in /tmp/pp-*.log; do
        if [ -f "$logfile" ]; then
            echo "[$(basename $logfile) - last 5 lines]"
            tail -5 "$logfile"
            echo ""
        fi
    done
fi

# ============================================
# SECURITY EVENTS
# ============================================
if $SHOW_ALL; then
    section "SECURITY EVENTS"

    echo "--- SSH Connections ---"
    if [ -f /var/log/auth.log ]; then
        grep -i "ssh\|sshd" /var/log/auth.log 2>/dev/null | tail -20
    else
        logread 2>/dev/null | grep -i "ssh\|dropbear" | tail -20
    fi

    echo ""
    echo "--- Failed Login Attempts ---"
    if [ -f /var/log/auth.log ]; then
        grep -i "failed\|invalid" /var/log/auth.log 2>/dev/null | tail -10
    else
        logread 2>/dev/null | grep -i "failed\|invalid" | tail -10
    fi

    echo ""
    echo "--- Web Interface Access ---"
    if [ -f /var/log/nginx/access.log ]; then
        tail -20 /var/log/nginx/access.log
    elif [ -f /var/log/lighttpd/access.log ]; then
        tail -20 /var/log/lighttpd/access.log
    else
        echo "No web access log found"
    fi
fi

# ============================================
# FOLLOW MODE
# ============================================
if $FOLLOW_MODE; then
    section "FOLLOWING LOGS (Ctrl+C to stop)"

    # Determine which log to follow
    if [ -f /var/log/messages ]; then
        tail -f /var/log/messages
    elif [ -f /var/log/syslog ]; then
        tail -f /var/log/syslog
    else
        logread -f 2>/dev/null || {
            echo "Cannot follow logs on this system"
            exit 1
        }
    fi
fi

echo ""
log "Log viewer complete"
exit 0
```

---

## Log Locations

### OpenWrt/Pineapple Log Files

| Log | Location | Contents |
|-----|----------|----------|
| System | `/var/log/messages` or `logread` | General system events |
| Kernel | `dmesg` | Kernel ring buffer |
| DHCP | `/tmp/dnsmasq.leases` | DHCP lease table |
| WiFi | Various | Wireless events |
| Web | `/var/log/nginx/` | Web interface access |
| Auth | System log | Login attempts |

### Common Log Locations

```
/var/log/
├── messages          # System messages
├── syslog            # Alternative system log
├── auth.log          # Authentication
├── kern.log          # Kernel messages
├── dmesg             # Boot messages
├── nginx/
│   ├── access.log    # Web access
│   └── error.log     # Web errors
├── hostapd.log       # AP daemon
└── dnsmasq.log       # DNS/DHCP
```

---

## Useful Log Filtering

### Find Specific Events
```bash
# All WiFi events
logread | grep -iE "wlan|wifi|wireless|80211"

# DHCP assignments
logread | grep "dnsmasq-dhcp"

# Client connections
grep "authenticated" /var/log/hostapd.log

# Failed SSH attempts
logread | grep -i "failed password"
```

### Real-Time Monitoring
```bash
# Follow all logs
logread -f

# Follow with filter
logread -f | grep -i "wlan"

# Multiple log files
tail -f /var/log/messages /tmp/pineap.log
```

---

## Security-Relevant Entries

### Signs of Attack
```bash
# Many failed logins
grep -c "Failed password" /var/log/auth.log

# Port scanning
grep "DPT=" /var/log/messages | sort | uniq -c | sort -rn

# Brute force attempts
grep "Invalid user" /var/log/auth.log | cut -d' ' -f10 | sort | uniq -c
```

### Successful Operations
```bash
# Successful associations
grep "authenticated" /var/log/hostapd.log

# Handshakes captured
grep -i "handshake" /tmp/*.log

# Evil Twin connections
grep "DHCPACK" /tmp/dnsmasq.leases
```

---

## Log Rotation

```bash
# Manual log rotation
cat /dev/null > /var/log/messages

# Rotate and compress
logrotate /etc/logrotate.conf

# Clear all logs
for log in /var/log/*.log; do
    cat /dev/null > "$log"
done
```

---

## Red Team Notes

- Clear logs after operations: `logread > /dev/null; cat /dev/null > /var/log/*`
- Disable logging: `/etc/init.d/syslog stop`
- Check for evidence before exfil
- Monitor logs during operations for issues

## Blue Team Notes

- Enable verbose logging on security devices
- Forward logs to SIEM
- Set up log monitoring alerts
- Preserve logs for forensics

---

## Payload File

Save as `PP-B09_Log_Viewer.sh`:

```bash
#!/bin/bash
# PP-B09: Log Viewer (Compact)
echo "=== Recent System Logs ==="
logread 2>/dev/null | tail -30 || tail -30 /var/log/messages 2>/dev/null || echo "No logs available"
echo ""
echo "=== Wireless Events ==="
logread 2>/dev/null | grep -iE "wlan|hostapd|wifi" | tail -10
```

---

[← PP-B08 Interface Status](PP-B08_Interface_Status.md) | [Back to Basic Payloads](README.md) | [Next: PP-B10 Quick Recon →](PP-B10_Quick_Recon.md)
