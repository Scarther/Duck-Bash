# Blue Team Fundamentals

## Overview

This guide covers essential Blue Team concepts, tools, and methodologies for defending against BadUSB and other endpoint attacks.

---

## Blue Team Mindset

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEFENSE IN DEPTH                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   PREVENT ──► DETECT ──► RESPOND ──► RECOVER ──► IMPROVE        │
│                                                                  │
│   Layers:                                                        │
│   ┌───────────────────────────────────────────────────────┐     │
│   │ Physical Security (USB ports, access control)          │     │
│   ├───────────────────────────────────────────────────────┤     │
│   │ Network Security (segmentation, monitoring)            │     │
│   ├───────────────────────────────────────────────────────┤     │
│   │ Endpoint Security (EDR, antivirus, logging)            │     │
│   ├───────────────────────────────────────────────────────┤     │
│   │ Application Security (whitelisting, hardening)         │     │
│   ├───────────────────────────────────────────────────────┤     │
│   │ Data Security (encryption, DLP, backups)               │     │
│   └───────────────────────────────────────────────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Security Concepts

### CIA Triad

| Principle | Description | BadUSB Threat |
|-----------|-------------|---------------|
| **Confidentiality** | Data accessible only to authorized | Data exfiltration payloads |
| **Integrity** | Data is accurate and unaltered | System modification |
| **Availability** | Systems accessible when needed | Destruction/ransomware |

### Security Controls

| Control Type | Purpose | Example |
|--------------|---------|---------|
| **Preventive** | Stop attacks | USB device blocking |
| **Detective** | Identify attacks | Process monitoring |
| **Corrective** | Fix damage | Incident response |
| **Deterrent** | Discourage attacks | Security awareness |

---

## Essential Blue Team Tools

### Endpoint Monitoring

```bash
#!/bin/bash
#######################################
# Essential Blue Team Toolkit Setup
# Linux/Kali Environment
#######################################

echo "[*] Installing Blue Team toolkit..."

# Monitoring tools
apt install -y \
    sysstat \
    htop \
    iotop \
    nethogs \
    iftop \
    auditd \
    osquery

# Analysis tools
apt install -y \
    volatility3 \
    sleuthkit \
    autopsy \
    binwalk \
    foremost

# Network tools
apt install -y \
    wireshark \
    tcpdump \
    tshark \
    ngrep \
    zeek

# Log analysis
apt install -y \
    logwatch \
    goaccess \
    lnav

echo "[+] Blue Team toolkit installed"
```

### Process Monitoring Script

```bash
#!/bin/bash
#######################################
# Real-time Process Monitor
# Detect suspicious activity
#######################################

LOG_FILE="/var/log/process_monitor.log"
ALERT_KEYWORDS="powershell|cmd\.exe|base64|wget|curl|nc |ncat|/dev/tcp"

monitor_processes() {
    echo "[*] Starting process monitor..."
    echo "[*] Logging to: $LOG_FILE"

    while true; do
        # Get new processes
        ps auxf | while read line; do
            # Check for suspicious patterns
            if echo "$line" | grep -qEi "$ALERT_KEYWORDS"; then
                TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
                echo "[$TIMESTAMP] ALERT: $line" | tee -a "$LOG_FILE"
            fi
        done
        sleep 5
    done
}

# Run with logging
monitor_processes
```

---

## Log Analysis Fundamentals

### Critical Log Sources

| Platform | Log | Path/Command |
|----------|-----|--------------|
| Linux | Auth | `/var/log/auth.log` |
| Linux | Syslog | `/var/log/syslog` |
| Linux | Audit | `/var/log/audit/audit.log` |
| Windows | Security | Event Viewer → Security |
| Windows | PowerShell | Event ID 4104 |
| Windows | Sysmon | Microsoft-Windows-Sysmon |

### Log Analysis Script

```bash
#!/bin/bash
#######################################
# Quick Log Analysis
# Check for common attack indicators
#######################################

echo "======================================"
echo "       LOG ANALYSIS REPORT"
echo "======================================"
echo ""

# Failed logins
echo "[*] Failed Login Attempts (last 24h):"
grep -i "failed" /var/log/auth.log 2>/dev/null | \
    grep "$(date -d '1 day ago' '+%b %d')" | \
    wc -l
echo ""

# Sudo usage
echo "[*] Sudo Commands (last 24h):"
grep "sudo" /var/log/auth.log 2>/dev/null | \
    grep "$(date -d '1 day ago' '+%b %d')" | \
    tail -10
echo ""

# New user accounts
echo "[*] Account Changes:"
grep -E "useradd|usermod|userdel" /var/log/auth.log 2>/dev/null | \
    tail -5
echo ""

# SSH connections
echo "[*] SSH Sessions:"
grep "sshd" /var/log/auth.log 2>/dev/null | \
    grep -E "Accepted|Failed" | \
    tail -10
echo ""

# USB device events
echo "[*] USB Device Events:"
dmesg | grep -i "usb" | tail -10
```

---

## USB Security Baseline

### USB Device Policy Script

```bash
#!/bin/bash
#######################################
# USB Device Control Setup
# Prevent unauthorized USB devices
#######################################

echo "[*] Configuring USB security..."

# Create udev rules for USB blocking
cat > /etc/udev/rules.d/10-usb-security.rules << 'EOF'
# Block all new USB storage devices
ACTION=="add", SUBSYSTEMS=="usb", DRIVERS=="usb-storage", \
    RUN+="/bin/sh -c 'echo 0 > /sys/$devpath/authorized'"

# Log all USB device connections
ACTION=="add", SUBSYSTEM=="usb", \
    RUN+="/usr/local/bin/log_usb.sh '%k' '%E{ID_VENDOR}' '%E{ID_MODEL}'"

# Allow specific trusted devices (example)
# ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="046d", ATTR{idProduct}=="c52b", GOTO="end"
EOF

# Create USB logging script
cat > /usr/local/bin/log_usb.sh << 'EOF'
#!/bin/bash
DEVICE="$1"
VENDOR="$2"
MODEL="$3"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] USB: Device=$DEVICE Vendor=$VENDOR Model=$MODEL" >> /var/log/usb_devices.log
EOF

chmod +x /usr/local/bin/log_usb.sh

# Reload udev rules
udevadm control --reload-rules

echo "[+] USB security configured"
echo "[*] Check logs: /var/log/usb_devices.log"
```

### USB Whitelist Management

```bash
#!/bin/bash
#######################################
# USB Device Whitelist Manager
#######################################

WHITELIST="/etc/usb_whitelist.conf"

show_menu() {
    echo ""
    echo "USB Whitelist Manager"
    echo "===================="
    echo "1. List current USB devices"
    echo "2. Show whitelist"
    echo "3. Add device to whitelist"
    echo "4. Remove from whitelist"
    echo "5. Apply whitelist"
    echo "6. Exit"
    echo ""
}

list_devices() {
    echo "[*] Currently connected USB devices:"
    lsusb
}

show_whitelist() {
    echo "[*] Whitelisted devices:"
    if [ -f "$WHITELIST" ]; then
        cat "$WHITELIST"
    else
        echo "    (none)"
    fi
}

add_device() {
    read -p "Enter VID:PID (e.g., 046d:c52b): " VIDPID
    read -p "Enter description: " DESC
    echo "$VIDPID # $DESC" >> "$WHITELIST"
    echo "[+] Added: $VIDPID"
}

apply_whitelist() {
    echo "[*] Generating udev rules from whitelist..."

    cat > /etc/udev/rules.d/99-usb-whitelist.rules << 'HEADER'
# USB Whitelist - Auto-generated
# Block all USB storage by default
ACTION=="add", SUBSYSTEMS=="usb", DRIVERS=="usb-storage", GOTO="check_whitelist"
GOTO="end"
LABEL="check_whitelist"
HEADER

    while IFS= read -r line; do
        VIDPID=$(echo "$line" | cut -d'#' -f1 | tr -d ' ')
        if [ -n "$VIDPID" ]; then
            VID=$(echo "$VIDPID" | cut -d':' -f1)
            PID=$(echo "$VIDPID" | cut -d':' -f2)
            echo "ATTR{idVendor}==\"$VID\", ATTR{idProduct}==\"$PID\", GOTO=\"end\"" >> /etc/udev/rules.d/99-usb-whitelist.rules
        fi
    done < "$WHITELIST"

    echo 'RUN+="/bin/sh -c '\''echo 0 > /sys/\$devpath/authorized'\''"' >> /etc/udev/rules.d/99-usb-whitelist.rules
    echo 'LABEL="end"' >> /etc/udev/rules.d/99-usb-whitelist.rules

    udevadm control --reload-rules
    echo "[+] Whitelist applied"
}

# Main loop
while true; do
    show_menu
    read -p "Select option: " choice
    case $choice in
        1) list_devices ;;
        2) show_whitelist ;;
        3) add_device ;;
        4) remove_device ;;
        5) apply_whitelist ;;
        6) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
done
```

---

## Network Baseline

### Establish Normal Traffic Baseline

```bash
#!/bin/bash
#######################################
# Network Baseline Script
# Capture normal traffic patterns
#######################################

BASELINE_DIR="/var/log/network_baseline"
DURATION="${1:-3600}"  # Default 1 hour

mkdir -p "$BASELINE_DIR"

echo "[*] Capturing network baseline for $DURATION seconds..."

# Capture connection states
echo "[*] Recording connection patterns..."
while [ $SECONDS -lt $DURATION ]; do
    ss -tulpn >> "$BASELINE_DIR/connections_$(date +%Y%m%d).log"
    sleep 60
done &

# Capture DNS queries
echo "[*] Recording DNS patterns..."
timeout $DURATION tcpdump -i any port 53 -w "$BASELINE_DIR/dns_$(date +%Y%m%d).pcap" &

# Capture HTTP/HTTPS
echo "[*] Recording web traffic patterns..."
timeout $DURATION tcpdump -i any "port 80 or port 443" -w "$BASELINE_DIR/web_$(date +%Y%m%d).pcap" &

wait

echo "[+] Baseline capture complete"
echo "[*] Files saved to: $BASELINE_DIR"

# Generate summary
echo ""
echo "[*] Connection Summary:"
cat "$BASELINE_DIR/connections_$(date +%Y%m%d).log" | \
    grep LISTEN | \
    sort -u
```

---

## Security Awareness Training Points

### BadUSB Warning Signs

```
TEACH USERS TO RECOGNIZE:

1. UNKNOWN USB DEVICES
   - Don't plug in found USB drives
   - Report unknown devices to security

2. UNEXPECTED BEHAVIOR
   - Command windows appearing
   - Rapid typing sounds
   - Screen flashing

3. SOCIAL ENGINEERING
   - "Free USB drive" giveaways
   - Devices left in common areas
   - "IT support" dropping off equipment

4. PHYSICAL SECURITY
   - Secure workstations when away
   - Lock screens (Win+L)
   - Report tailgating
```

### Security Awareness Script

```bash
#!/bin/bash
#######################################
# Security Awareness Quiz
# For training purposes
#######################################

SCORE=0
TOTAL=5

ask() {
    echo ""
    echo "Question $1: $2"
    echo "A) $3"
    echo "B) $4"
    echo "C) $5"
    read -p "Your answer (A/B/C): " answer
    if [ "${answer^^}" = "$6" ]; then
        echo "✓ Correct!"
        ((SCORE++))
    else
        echo "✗ Incorrect. The answer is $6"
        echo "Explanation: $7"
    fi
}

echo "================================"
echo "   USB Security Awareness Quiz"
echo "================================"

ask 1 "You find a USB drive in the parking lot. What should you do?" \
    "Plug it into your work computer to see what's on it" \
    "Give it to IT security without plugging it in" \
    "Plug it into your personal computer instead" \
    "B" "Unknown USB devices can contain malware that activates when plugged in."

ask 2 "Your computer suddenly opens a command window you didn't launch. What should you do?" \
    "Wait and see what happens" \
    "Immediately unplug any USB devices and report to IT" \
    "Close it and continue working" \
    "B" "This could indicate a BadUSB attack in progress."

ask 3 "What is a BadUSB device?" \
    "A broken USB drive" \
    "A USB device that pretends to be a keyboard to type malicious commands" \
    "A USB drive with viruses" \
    "B" "BadUSB devices impersonate keyboards to inject commands."

ask 4 "Someone claims to be from IT and asks to plug in a device. What do you do?" \
    "Let them, they're IT" \
    "Verify their identity and authorization with your manager or IT security" \
    "Watch them carefully while they work" \
    "B" "Always verify identity before allowing physical access."

ask 5 "Which is the safest USB practice?" \
    "Only use company-issued USB devices" \
    "Scan USB drives with antivirus before use" \
    "Use USB drives from trusted friends" \
    "A" "Company-issued devices are tracked and verified."

echo ""
echo "================================"
echo "   Score: $SCORE / $TOTAL"
echo "================================"

if [ $SCORE -eq $TOTAL ]; then
    echo "Excellent! Perfect score!"
elif [ $SCORE -ge 3 ]; then
    echo "Good job! Review the missed questions."
else
    echo "Please review USB security training materials."
fi
```

---

## Blue Team Checklist

### Daily Tasks

```
☐ Review security alerts
☐ Check critical system logs
☐ Verify backup completion
☐ Review user access logs
☐ Check for unusual processes
```

### Weekly Tasks

```
☐ Review USB device logs
☐ Analyze network traffic patterns
☐ Update threat intelligence
☐ Verify endpoint protection status
☐ Review privileged account usage
```

### Monthly Tasks

```
☐ Conduct security awareness reminder
☐ Review and update detection rules
☐ Test incident response procedures
☐ Audit user access rights
☐ Update baseline documentation
```

---

[← Back to Security Operations](../README.md)
