# PP-B01: Hello World

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-B01 |
| **Name** | Hello World |
| **Difficulty** | Basic |
| **Type** | Test |
| **Purpose** | Verify device functionality |

## What This Payload Does

The simplest WiFi Pineapple payload - verifies the device is working correctly, tests script execution, and familiarizes you with the Pineapple environment.

---

## Understanding the Pineapple

```
┌─────────────────────────────────────────────────────────────┐
│              WiFi PINEAPPLE ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────────┐     ┌──────────────┐                     │
│   │   wlan0      │     │    wlan1     │                     │
│   │ (Management) │     │  (Monitor)   │                     │
│   └──────────────┘     └──────────────┘                     │
│          │                    │                              │
│          ▼                    ▼                              │
│   ┌──────────────────────────────────────┐                  │
│   │         OpenWrt Linux System          │                  │
│   ├──────────────────────────────────────┤                  │
│   │  /root/             - Home directory  │                  │
│   │  /sd/               - SD card mount   │                  │
│   │  /pineapple/        - Core files      │                  │
│   │  /tmp/              - Temp storage    │                  │
│   └──────────────────────────────────────┘                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-B01
# Name: Hello World
# Description: Basic functionality test
# Author: Security Training
#

# ============================================
# CONFIGURATION
# ============================================
OUTPUT_FILE="/tmp/pp-b01-output.txt"
LOG_FILE="/tmp/pp-b01.log"

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# ============================================
# MAIN EXECUTION
# ============================================
log "Starting PP-B01: Hello World"

# Clear previous output
> "$OUTPUT_FILE"

# Basic system information
echo "========================================" >> "$OUTPUT_FILE"
echo "       WiFi PINEAPPLE HELLO WORLD       " >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Hostname
echo "Hostname: $(hostname)" >> "$OUTPUT_FILE"

# Current user
echo "User: $(whoami)" >> "$OUTPUT_FILE"

# Date/Time
echo "Date: $(date)" >> "$OUTPUT_FILE"

# Uptime
echo "Uptime: $(uptime -p 2>/dev/null || uptime)" >> "$OUTPUT_FILE"

# Kernel version
echo "Kernel: $(uname -r)" >> "$OUTPUT_FILE"

# Architecture
echo "Arch: $(uname -m)" >> "$OUTPUT_FILE"

# Available memory
echo "Memory: $(free -m 2>/dev/null | awk '/Mem:/{print $2"MB total, "$3"MB used"}')" >> "$OUTPUT_FILE"

# Disk space
echo "Storage: $(df -h / | awk 'NR==2{print $4 " available"}')" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
echo "       PAYLOAD EXECUTED SUCCESSFULLY    " >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"

# Display output
cat "$OUTPUT_FILE"

log "PP-B01 completed successfully"

# LED indicator (if available)
if [ -f /sys/class/leds/pineapple:blue:system/brightness ]; then
    echo 1 > /sys/class/leds/pineapple:blue:system/brightness
    sleep 1
    echo 0 > /sys/class/leds/pineapple:blue:system/brightness
fi

exit 0
```

---

## Line-by-Line Breakdown

### Header Section
```bash
#!/bin/bash
```
**Shebang line** - Tells the system to use Bash interpreter. On Pineapple, this is typically `/bin/bash` or `/bin/sh`.

### Configuration Variables
```bash
OUTPUT_FILE="/tmp/pp-b01-output.txt"
LOG_FILE="/tmp/pp-b01.log"
```
- `/tmp/` is RAM-based storage on Pineapple - fast but non-persistent
- Always define output paths at top for easy modification

### Logging Function
```bash
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}
```
- Custom function for timestamped logging
- `tee -a` writes to both screen and file
- `-a` appends instead of overwriting

### Information Gathering
```bash
hostname
whoami
date
uptime -p
uname -r
uname -m
free -m
df -h /
```
Each command gathers different system information:
| Command | Output |
|---------|--------|
| `hostname` | Device name |
| `whoami` | Current user (usually root) |
| `date` | Current date/time |
| `uptime -p` | How long device has been running |
| `uname -r` | Kernel version |
| `uname -m` | Architecture (mips, arm, etc.) |
| `free -m` | Memory usage in MB |
| `df -h /` | Disk space on root partition |

### LED Feedback
```bash
echo 1 > /sys/class/leds/pineapple:blue:system/brightness
```
- Controls hardware LED through sysfs interface
- Provides visual confirmation of payload execution
- Path varies by Pineapple model

---

## Directory Structure

```
WiFi Pineapple Filesystem:
/
├── root/                    # Home directory
│   └── payloads/           # Your payloads go here
├── sd/                      # External SD card
│   ├── loot/               # Captured data
│   └── payloads/           # Additional payloads
├── pineapple/               # Core system
│   ├── api/                # REST API
│   ├── modules/            # Installed modules
│   └── components/         # UI components
├── tmp/                     # Temporary (RAM)
├── etc/                     # Configuration files
└── var/                     # Variable data
    └── log/                # System logs
```

---

## Running the Payload

### Method 1: SSH Execution
```bash
# Connect to Pineapple
ssh root@172.16.42.1

# Make script executable
chmod +x /root/payloads/PP-B01_Hello_World.sh

# Run it
./root/payloads/PP-B01_Hello_World.sh
```

### Method 2: Web Interface
1. Access `http://172.16.42.1:1471`
2. Navigate to Payloads module
3. Upload or paste script
4. Click Execute

### Method 3: Cron Job
```bash
# Edit crontab
crontab -e

# Add entry (run at boot)
@reboot /root/payloads/PP-B01_Hello_World.sh
```

---

## Expected Output

```
========================================
       WiFi PINEAPPLE HELLO WORLD
========================================

Hostname: Pineapple
User: root
Date: Mon Dec 28 15:30:45 UTC 2025
Uptime: up 2 hours, 15 minutes
Kernel: 4.14.171
Arch: mips
Memory: 128MB total, 45MB used
Storage: 12M available

========================================
       PAYLOAD EXECUTED SUCCESSFULLY
========================================
```

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Permission denied | Script not executable | `chmod +x script.sh` |
| Command not found | Missing utility | Install with `opkg install` |
| No space left | /tmp full | Clear temp files or use SD |
| LED not working | Wrong path | Check your Pineapple model |

---

## Variations

### Minimal Version
```bash
#!/bin/bash
echo "Hello from WiFi Pineapple!"
hostname
date
```

### Verbose Version
```bash
#!/bin/bash
echo "=== Complete System Information ==="
cat /proc/version
cat /proc/cpuinfo
cat /proc/meminfo
ip addr
iwconfig 2>/dev/null
```

### Network-Focused Version
```bash
#!/bin/bash
echo "=== Network Status ==="
ip addr show
ip route
cat /etc/resolv.conf
ping -c 1 8.8.8.8 2>/dev/null && echo "Internet: Connected" || echo "Internet: Disconnected"
```

---

## Practice Exercises

### Exercise 1: Add More Info
Modify the script to also display:
- Number of connected clients
- Current WiFi channel
- Available disk space on SD card

### Exercise 2: Create Alert
Add a notification feature:
```bash
# Send to notification endpoint
curl -s "http://your-server/notify?msg=Pineapple+Online"
```

### Exercise 3: Persistent Logging
Modify to log to SD card instead of /tmp for persistence.

---

## Red Team Notes

- Use Hello World to verify Pineapple is operational before field deployment
- LED flash can confirm execution without screen access
- Logs help troubleshoot issues in the field
- Test all payloads in lab before real operations

## Blue Team Notes

- Unknown devices with hostname "Pineapple" are obvious indicators
- Monitor for new devices on network segments
- Watch for unusual SSH connections to 172.16.42.1
- Log analysis can reveal Pineapple presence

---

[← Back to Basic Payloads](README.md) | [Next: PP-B02 Handshake Alert →](PP-B02_Handshake_Alert.md)
