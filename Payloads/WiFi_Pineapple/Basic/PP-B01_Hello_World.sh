#!/bin/bash
#####################################################
# Payload: PP-B01 - Hello World
# Device:  WiFi Pineapple Pager
# Type:    User Payload
# Author:  Ducky_Bash Training Repository
# Version: 1.0
#
# Description:
# Simple test payload to verify Pager is working.
# Displays notifications and LED status.
#
# Documentation: Chapter_02/02_Basic_Payloads/PP-B01_Hello_World.md
#####################################################

# ===== CONFIGURATION =====
LOG_FILE="/root/loot/hello_world.log"

# ===== SETUP =====
# Create loot directory if needed
mkdir -p /root/loot

# ===== MAIN =====
# Visual feedback
LED BLUE
NOTIFY "Hello World starting..."

# Log our activity
echo "=== Hello World Payload ===" >> "$LOG_FILE"
echo "Run at: $(date)" >> "$LOG_FILE"
echo "Hostname: $(hostname)" >> "$LOG_FILE"
echo "Uptime: $(uptime)" >> "$LOG_FILE"

# Wait a moment
sleep 2

# Success notification
LED GREEN
NOTIFY "Hello World complete!"

# Show what we logged
echo "" >> "$LOG_FILE"
echo "Payload completed successfully" >> "$LOG_FILE"

# Return LED to normal
sleep 2
LED OFF

# Exit cleanly
exit 0
