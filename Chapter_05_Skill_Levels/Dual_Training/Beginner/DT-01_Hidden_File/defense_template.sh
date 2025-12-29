#!/bin/bash
#######################################
# DT-01: Hidden File Dropper - DEFENSE
# YOUR TASK: Complete this script
#
# Requirements:
# - Find hidden files in /tmp
# - Check if they were recently created
# - Analyze content for suspicious patterns
# - Print colored alerts
#######################################

# Colors (provided for you)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Alert counter
ALERTS=0

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     BLUE TEAM - Hidden File Detection                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# === YOUR CODE STARTS HERE ===

# 1. Find hidden files in /tmp
# Hint: Use find command with -name ".*" -type f
echo -e "${YELLOW}[*] Searching for hidden files in /tmp...${NC}"

# TODO: Store the find results in a variable
# HIDDEN_FILES=$(find ...)

# 2. Loop through each found file
# TODO: Complete the loop
# for file in $HIDDEN_FILES; do
#     echo "Found: $file"
#
#     # 3. Check if file was created recently (within last hour)
#     # Hint: Use find with -mmin -60 or stat command
#
#     # 4. Check content for suspicious patterns
#     # Hint: Use grep to look for keywords like "payload", "beacon", etc.
#
#     # 5. If suspicious, increment ALERTS and print alert
#     # echo -e "${RED}[ALERT] Suspicious file: $file${NC}"
#     # ((ALERTS++))
# done

# === YOUR CODE ENDS HERE ===

# Summary (don't modify this)
echo ""
echo "─────────────────────────────────────────────────────"
if [ $ALERTS -gt 0 ]; then
    echo -e "${RED}[!] Total alerts: $ALERTS${NC}"
    echo -e "${RED}[!] Suspicious activity detected!${NC}"
    exit 1
else
    echo -e "${GREEN}[✓] No suspicious files found${NC}"
    exit 0
fi
