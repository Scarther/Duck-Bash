#!/bin/bash
#######################################
# DT-02: Cron Persistence - DEFENSE
# YOUR TASK: Complete this script
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ALERTS=0

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     BLUE TEAM - Cron Persistence Detection                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# === YOUR CODE STARTS HERE ===

# 1. Check user crontab for suspicious entries
echo -e "${YELLOW}[*] Checking user crontab...${NC}"
# TODO: Get crontab content and look for:
#   - Hidden scripts (paths with /.)
#   - Temp directory scripts (/tmp/)
#   - Suspicious keywords (beacon, persist, etc.)

# CRON_CONTENT=$(crontab -l 2>/dev/null)
# if echo "$CRON_CONTENT" | grep -qE "pattern"; then
#     echo -e "${RED}[ALERT] Suspicious cron entry!${NC}"
#     ((ALERTS++))
# fi

# 2. Find the persistence script and analyze it
# TODO: If suspicious cron found, find and analyze the script

# 3. Check for beacon log files
# TODO: Look for /tmp/.beacon.log or similar

# === YOUR CODE ENDS HERE ===

# Summary
echo ""
if [ $ALERTS -gt 0 ]; then
    echo -e "${RED}[!] Persistence detected! Alerts: $ALERTS${NC}"
else
    echo -e "${GREEN}[✓] No cron persistence found${NC}"
fi
