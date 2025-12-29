#!/bin/bash
#######################################
# DT-02: Cron Persistence Detection - SOLUTION
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ALERTS=0

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     BLUE TEAM - Cron Persistence Detection                 ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check user crontab
echo -e "${YELLOW}[*] Checking user crontab...${NC}"
CRON_CONTENT=$(crontab -l 2>/dev/null)

if [ -n "$CRON_CONTENT" ]; then
    echo "Current crontab entries:"
    echo "$CRON_CONTENT"
    echo ""

    # Check for suspicious patterns
    if echo "$CRON_CONTENT" | grep -qE "/tmp/\.|/\.[a-z]|hidden|persist|beacon"; then
        echo -e "${RED}[ALERT] Suspicious cron entry detected!${NC}"
        SUSPICIOUS_ENTRY=$(echo "$CRON_CONTENT" | grep -E "/tmp/\.|/\.[a-z]|hidden|persist|beacon")
        echo -e "${RED}  → $SUSPICIOUS_ENTRY${NC}"
        ((ALERTS++))

        # Extract script path
        SCRIPT_PATH=$(echo "$SUSPICIOUS_ENTRY" | grep -oE '/[^ ]+\.sh' | head -1)
        if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
            echo ""
            echo -e "${YELLOW}[*] Analyzing persistence script: $SCRIPT_PATH${NC}"
            echo "Content:"
            cat "$SCRIPT_PATH"
            echo ""

            # Check for flags
            FLAG=$(grep -o "FLAG{[^}]*}" "$SCRIPT_PATH" 2>/dev/null)
            if [ -n "$FLAG" ]; then
                echo -e "${GREEN}[CTF] Found: $FLAG${NC}"
            fi
        fi
    fi
else
    echo -e "${GREEN}[OK] No crontab entries${NC}"
fi

# Check for beacon logs
echo ""
echo -e "${YELLOW}[*] Checking for beacon activity logs...${NC}"
if [ -f "/tmp/.beacon.log" ]; then
    echo -e "${RED}[ALERT] Beacon log found!${NC}"
    echo "Content:"
    cat /tmp/.beacon.log
    ((ALERTS++))
fi

# Summary
echo ""
echo "─────────────────────────────────────────────────────"
if [ $ALERTS -gt 0 ]; then
    echo -e "${RED}[!] Total alerts: $ALERTS${NC}"
    echo -e "${RED}[!] Persistence mechanism detected!${NC}"
    echo ""
    echo -e "${YELLOW}Cleanup commands:${NC}"
    echo "  crontab -r  # Remove all cron entries (careful!)"
    echo "  rm /tmp/.persistence.sh /tmp/.beacon.log"
else
    echo -e "${GREEN}[✓] No cron persistence detected${NC}"
fi
