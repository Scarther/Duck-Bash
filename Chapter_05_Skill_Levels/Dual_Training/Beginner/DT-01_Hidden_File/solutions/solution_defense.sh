#!/bin/bash
#######################################
# DT-01: Hidden File Detection - SOLUTION
# This is the reference solution
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ALERTS=0

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     BLUE TEAM - Hidden File Detection                      ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Suspicious patterns to look for
SUSPICIOUS_PATTERNS="payload|beacon|exfil|c2|backdoor|malware|FLAG{"

# 1. Find hidden files in /tmp created in last hour
echo -e "${YELLOW}[*] Searching for hidden files in /tmp (created in last hour)...${NC}"
HIDDEN_FILES=$(find /tmp -maxdepth 1 -name ".*" -type f -mmin -60 2>/dev/null)

if [ -z "$HIDDEN_FILES" ]; then
    echo -e "${GREEN}[OK] No recently created hidden files found${NC}"
else
    echo -e "${YELLOW}[!] Found hidden files:${NC}"

    # 2. Loop through each found file
    for file in $HIDDEN_FILES; do
        echo ""
        echo -e "${CYAN}Analyzing: $file${NC}"

        # Get file info
        SIZE=$(stat -c%s "$file" 2>/dev/null || echo "unknown")
        MODIFIED=$(stat -c%y "$file" 2>/dev/null | cut -d'.' -f1)
        echo "  Size: $SIZE bytes"
        echo "  Modified: $MODIFIED"

        # 3. Check content for suspicious patterns
        MATCHES=$(grep -iE "$SUSPICIOUS_PATTERNS" "$file" 2>/dev/null)

        if [ -n "$MATCHES" ]; then
            echo -e "${RED}[ALERT] Suspicious content detected!${NC}"
            echo -e "${RED}  Matched patterns:${NC}"
            echo "$MATCHES" | while read -r line; do
                echo -e "    ${RED}→ $line${NC}"
            done
            ((ALERTS++))

            # 4. Extract and display any flags
            FLAG=$(grep -o "FLAG{[^}]*}" "$file" 2>/dev/null)
            if [ -n "$FLAG" ]; then
                echo -e "${GREEN}  [CTF] Found flag: $FLAG${NC}"
            fi
        else
            echo -e "${YELLOW}  [INFO] No suspicious patterns in content${NC}"
        fi
    done
fi

# Summary
echo ""
echo "─────────────────────────────────────────────────────"
if [ $ALERTS -gt 0 ]; then
    echo -e "${RED}[!] Total alerts: $ALERTS${NC}"
    echo -e "${RED}[!] Suspicious activity detected!${NC}"
    echo ""
    echo -e "${YELLOW}Recommended Actions:${NC}"
    echo "  1. Quarantine suspicious files"
    echo "  2. Investigate creation source"
    echo "  3. Check for related processes"
    echo "  4. Review system logs"
    exit 1
else
    echo -e "${GREEN}[✓] No suspicious files found${NC}"
    exit 0
fi
