#!/bin/bash
#######################################
# Blue Team Script: Detect Scheduled Task Persistence
# Counters: RT-02 Scheduled Task Persistence
# MITRE D3FEND: D3-SJA (Scheduled Job Analysis)
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     BLUE TEAM - Scheduled Task Detection                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

ALERTS=0

# Known suspicious task name patterns
SUSPICIOUS_PATTERNS=(
    "Update"
    "Sync"
    "Service"
    "Helper"
    "System"
    "Microsoft"
    "Windows"
)

# Function: Analyze user crontab
analyze_user_crontab() {
    echo -e "${YELLOW}[*] Analyzing user crontab...${NC}"

    CRON=$(crontab -l 2>/dev/null)

    if [ -n "$CRON" ]; then
        echo "Current user crontab entries:"
        echo "$CRON"
        echo ""

        # Check for suspicious patterns
        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            if echo "$CRON" | grep -qi "$pattern"; then
                echo -e "${YELLOW}[WARNING] Task contains '$pattern' - review carefully${NC}"
            fi
        done

        # Check for hidden scripts
        if echo "$CRON" | grep -qE "\./\.|/tmp/\.|hidden"; then
            echo -e "${RED}[ALERT] Cron references hidden files!${NC}"
            ((ALERTS++))
        fi

        # Check for network activity
        if echo "$CRON" | grep -qE "curl|wget|nc|python.*http"; then
            echo -e "${RED}[ALERT] Cron has network activity!${NC}"
            ((ALERTS++))
        fi
    else
        echo -e "${GREEN}[OK] No user crontab entries${NC}"
    fi
}

# Function: Analyze system cron
analyze_system_cron() {
    echo -e "${YELLOW}[*] Analyzing system cron directories...${NC}"

    # Check cron.d
    echo "Checking /etc/cron.d/:"
    for file in /etc/cron.d/*; do
        if [ -f "$file" ]; then
            name=$(basename "$file")
            mod_time=$(stat -c %y "$file" 2>/dev/null | cut -d' ' -f1)
            echo "  [$mod_time] $name"

            # Check content for suspicious patterns
            if grep -qE "powershell|hidden|base64|curl.*\|.*bash" "$file" 2>/dev/null; then
                echo -e "${RED}    [ALERT] Suspicious content detected!${NC}"
                ((ALERTS++))
            fi
        fi
    done

    # Check for recently added cron files
    echo ""
    echo "Recently modified cron files (last 7 days):"
    find /etc/cron* -type f -mtime -7 2>/dev/null | while read -r file; do
        echo -e "  ${YELLOW}$file${NC}"
    done
}

# Function: Analyze systemd timers
analyze_systemd_timers() {
    echo -e "${YELLOW}[*] Analyzing systemd timers...${NC}"

    echo "Active timers:"
    systemctl list-timers --all 2>/dev/null | head -15

    echo ""
    echo "User-level timers:"
    systemctl --user list-timers --all 2>/dev/null | head -10

    # Check for custom user services
    echo ""
    echo "Custom user services:"
    ls -la ~/.config/systemd/user/*.service 2>/dev/null || echo "  None found"
    ls -la ~/.config/systemd/user/*.timer 2>/dev/null || echo "  No user timers"
}

# Function: Analyze at jobs
analyze_at_jobs() {
    echo -e "${YELLOW}[*] Analyzing at jobs...${NC}"

    if command -v atq &> /dev/null; then
        JOBS=$(atq 2>/dev/null)
        if [ -n "$JOBS" ]; then
            echo "Pending at jobs:"
            echo "$JOBS"
            ((ALERTS++))
        else
            echo -e "${GREEN}[OK] No pending at jobs${NC}"
        fi
    else
        echo "at command not available"
    fi
}

# Function: Generate YARA rule
generate_yara_rule() {
    echo -e "${YELLOW}[*] YARA Rule for Scheduled Task Detection:${NC}"
    cat << 'EOF'
rule Suspicious_Scheduled_Task_Content {
    meta:
        description = "Detects suspicious scheduled task configurations"
        author = "Blue Team"

    strings:
        $hidden1 = "-w hidden" ascii wide
        $hidden2 = "-WindowStyle Hidden" ascii wide
        $bypass = "-ep bypass" ascii wide
        $encoded = "-enc" ascii wide
        $download = "DownloadString" ascii wide
        $iex = "IEX" ascii wide

    condition:
        2 of them
}
EOF
}

# Function: Show hunting queries
show_hunting_queries() {
    echo ""
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║              THREAT HUNTING QUERIES                        ║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"

    echo ""
    echo "Splunk Query - Suspicious Task Creation:"
    echo '  index=windows EventCode=4698 | search TaskContent="*hidden*" OR TaskContent="*bypass*"'

    echo ""
    echo "Elastic Query - New Scheduled Tasks:"
    echo '  event.code: 4698 AND winlog.event_data.TaskContent: (*hidden* OR *powershell*)'

    echo ""
    echo "Linux - Find suspicious cron entries:"
    echo '  grep -r "curl\|wget\|base64\|hidden" /etc/cron* /var/spool/cron/'
}

# Main execution
echo -e "${BLUE}Starting scheduled task analysis...${NC}"
echo "─────────────────────────────────────────────────────"

analyze_user_crontab
echo ""
analyze_system_cron
echo ""
analyze_systemd_timers
echo ""
analyze_at_jobs
echo ""

# Summary
echo "─────────────────────────────────────────────────────"
if [ $ALERTS -gt 0 ]; then
    echo -e "${RED}[!] Total alerts: $ALERTS${NC}"
    echo -e "${RED}[!] Suspicious scheduled tasks detected!${NC}"
else
    echo -e "${GREEN}[✓] No suspicious scheduled tasks found${NC}"
fi

echo ""
echo -e "${YELLOW}Show threat hunting queries? (y/n)${NC}"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    show_hunting_queries
fi
