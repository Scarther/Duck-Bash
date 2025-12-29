#!/bin/bash
#######################################
# Basic Level Blue Team Forensics Tool
# Purpose: Help investigate BadUSB attacks
# Level: Basic
#######################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          BLUE TEAM - BASIC FORENSICS TOOLKIT               ║${NC}"
echo -e "${BLUE}║          CTF Investigation Assistant                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

show_menu() {
    echo -e "${CYAN}Select an investigation option:${NC}"
    echo ""
    echo "  1) Find recently modified files"
    echo "  2) Find hidden files in common locations"
    echo "  3) Check command history"
    echo "  4) Check scheduled tasks (cron)"
    echo "  5) Search for archive files"
    echo "  6) Check USB device logs"
    echo "  7) Search for FLAG strings"
    echo "  8) Run all checks"
    echo "  9) Exit"
    echo ""
    echo -n "Choice: "
}

find_recent_files() {
    echo -e "\n${YELLOW}[*] Finding files modified in the last 60 minutes...${NC}"
    echo "─────────────────────────────────────────────────────"
    find /tmp /var/tmp "$HOME" -mmin -60 -type f 2>/dev/null | head -20
    echo "─────────────────────────────────────────────────────"
}

find_hidden_files() {
    echo -e "\n${YELLOW}[*] Finding hidden files in common locations...${NC}"
    echo "─────────────────────────────────────────────────────"
    echo -e "${CYAN}In /tmp:${NC}"
    ls -la /tmp/.[!.]* 2>/dev/null || echo "  No hidden files found"
    echo ""
    echo -e "${CYAN}In /var/tmp:${NC}"
    ls -la /var/tmp/.[!.]* 2>/dev/null || echo "  No hidden files found"
    echo ""
    echo -e "${CYAN}In home directory:${NC}"
    ls -la "$HOME"/.[!.]* 2>/dev/null | grep -v ".bash\|.profile\|.cache\|.config\|.local" | head -10
    echo "─────────────────────────────────────────────────────"
}

check_history() {
    echo -e "\n${YELLOW}[*] Checking command history...${NC}"
    echo "─────────────────────────────────────────────────────"
    if [ -f "$HOME/.bash_history" ]; then
        echo -e "${CYAN}Last 20 commands:${NC}"
        tail -20 "$HOME/.bash_history"
    else
        echo "No bash history found"
    fi
    echo "─────────────────────────────────────────────────────"
}

check_cron() {
    echo -e "\n${YELLOW}[*] Checking scheduled tasks...${NC}"
    echo "─────────────────────────────────────────────────────"
    echo -e "${CYAN}User crontab:${NC}"
    crontab -l 2>/dev/null || echo "  No user crontab"
    echo ""
    echo -e "${CYAN}System cron.d:${NC}"
    ls -la /etc/cron.d/ 2>/dev/null
    echo ""
    echo -e "${CYAN}Suspicious entries in cron.d:${NC}"
    grep -r "tmp\|hidden\|\.sh" /etc/cron.d/ 2>/dev/null || echo "  None found"
    echo "─────────────────────────────────────────────────────"
}

find_archives() {
    echo -e "\n${YELLOW}[*] Searching for archive files...${NC}"
    echo "─────────────────────────────────────────────────────"
    echo -e "${CYAN}Archive files in temp locations:${NC}"
    find /tmp /var/tmp -name "*.tar.gz" -o -name "*.zip" -o -name "*.7z" -o -name "*.tar" 2>/dev/null
    echo ""
    echo -e "${CYAN}Hidden archives:${NC}"
    find /tmp /var/tmp -name ".*" -type f 2>/dev/null | xargs file 2>/dev/null | grep -i "archive\|compressed\|gzip"
    echo "─────────────────────────────────────────────────────"
}

check_usb_logs() {
    echo -e "\n${YELLOW}[*] Checking USB device logs...${NC}"
    echo "─────────────────────────────────────────────────────"
    echo -e "${CYAN}Dmesg USB entries:${NC}"
    dmesg 2>/dev/null | grep -i "usb\|hid" | tail -15
    echo ""
    echo -e "${CYAN}Custom USB logs:${NC}"
    if [ -f /var/log/usb_forensics.log ]; then
        cat /var/log/usb_forensics.log
    elif [ -f /var/log/usb_activity.log ]; then
        cat /var/log/usb_activity.log
    else
        echo "  No custom USB logs found"
    fi
    echo "─────────────────────────────────────────────────────"
}

search_flags() {
    echo -e "\n${YELLOW}[*] Searching for FLAG strings...${NC}"
    echo "─────────────────────────────────────────────────────"
    echo -e "${RED}Searching common locations for 'FLAG{' pattern...${NC}"
    grep -r "FLAG{" /tmp /var/tmp /var/log "$HOME" 2>/dev/null | head -10
    echo ""
    echo -e "${CYAN}Checking base64 encoded strings:${NC}"
    find /tmp -type f 2>/dev/null | while read -r file; do
        if grep -q "RkxBR" "$file" 2>/dev/null; then
            echo "  Possible base64 flag in: $file"
        fi
    done
    echo "─────────────────────────────────────────────────────"
}

run_all() {
    find_recent_files
    find_hidden_files
    check_history
    check_cron
    find_archives
    check_usb_logs
    search_flags
}

# Main loop
while true; do
    show_menu
    read -r choice

    case $choice in
        1) find_recent_files ;;
        2) find_hidden_files ;;
        3) check_history ;;
        4) check_cron ;;
        5) find_archives ;;
        6) check_usb_logs ;;
        7) search_flags ;;
        8) run_all ;;
        9) echo -e "${GREEN}Exiting. Good luck with your investigation!${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac

    echo ""
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          BLUE TEAM - BASIC FORENSICS TOOLKIT               ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
done
