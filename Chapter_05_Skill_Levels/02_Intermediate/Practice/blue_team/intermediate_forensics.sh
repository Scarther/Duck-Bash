#!/bin/bash
#######################################
# Intermediate Level Blue Team Forensics Tool
# Purpose: Advanced investigation capabilities
# Level: Intermediate
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

clear
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       BLUE TEAM - INTERMEDIATE FORENSICS TOOLKIT          ║${NC}"
echo -e "${BLUE}║       Advanced Investigation Capabilities                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

show_menu() {
    echo -e "${CYAN}Select an investigation module:${NC}"
    echo ""
    echo -e "  ${MAGENTA}=== Encoding Analysis ===${NC}"
    echo "  1) Detect and decode base64 content"
    echo "  2) Find hex-encoded strings"
    echo "  3) Decode multi-layer encoding"
    echo ""
    echo -e "  ${MAGENTA}=== Credential Analysis ===${NC}"
    echo "  4) Find credential harvesting evidence"
    echo "  5) Check for staged credential files"
    echo ""
    echo -e "  ${MAGENTA}=== Network Analysis ===${NC}"
    echo "  6) Find beacon configurations"
    echo "  7) Check for C2 indicators"
    echo ""
    echo -e "  ${MAGENTA}=== Persistence Analysis ===${NC}"
    echo "  8) Full persistence scan"
    echo "  9) Check all startup locations"
    echo ""
    echo -e "  ${MAGENTA}=== Memory/Runtime ===${NC}"
    echo "  10) Check environment variables"
    echo "  11) Scan /dev/shm for artifacts"
    echo ""
    echo "  12) Search for all FLAGS"
    echo "  13) Run comprehensive scan"
    echo "  0) Exit"
    echo ""
    echo -n "Choice: "
}

decode_base64() {
    echo -e "\n${YELLOW}[*] Scanning for base64 content...${NC}"
    echo "─────────────────────────────────────────────────────"

    for file in $(find /tmp -type f 2>/dev/null); do
        if file "$file" 2>/dev/null | grep -q "text\|ASCII"; then
            # Check for base64 patterns
            if grep -qE '^[A-Za-z0-9+/]{20,}={0,2}$' "$file" 2>/dev/null; then
                echo -e "${CYAN}Possible base64 in: $file${NC}"
                echo "Content preview:"
                head -3 "$file"
                echo ""
                echo "Attempting decode:"
                cat "$file" | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$' | head -1 | base64 -d 2>/dev/null
                echo ""
            fi
        fi
    done
    echo "─────────────────────────────────────────────────────"
}

find_hex() {
    echo -e "\n${YELLOW}[*] Scanning for hex-encoded strings...${NC}"
    echo "─────────────────────────────────────────────────────"

    for file in $(find /tmp -type f 2>/dev/null); do
        if grep -qE '^[0-9a-fA-F]{20,}$' "$file" 2>/dev/null; then
            echo -e "${CYAN}Possible hex encoding in: $file${NC}"
            HEX=$(grep -E '^[0-9a-fA-F]{20,}$' "$file" | head -1)
            echo "Hex: ${HEX:0:50}..."
            echo "Decoded: $(echo "$HEX" | xxd -r -p 2>/dev/null)"
        fi
    done
    echo "─────────────────────────────────────────────────────"
}

multilayer_decode() {
    echo -e "\n${YELLOW}[*] Attempting multi-layer decode...${NC}"
    echo "─────────────────────────────────────────────────────"

    if [ -f /tmp/.encoded_payload ]; then
        echo -e "${CYAN}Found encoded payload, decoding layers:${NC}"
        echo ""
        echo "Layer 0 (Original):"
        cat /tmp/.encoded_payload | grep -v "^#" | head -1
        echo ""

        echo "Layer 1 (Base64 decode):"
        LAYER1=$(cat /tmp/.encoded_payload | grep -v "^#" | head -1 | base64 -d 2>/dev/null)
        echo "$LAYER1"
        echo ""

        echo "Layer 2 (Hex decode):"
        echo "$LAYER1" | xxd -r -p 2>/dev/null
        echo ""
    else
        echo "No multi-layer encoded file found at expected location"
    fi
    echo "─────────────────────────────────────────────────────"
}

find_credentials() {
    echo -e "\n${YELLOW}[*] Searching for credential harvesting evidence...${NC}"
    echo "─────────────────────────────────────────────────────"

    echo -e "${CYAN}Credential-related files:${NC}"
    find /tmp -name "*cred*" -o -name "*pass*" -o -name "*harvest*" 2>/dev/null

    echo ""
    echo -e "${CYAN}JSON files with password content:${NC}"
    grep -l "password\|credential" /tmp/*.json 2>/dev/null

    echo ""
    echo -e "${CYAN}Scripts that access credential locations:${NC}"
    grep -r "Login Data\|passwords.txt\|credentials" /tmp/*.sh 2>/dev/null
    echo "─────────────────────────────────────────────────────"
}

find_staged_creds() {
    echo -e "\n${YELLOW}[*] Checking for staged credentials...${NC}"
    echo "─────────────────────────────────────────────────────"

    for file in /tmp/.harvested_creds.json /tmp/.credentials.json /tmp/.creds.txt; do
        if [ -f "$file" ]; then
            echo -e "${RED}[!] Found: $file${NC}"
            echo "Content:"
            cat "$file"
            echo ""
        fi
    done
    echo "─────────────────────────────────────────────────────"
}

find_beacons() {
    echo -e "\n${YELLOW}[*] Searching for beacon configurations...${NC}"
    echo "─────────────────────────────────────────────────────"

    echo -e "${CYAN}Potential beacon scripts:${NC}"
    find /tmp -name "*beacon*" -o -name "*c2*" 2>/dev/null

    echo ""
    echo -e "${CYAN}Cron entries with network activity:${NC}"
    grep -r "curl\|wget\|nc\|beacon" /etc/cron.d/ 2>/dev/null
    crontab -l 2>/dev/null | grep -i "curl\|wget\|http"

    echo ""
    echo -e "${CYAN}Config files with server addresses:${NC}"
    grep -r "server\|port\|c2" /tmp/*.json 2>/dev/null
    echo "─────────────────────────────────────────────────────"
}

check_c2() {
    echo -e "\n${YELLOW}[*] Checking for C2 indicators...${NC}"
    echo "─────────────────────────────────────────────────────"

    if [ -f /tmp/.c2_config.json ]; then
        echo -e "${RED}[!] C2 Configuration found:${NC}"
        cat /tmp/.c2_config.json
    fi

    if [ -f /tmp/.beacon.log ]; then
        echo -e "${RED}[!] Beacon log found:${NC}"
        cat /tmp/.beacon.log
    fi
    echo "─────────────────────────────────────────────────────"
}

full_persistence_scan() {
    echo -e "\n${YELLOW}[*] Full persistence scan...${NC}"
    echo "─────────────────────────────────────────────────────"

    echo -e "${CYAN}1. Checking bashrc/profile:${NC}"
    grep -v "^#" ~/.bashrc 2>/dev/null | grep -v "^$" | tail -10
    echo ""

    echo -e "${CYAN}2. User crontab:${NC}"
    crontab -l 2>/dev/null
    echo ""

    echo -e "${CYAN}3. System cron.d:${NC}"
    ls -la /etc/cron.d/
    echo ""

    echo -e "${CYAN}4. Systemd user services:${NC}"
    ls -la ~/.config/systemd/user/ 2>/dev/null
    for svc in ~/.config/systemd/user/*.service; do
        if [ -f "$svc" ]; then
            echo -e "${YELLOW}Service: $svc${NC}"
            cat "$svc"
        fi
    done
    echo ""

    echo -e "${CYAN}5. Authorized keys:${NC}"
    cat ~/.ssh/authorized_keys 2>/dev/null || echo "No authorized_keys file"
    echo "─────────────────────────────────────────────────────"
}

check_env() {
    echo -e "\n${YELLOW}[*] Checking environment variables...${NC}"
    echo "─────────────────────────────────────────────────────"
    env | grep -iE "secret|key|token|pass|flag|c2|beacon" || echo "No suspicious variables found"
    echo "─────────────────────────────────────────────────────"
}

check_shm() {
    echo -e "\n${YELLOW}[*] Scanning /dev/shm...${NC}"
    echo "─────────────────────────────────────────────────────"
    ls -la /dev/shm/
    echo ""
    for file in /dev/shm/.*; do
        if [ -f "$file" ]; then
            echo -e "${CYAN}Hidden file: $file${NC}"
            cat "$file" 2>/dev/null
            echo ""
        fi
    done
    echo "─────────────────────────────────────────────────────"
}

search_flags() {
    echo -e "\n${YELLOW}[*] Comprehensive FLAG search...${NC}"
    echo "─────────────────────────────────────────────────────"

    echo -e "${RED}Searching all locations for FLAG patterns...${NC}"
    echo ""

    LOCATIONS="/tmp /var/tmp /var/log /dev/shm $HOME"
    for loc in $LOCATIONS; do
        FLAGS=$(grep -r "FLAG{" "$loc" 2>/dev/null)
        if [ -n "$FLAGS" ]; then
            echo -e "${GREEN}Found in $loc:${NC}"
            echo "$FLAGS"
            echo ""
        fi
    done

    # Check crontab
    CRON_FLAG=$(crontab -l 2>/dev/null | grep "FLAG{")
    if [ -n "$CRON_FLAG" ]; then
        echo -e "${GREEN}Found in crontab:${NC}"
        echo "$CRON_FLAG"
    fi

    # Check bashrc
    BASHRC_FLAG=$(grep "FLAG{" ~/.bashrc 2>/dev/null)
    if [ -n "$BASHRC_FLAG" ]; then
        echo -e "${GREEN}Found in bashrc:${NC}"
        echo "$BASHRC_FLAG"
    fi

    # Check systemd
    SVC_FLAG=$(grep -r "FLAG{" ~/.config/systemd/user/ 2>/dev/null)
    if [ -n "$SVC_FLAG" ]; then
        echo -e "${GREEN}Found in systemd:${NC}"
        echo "$SVC_FLAG"
    fi
    echo "─────────────────────────────────────────────────────"
}

run_comprehensive() {
    decode_base64
    find_hex
    find_credentials
    find_beacons
    full_persistence_scan
    check_env
    check_shm
    search_flags
}

# Main loop
while true; do
    show_menu
    read -r choice

    case $choice in
        1) decode_base64 ;;
        2) find_hex ;;
        3) multilayer_decode ;;
        4) find_credentials ;;
        5) find_staged_creds ;;
        6) find_beacons ;;
        7) check_c2 ;;
        8) full_persistence_scan ;;
        9) full_persistence_scan ;;
        10) check_env ;;
        11) check_shm ;;
        12) search_flags ;;
        13) run_comprehensive ;;
        0) echo -e "${GREEN}Good luck with your investigation!${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac

    echo ""
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       BLUE TEAM - INTERMEDIATE FORENSICS TOOLKIT          ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
done
