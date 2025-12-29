#!/bin/bash
#######################################
# EXP-B01: Cryptocurrency Miner Detection
# Purpose: Detect running cryptocurrency miners
# Platform: Linux/macOS
# Author: Security Training
#######################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     CRYPTOCURRENCY MINER DETECTION SCRIPT                  ║${NC}"
echo -e "${BLUE}║     Blue Team - Expert Level                               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

ALERTS=0

#######################################
# FUNCTION: Check for known miner process names
#######################################
check_process_names() {
    echo -e "${YELLOW}[*] Checking for known miner process names...${NC}"
    
    MINERS=(
        "xmrig"
        "xmr-stak"
        "cpuminer"
        "ccminer"
        "ethminer"
        "minerd"
        "cgminer"
        "bfgminer"
        "phoenixminer"
        "t-rex"
        "nbminer"
        "gminer"
        "lolminer"
        "claymore"
    )
    
    for miner in "${MINERS[@]}"; do
        if pgrep -i "$miner" > /dev/null 2>&1; then
            echo -e "${RED}[ALERT] Miner process detected: $miner${NC}"
            ps aux | grep -i "$miner" | grep -v grep
            ((ALERTS++))
        fi
    done
    
    echo ""
}

#######################################
# FUNCTION: Check for high CPU processes
#######################################
check_high_cpu() {
    echo -e "${YELLOW}[*] Checking for high CPU usage processes...${NC}"
    
    # Get processes using more than 50% CPU
    HIGH_CPU=$(ps aux --sort=-%cpu | awk '$3 > 50 {print $0}' | head -10)
    
    if [ -n "$HIGH_CPU" ]; then
        echo -e "${YELLOW}[WARNING] High CPU processes detected:${NC}"
        echo "$HIGH_CPU"
        ((ALERTS++))
    else
        echo -e "${GREEN}[OK] No unusually high CPU processes${NC}"
    fi
    
    echo ""
}

#######################################
# FUNCTION: Check network connections to mining pools
#######################################
check_pool_connections() {
    echo -e "${YELLOW}[*] Checking for connections to mining pools...${NC}"
    
    POOL_PORTS="3333 3334 4444 5555 7777 8888 9999 14444 14433"
    POOL_DOMAINS=(
        "minexmr"
        "nanopool"
        "supportxmr"
        "monerohash"
        "hashvault"
        "moneroocean"
        "2miners"
        "ethermine"
        "nicehash"
        "f2pool"
        "antpool"
        "poolin"
        "viabtc"
        "slushpool"
    )
    
    # Check port connections
    for port in $POOL_PORTS; do
        CONNS=$(ss -tn 2>/dev/null | grep ":$port" | head -5)
        if [ -n "$CONNS" ]; then
            echo -e "${RED}[ALERT] Connection to mining port $port detected:${NC}"
            echo "$CONNS"
            ((ALERTS++))
        fi
    done
    
    # Check DNS cache/connections for pool domains
    for domain in "${POOL_DOMAINS[@]}"; do
        if ss -tn 2>/dev/null | grep -qi "$domain"; then
            echo -e "${RED}[ALERT] Connection to pool domain: $domain${NC}"
            ((ALERTS++))
        fi
    done
    
    echo ""
}

#######################################
# FUNCTION: Check for Stratum protocol indicators
#######################################
check_stratum_traffic() {
    echo -e "${YELLOW}[*] Checking for Stratum protocol traffic (requires tcpdump)...${NC}"
    
    if command -v tcpdump &> /dev/null; then
        # Quick capture to check for stratum traffic
        timeout 5 tcpdump -i any -c 100 port 3333 or port 4444 or port 14444 2>/dev/null | \
            grep -i "mining\|stratum\|subscribe" && {
            echo -e "${RED}[ALERT] Stratum mining traffic detected!${NC}"
            ((ALERTS++))
        }
    else
        echo -e "${YELLOW}[SKIP] tcpdump not available${NC}"
    fi
    
    echo ""
}

#######################################
# FUNCTION: Check for miner config files
#######################################
check_config_files() {
    echo -e "${YELLOW}[*] Searching for miner configuration files...${NC}"
    
    # Common config file patterns
    CONFIG_PATTERNS=(
        "config.json"
        "pools.txt"
        "xmrig.json"
        "miner.conf"
    )
    
    # Search common locations
    SEARCH_PATHS=(
        "/tmp"
        "/var/tmp"
        "$HOME"
        "/opt"
    )
    
    for path in "${SEARCH_PATHS[@]}"; do
        if [ -d "$path" ]; then
            for pattern in "${CONFIG_PATTERNS[@]}"; do
                FOUND=$(find "$path" -name "$pattern" -type f 2>/dev/null)
                if [ -n "$FOUND" ]; then
                    for file in $FOUND; do
                        if grep -qi "pool\|stratum\|wallet" "$file" 2>/dev/null; then
                            echo -e "${RED}[ALERT] Suspicious config file: $file${NC}"
                            ((ALERTS++))
                        fi
                    done
                fi
            done
        fi
    done
    
    echo ""
}

#######################################
# FUNCTION: Check scheduled tasks/cron for miners
#######################################
check_persistence() {
    echo -e "${YELLOW}[*] Checking for miner persistence mechanisms...${NC}"
    
    # Check crontabs
    for cronfile in /etc/crontab /var/spool/cron/*; do
        if [ -f "$cronfile" ]; then
            if grep -qi "miner\|xmrig\|stratum" "$cronfile" 2>/dev/null; then
                echo -e "${RED}[ALERT] Miner reference in cron: $cronfile${NC}"
                ((ALERTS++))
            fi
        fi
    done
    
    # Check systemd services
    if command -v systemctl &> /dev/null; then
        SUSPICIOUS=$(systemctl list-units --type=service --all 2>/dev/null | grep -i "miner\|xmrig")
        if [ -n "$SUSPICIOUS" ]; then
            echo -e "${RED}[ALERT] Suspicious systemd service:${NC}"
            echo "$SUSPICIOUS"
            ((ALERTS++))
        fi
    fi
    
    # Check rc.local
    if [ -f /etc/rc.local ]; then
        if grep -qi "miner\|xmrig" /etc/rc.local 2>/dev/null; then
            echo -e "${RED}[ALERT] Miner reference in /etc/rc.local${NC}"
            ((ALERTS++))
        fi
    fi
    
    echo ""
}

#######################################
# MAIN EXECUTION
#######################################

check_process_names
check_high_cpu
check_pool_connections
check_stratum_traffic
check_config_files
check_persistence

#######################################
# SUMMARY
#######################################
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                      SCAN SUMMARY                          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

if [ $ALERTS -gt 0 ]; then
    echo -e "${RED}[!] Total alerts: $ALERTS${NC}"
    echo -e "${RED}[!] Potential cryptocurrency mining activity detected!${NC}"
    echo -e "${YELLOW}[*] Recommended actions:${NC}"
    echo "    1. Identify and kill mining processes"
    echo "    2. Block mining pool connections at firewall"
    echo "    3. Remove persistence mechanisms"
    echo "    4. Investigate infection vector"
    exit 1
else
    echo -e "${GREEN}[✓] No obvious cryptocurrency mining indicators found${NC}"
    echo -e "${YELLOW}[*] Note: Advanced miners may evade detection${NC}"
    exit 0
fi
