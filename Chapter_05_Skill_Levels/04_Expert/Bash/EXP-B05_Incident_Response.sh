#!/bin/bash
#######################################
# EXP-B05: Cryptocurrency Miner Incident Response
# Purpose: Comprehensive IR toolkit for miner infections
# Platform: Linux/macOS
# Author: Security Training
#######################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Evidence directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
EVIDENCE_DIR="/tmp/miner_ir_$TIMESTAMP"
mkdir -p "$EVIDENCE_DIR"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     CRYPTOCURRENCY MINER INCIDENT RESPONSE                 ║${NC}"
echo -e "${BLUE}║     Evidence Directory: $EVIDENCE_DIR${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

#######################################
# PHASE 1: EVIDENCE COLLECTION
#######################################
echo -e "${YELLOW}[PHASE 1] Evidence Collection${NC}"
echo "========================================"

# System information
echo "[*] Collecting system information..."
uname -a > "$EVIDENCE_DIR/system_info.txt"
date >> "$EVIDENCE_DIR/system_info.txt"
hostname >> "$EVIDENCE_DIR/system_info.txt"

# Running processes
echo "[*] Capturing running processes..."
ps auxf > "$EVIDENCE_DIR/processes.txt"

# Network connections
echo "[*] Capturing network connections..."
ss -tulpan > "$EVIDENCE_DIR/network_connections.txt" 2>/dev/null
netstat -tulpan >> "$EVIDENCE_DIR/network_connections.txt" 2>/dev/null

# Open files
echo "[*] Capturing open files..."
lsof -i > "$EVIDENCE_DIR/open_network_files.txt" 2>/dev/null

# Crontabs
echo "[*] Capturing scheduled tasks..."
crontab -l > "$EVIDENCE_DIR/user_crontab.txt" 2>/dev/null
cat /etc/crontab > "$EVIDENCE_DIR/system_crontab.txt" 2>/dev/null

# Login history
echo "[*] Capturing login history..."
last > "$EVIDENCE_DIR/login_history.txt"
who > "$EVIDENCE_DIR/current_users.txt"

echo -e "${GREEN}[✓] Evidence collected in $EVIDENCE_DIR${NC}"
echo ""

#######################################
# PHASE 2: MINER IDENTIFICATION
#######################################
echo -e "${YELLOW}[PHASE 2] Miner Identification${NC}"
echo "========================================"

MINER_PIDS=()
MINER_NAMES=("xmrig" "xmr-stak" "cpuminer" "ccminer" "ethminer" "minerd")

for miner in "${MINER_NAMES[@]}"; do
    PIDS=$(pgrep -i "$miner" 2>/dev/null)
    if [ -n "$PIDS" ]; then
        echo -e "${RED}[ALERT] Found miner: $miner (PIDs: $PIDS)${NC}"
        for pid in $PIDS; do
            MINER_PIDS+=("$pid")
            # Get process details
            cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' >> "$EVIDENCE_DIR/miner_cmdlines.txt"
            echo "" >> "$EVIDENCE_DIR/miner_cmdlines.txt"
            ls -la /proc/$pid/exe 2>/dev/null >> "$EVIDENCE_DIR/miner_binaries.txt"
        done
    fi
done

# Check high CPU processes
echo "[*] Checking high CPU processes..."
ps aux --sort=-%cpu | head -20 > "$EVIDENCE_DIR/high_cpu_processes.txt"

echo ""

#######################################
# PHASE 3: CONTAINMENT
#######################################
echo -e "${YELLOW}[PHASE 3] Containment${NC}"
echo "========================================"

if [ ${#MINER_PIDS[@]} -gt 0 ]; then
    read -p "Kill identified miner processes? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for pid in "${MINER_PIDS[@]}"; do
            echo "[*] Killing process $pid..."
            kill -9 "$pid" 2>/dev/null
        done
        echo -e "${GREEN}[✓] Miner processes terminated${NC}"
    fi
fi

# Block mining ports
read -p "Block mining ports with iptables? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    MINING_PORTS="3333 3334 4444 5555 14444 14433"
    for port in $MINING_PORTS; do
        iptables -A OUTPUT -p tcp --dport "$port" -j DROP 2>/dev/null
        echo "[*] Blocked outbound port $port"
    done
    echo -e "${GREEN}[✓] Mining ports blocked${NC}"
fi

echo ""

#######################################
# PHASE 4: ERADICATION
#######################################
echo -e "${YELLOW}[PHASE 4] Eradication${NC}"
echo "========================================"

# Find and display suspicious files
echo "[*] Searching for suspicious files..."
SUSPICIOUS_FILES=()

# Search common locations
for dir in /tmp /var/tmp /dev/shm "$HOME"; do
    if [ -d "$dir" ]; then
        while IFS= read -r file; do
            SUSPICIOUS_FILES+=("$file")
        done < <(find "$dir" -type f \( -name "*.json" -o -name "*miner*" -o -name "*xmrig*" \) 2>/dev/null)
    fi
done

if [ ${#SUSPICIOUS_FILES[@]} -gt 0 ]; then
    echo -e "${RED}[ALERT] Suspicious files found:${NC}"
    for file in "${SUSPICIOUS_FILES[@]}"; do
        echo "  - $file"
        # Check if config file
        if grep -qi "pool\|stratum\|wallet" "$file" 2>/dev/null; then
            echo -e "    ${RED}[!] Contains mining configuration${NC}"
        fi
    done
    
    read -p "Remove suspicious files? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for file in "${SUSPICIOUS_FILES[@]}"; do
            cp "$file" "$EVIDENCE_DIR/" 2>/dev/null  # Preserve evidence
            rm -f "$file"
            echo "[*] Removed: $file"
        done
    fi
fi

# Check and clean persistence
echo "[*] Checking persistence mechanisms..."

# Cron
if grep -rqi "miner\|xmrig\|stratum" /var/spool/cron/ 2>/dev/null; then
    echo -e "${RED}[ALERT] Miner references found in crontabs${NC}"
    echo "[!] Manual review required"
fi

echo ""

#######################################
# PHASE 5: RECOVERY VERIFICATION
#######################################
echo -e "${YELLOW}[PHASE 5] Recovery Verification${NC}"
echo "========================================"

echo "[*] Verifying cleanup..."

# Re-check for miners
REMAINING=$(pgrep -i "xmrig\|cpuminer\|minerd" 2>/dev/null)
if [ -n "$REMAINING" ]; then
    echo -e "${RED}[WARNING] Miner processes still running: $REMAINING${NC}"
else
    echo -e "${GREEN}[✓] No miner processes detected${NC}"
fi

# Re-check network connections
POOL_CONNS=$(ss -tn 2>/dev/null | grep -E ":3333|:4444|:14444")
if [ -n "$POOL_CONNS" ]; then
    echo -e "${RED}[WARNING] Connections to mining ports still active${NC}"
else
    echo -e "${GREEN}[✓] No mining pool connections detected${NC}"
fi

echo ""

#######################################
# GENERATE REPORT
#######################################
echo -e "${YELLOW}[REPORT] Generating Incident Report${NC}"
echo "========================================"

cat > "$EVIDENCE_DIR/incident_report.txt" << REPORT
CRYPTOCURRENCY MINER INCIDENT REPORT
====================================
Generated: $(date)
Hostname: $(hostname)
Investigator: $(whoami)

SUMMARY
-------
Evidence Directory: $EVIDENCE_DIR

IDENTIFIED MINERS
-----------------
$(cat "$EVIDENCE_DIR/miner_cmdlines.txt" 2>/dev/null || echo "None identified")

HIGH CPU PROCESSES
------------------
$(head -10 "$EVIDENCE_DIR/high_cpu_processes.txt")

SUSPICIOUS FILES FOUND
----------------------
${SUSPICIOUS_FILES[*]:-None}

ACTIONS TAKEN
-------------
- Evidence collected
- Miner processes terminated (if confirmed)
- Mining ports blocked (if confirmed)
- Suspicious files removed (if confirmed)

RECOMMENDATIONS
---------------
1. Investigate infection vector (BadUSB, phishing, etc.)
2. Check for lateral movement to other systems
3. Update detection rules to prevent reinfection
4. Review USB device policies
5. Conduct user security awareness training

END OF REPORT
REPORT

echo -e "${GREEN}[✓] Report saved to $EVIDENCE_DIR/incident_report.txt${NC}"

#######################################
# HASH EVIDENCE
#######################################
echo ""
echo "[*] Calculating evidence hashes..."
cd "$EVIDENCE_DIR"
sha256sum * > sha256sums.txt 2>/dev/null
echo -e "${GREEN}[✓] Evidence hashes saved${NC}"

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                 INCIDENT RESPONSE COMPLETE                 ║${NC}"
echo -e "${BLUE}║     Evidence preserved in: $EVIDENCE_DIR${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
