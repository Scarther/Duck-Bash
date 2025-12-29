#!/bin/bash
#######################################
# Blue Team Script: Detect Registry Persistence
# Counters: RT-01 Registry Run Key Persistence
# MITRE D3FEND: D3-PSA (Process Spawn Analysis)
#######################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     BLUE TEAM - Registry Persistence Detection            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

ALERTS=0

# Function: Check Linux equivalent persistence (for training on Linux)
check_bashrc_persistence() {
    echo -e "${YELLOW}[*] Checking bashrc for persistence...${NC}"

    # Look for suspicious patterns in bashrc
    SUSPICIOUS=$(grep -E "powershell|hidden|beacon|curl.*\|.*bash|wget.*\|.*bash" ~/.bashrc 2>/dev/null)

    if [ -n "$SUSPICIOUS" ]; then
        echo -e "${RED}[ALERT] Suspicious bashrc entries found:${NC}"
        echo "$SUSPICIOUS"
        ((ALERTS++))
    else
        echo -e "${GREEN}[OK] No suspicious bashrc entries${NC}"
    fi
}

# Function: Check profile.d scripts
check_profile_persistence() {
    echo -e "${YELLOW}[*] Checking /etc/profile.d for persistence...${NC}"

    # List recent additions to profile.d
    RECENT=$(find /etc/profile.d -mtime -7 -type f 2>/dev/null)

    if [ -n "$RECENT" ]; then
        echo -e "${YELLOW}[INFO] Recently modified profile.d scripts:${NC}"
        echo "$RECENT"
    fi
}

# Function: Check for simulated Windows registry artifacts
check_simulated_registry() {
    echo -e "${YELLOW}[*] Checking for training registry simulation files...${NC}"

    # In training, we simulate registry with files
    REG_SIM=$(find /tmp -name "*persist*" -o -name "*registry*" -o -name "*.reg" 2>/dev/null)

    if [ -n "$REG_SIM" ]; then
        echo -e "${RED}[ALERT] Registry simulation files found:${NC}"
        echo "$REG_SIM"
        ((ALERTS++))
    fi
}

# Function: Check for hidden PowerShell-like scripts
check_hidden_scripts() {
    echo -e "${YELLOW}[*] Checking for hidden scripts in temp...${NC}"

    HIDDEN=$(find /tmp -name ".*" -type f -executable 2>/dev/null)

    if [ -n "$HIDDEN" ]; then
        echo -e "${RED}[ALERT] Hidden executable scripts in temp:${NC}"
        echo "$HIDDEN"
        for script in $HIDDEN; do
            echo -e "${YELLOW}  Content of $script:${NC}"
            head -5 "$script"
        done
        ((ALERTS++))
    fi
}

# Function: Generate Sigma-style detection rule
generate_detection_rule() {
    echo -e "${YELLOW}[*] Suggested Sigma Detection Rule:${NC}"
    cat << 'EOF'
title: Suspicious Registry Run Key Modification
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains:
            - '\CurrentVersion\Run'
            - '\CurrentVersion\RunOnce'
        Details|contains:
            - 'powershell'
            - '-w hidden'
            - '-ep bypass'
    condition: selection
level: high
EOF
}

# Function: Provide remediation steps
show_remediation() {
    echo ""
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║                    REMEDIATION STEPS                       ║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "For Windows Registry Persistence:"
    echo "  1. Open Registry Editor (regedit)"
    echo "  2. Navigate to: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    echo "  3. Identify and delete suspicious entries"
    echo ""
    echo "PowerShell Removal:"
    echo '  Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SuspiciousEntry"'
    echo ""
    echo "For Linux Persistence:"
    echo "  1. Review and clean ~/.bashrc"
    echo "  2. Check /etc/profile.d/ for unauthorized scripts"
    echo "  3. Review crontab entries"
}

# Main execution
echo -e "${BLUE}Starting persistence detection scan...${NC}"
echo "─────────────────────────────────────────────────────"

check_bashrc_persistence
echo ""
check_profile_persistence
echo ""
check_simulated_registry
echo ""
check_hidden_scripts
echo ""

# Summary
echo "─────────────────────────────────────────────────────"
if [ $ALERTS -gt 0 ]; then
    echo -e "${RED}[!] Total alerts: $ALERTS${NC}"
    echo -e "${RED}[!] Potential persistence mechanisms detected!${NC}"
    show_remediation
else
    echo -e "${GREEN}[✓] No persistence indicators found${NC}"
fi

echo ""
echo -e "${YELLOW}Generate detection rule? (y/n)${NC}"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    generate_detection_rule
fi
