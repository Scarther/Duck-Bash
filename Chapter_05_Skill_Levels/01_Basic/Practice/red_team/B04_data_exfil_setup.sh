#!/bin/bash
#######################################
# CTF Scenario B04: Data Exfil Basics
# Red Team Setup Script
# Purpose: Simulate data staging for exfiltration
# Level: Basic
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          B04: Data Exfil Basics                            ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

SETUP_USER="${SUDO_USER:-$USER}"
SETUP_HOME=$(eval echo "~$SETUP_USER")

echo -e "${YELLOW}[*] Setting up scenario for user: $SETUP_USER${NC}"

# Create staging directory
echo -e "${YELLOW}[*] Staging sensitive data...${NC}"

STAGE_DIR="/tmp/.staged_data_$$"
mkdir -p "$STAGE_DIR"

# Create fake sensitive files
cat > "$STAGE_DIR/passwords.txt" << 'EOF'
# Extracted credentials (simulated)
admin:P@ssw0rd123
user1:Welcome1!
service_account:Svc#2024
EOF

cat > "$STAGE_DIR/system_info.txt" << 'EOF'
Hostname: target-workstation
IP: 192.168.1.100
Domain: CORP.LOCAL
Users: admin, user1, service_account
EOF

cat > "$STAGE_DIR/flag.txt" << 'EOF'
╔════════════════════════════════════════════════════════════╗
║  CONGRATULATIONS!                                          ║
║  You found the staged exfiltration data!                   ║
║                                                            ║
║  FLAG{data_staging_discovered}                             ║
║                                                            ║
║  In a real attack, this data would be exfiltrated to:      ║
║  - Attacker's server                                       ║
║  - Cloud storage                                           ║
║  - USB device                                              ║
╚════════════════════════════════════════════════════════════╝
EOF

# Create compressed archive
cd /tmp
tar -czf .staged_data.tar.gz -C "$STAGE_DIR" .
rm -rf "$STAGE_DIR"

# Also create a backup location
mkdir -p /tmp/.backup_$$
cp /tmp/.staged_data.tar.gz "/tmp/.backup_$$/.data.tar.gz"

echo -e "${GREEN}[✓] Scenario B04 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. Sensitive files may have been copied and staged"
echo "2. Look for archive files in temp locations"
echo "3. Find and extract the flag from staged data"
echo ""
echo -e "${RED}Blue Team should NOT look at this script!${NC}"
