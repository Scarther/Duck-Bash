#!/bin/bash
#######################################
# CTF Scenario B02: Process Hunter
# Red Team Setup Script
# Purpose: Simulate BadUSB process execution
# Level: Basic
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          B02: Process Hunter                               ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

SETUP_USER="${SUDO_USER:-$USER}"
SETUP_HOME=$(eval echo "~$SETUP_USER")

echo -e "${YELLOW}[*] Setting up scenario for user: $SETUP_USER${NC}"

# Create fake USB activity log
echo -e "${YELLOW}[*] Creating USB activity evidence...${NC}"

cat > /var/log/usb_activity.log << 'EOF'
[2024-01-15 09:15:32] USB Device Connected: VID=0483 PID=5740
[2024-01-15 09:15:33] HID Keyboard enumerated
[2024-01-15 09:15:34] Keystroke injection detected - rapid input
[2024-01-15 09:15:35] Process spawned: /bin/bash
[2024-01-15 09:15:36] Command executed: whoami
[2024-01-15 09:15:36] Command executed: hostname
[2024-01-15 09:15:37] Command executed: cat /etc/passwd
[2024-01-15 09:15:38] FLAG{process_execution_traced}
[2024-01-15 09:15:39] Process terminated
[2024-01-15 09:15:40] USB Device Disconnected
EOF

chmod 644 /var/log/usb_activity.log

# Add fake entries to bash history
echo -e "${YELLOW}[*] Adding simulated command history...${NC}"

HISTORY_BACKUP="$SETUP_HOME/.bash_history.ctf_backup"
if [ -f "$SETUP_HOME/.bash_history" ]; then
    cp "$SETUP_HOME/.bash_history" "$HISTORY_BACKUP"
fi

cat >> "$SETUP_HOME/.bash_history" << 'EOF'
# Normal user activity
ls -la
cd Documents
cat notes.txt
# SUSPICIOUS ACTIVITY BELOW
whoami
hostname
cat /etc/passwd | head -5
uname -a
ip addr
# End of suspicious activity
ls -la
EOF

chown "$SETUP_USER:$SETUP_USER" "$SETUP_HOME/.bash_history" 2>/dev/null

echo -e "${GREEN}[✓] Scenario B02 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. Unusual CPU activity was noticed after USB connection"
echo "2. Find evidence of what commands were executed"
echo "3. Locate the flag in the evidence"
echo ""
echo -e "${RED}Blue Team should NOT look at this script!${NC}"
