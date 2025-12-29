#!/bin/bash
#######################################
# CTF Scenario B01: Hidden Message
# Red Team Setup Script
# Purpose: Simulate a basic BadUSB leaving traces
# Level: Basic
#######################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          B01: Hidden Message                               ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as appropriate user
SETUP_USER="${SUDO_USER:-$USER}"
SETUP_HOME=$(eval echo "~$SETUP_USER")

echo -e "${YELLOW}[*] Setting up scenario for user: $SETUP_USER${NC}"

# Create hidden file in /tmp (simulating BadUSB output)
echo -e "${YELLOW}[*] Simulating BadUSB payload execution...${NC}"

cat > /tmp/.badusb_was_here << 'EOF'
═══════════════════════════════════════════════════════
  BadUSB Payload Executed Successfully
  Timestamp: $(date)
  Target: $(hostname)

  FLAG{basic_hidden_file_found}

  This simulates a simple BadUSB that writes to a file.
═══════════════════════════════════════════════════════
EOF

# Also create a hidden file in home directory
cat > "$SETUP_HOME/.hidden_payload_output" << 'EOF'
System information collected by payload:
Hostname: simulated_target
User: victim_user
The real flag is in /tmp - keep looking!
EOF

# Set proper permissions
chmod 644 /tmp/.badusb_was_here
chown "$SETUP_USER:$SETUP_USER" "$SETUP_HOME/.hidden_payload_output" 2>/dev/null

echo -e "${GREEN}[✓] Scenario B01 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. A BadUSB device was briefly connected to this system"
echo "2. The terminal opened and closed quickly"
echo "3. Find the flag left behind by the attacker"
echo ""
echo -e "${RED}Blue Team should NOT look at this script!${NC}"
