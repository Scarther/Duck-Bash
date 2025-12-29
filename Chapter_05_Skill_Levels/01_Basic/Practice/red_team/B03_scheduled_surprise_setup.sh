#!/bin/bash
#######################################
# CTF Scenario B03: Scheduled Surprise
# Red Team Setup Script
# Purpose: Simulate BadUSB persistence via cron
# Level: Basic
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          B03: Scheduled Surprise                           ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

SETUP_USER="${SUDO_USER:-$USER}"
SETUP_HOME=$(eval echo "~$SETUP_USER")

echo -e "${YELLOW}[*] Setting up scenario for user: $SETUP_USER${NC}"

# Create malicious script in /tmp
echo -e "${YELLOW}[*] Creating persistence payload...${NC}"

cat > /tmp/.system_update.sh << 'EOF'
#!/bin/bash
# This looks like a system update script but it's not!
# Payload deployed by BadUSB

# Collect system info
HOSTNAME=$(hostname)
USER=$(whoami)

# The flag is base64 encoded to make it slightly harder
# Decode: echo "RkxBR3tiYXNpY19wZXJzaXN0ZW5jZV9mb3VuZH0=" | base64 -d
# RkxBR3tiYXNpY19wZXJzaXN0ZW5jZV9mb3VuZH0=

# Log activity (simulated beacon)
echo "[$(date)] Beacon from $USER@$HOSTNAME" >> /tmp/.update_log
EOF

chmod 755 /tmp/.system_update.sh

# Create cron entry
echo -e "${YELLOW}[*] Installing persistence mechanism...${NC}"

# Create a cron.d entry (requires root)
cat > /etc/cron.d/system_update << 'EOF'
# Malicious cron job disguised as system update
# Added by BadUSB payload
*/5 * * * * root /tmp/.system_update.sh >/dev/null 2>&1
# FLAG is in the script above - decode the base64!
EOF

chmod 644 /etc/cron.d/system_update

echo -e "${GREEN}[✓] Scenario B03 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. A maintenance tech plugged in a USB to 'update drivers'"
echo "2. You suspect something was installed"
echo "3. Check for scheduled tasks and find the flag"
echo ""
echo -e "${RED}Blue Team should NOT look at this script!${NC}"
