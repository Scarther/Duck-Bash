#!/bin/bash
#######################################
# Basic Level CTF Cleanup Script
# Purpose: Remove all CTF artifacts
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║          CTF CLEANUP - BASIC LEVEL                         ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

SETUP_USER="${SUDO_USER:-$USER}"
SETUP_HOME=$(eval echo "~$SETUP_USER")

echo -e "${YELLOW}[*] Cleaning up CTF artifacts...${NC}"

# Scenario B01
rm -f /tmp/.badusb_was_here
rm -f "$SETUP_HOME/.hidden_payload_output"

# Scenario B02
rm -f /var/log/usb_activity.log
if [ -f "$SETUP_HOME/.bash_history.ctf_backup" ]; then
    mv "$SETUP_HOME/.bash_history.ctf_backup" "$SETUP_HOME/.bash_history"
fi

# Scenario B03
rm -f /tmp/.system_update.sh
rm -f /tmp/.update_log
rm -f /etc/cron.d/system_update

# Scenario B04
rm -f /tmp/.staged_data.tar.gz
rm -rf /tmp/.staged_data_*
rm -rf /tmp/.backup_*

# Scenario B05
rm -f /var/log/usb_forensics.log
rm -f /tmp/.kernel_usb.log

echo -e "${GREEN}[✓] All CTF artifacts cleaned up${NC}"
echo ""
echo -e "${YELLOW}System restored to pre-CTF state${NC}"
