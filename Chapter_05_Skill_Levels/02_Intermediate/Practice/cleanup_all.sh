#!/bin/bash
#######################################
# Intermediate Level CTF Cleanup Script
#######################################

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${YELLOW}[*] Cleaning up Intermediate CTF artifacts...${NC}"

SETUP_USER="${SUDO_USER:-$USER}"
SETUP_HOME=$(eval echo "~$SETUP_USER")

# I01
rm -f /tmp/.encoded_payload /tmp/.decoy_payload /tmp/.payload_readme

# I02
rm -f /tmp/.harvest_creds.sh /tmp/.harvested_creds.json /tmp/.browser_db_copy

# I03
rm -f /tmp/.beacon.sh /tmp/.c2_config.json /tmp/.beacon.log
rm -f /etc/cron.d/network_check

# I05
[ -f "$SETUP_HOME/.bashrc.ctf_backup" ] && mv "$SETUP_HOME/.bashrc.ctf_backup" "$SETUP_HOME/.bashrc"
[ -f /tmp/.cron_backup ] && crontab /tmp/.cron_backup && rm /tmp/.cron_backup
rm -f /tmp/.update_check.sh /tmp/.maintenance.sh /tmp/.persist_log /tmp/.maint_log
rm -f "$SETUP_HOME/.config/systemd/user/update.service"
rm -f /tmp/.system_update_svc.sh /tmp/.svc_log

# I06
rm -f /dev/shm/.memory_artifact

echo -e "${GREEN}[✓] Intermediate CTF cleanup complete${NC}"
