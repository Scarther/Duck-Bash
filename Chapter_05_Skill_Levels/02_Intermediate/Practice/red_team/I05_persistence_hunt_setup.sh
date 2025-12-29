#!/bin/bash
#######################################
# CTF Scenario I05: Persistence Hunt
# Red Team Setup Script
# Level: Intermediate
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          I05: Persistence Hunt (3 Flags)                   ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

SETUP_USER="${SUDO_USER:-$USER}"
SETUP_HOME=$(eval echo "~$SETUP_USER")

echo -e "${YELLOW}[*] Installing multiple persistence mechanisms...${NC}"

# Persistence 1: Bashrc
echo -e "${YELLOW}[*] Installing bashrc persistence...${NC}"
cp "$SETUP_HOME/.bashrc" "$SETUP_HOME/.bashrc.ctf_backup" 2>/dev/null

cat >> "$SETUP_HOME/.bashrc" << 'EOF'

# System update check - DO NOT REMOVE
# FLAG{bashrc_persistence_found}
/tmp/.update_check.sh >/dev/null 2>&1 &
EOF

# Create the payload it references
cat > /tmp/.update_check.sh << 'SCRIPT'
#!/bin/bash
# Persistence payload
sleep 10
echo "Persistence active" > /tmp/.persist_log
SCRIPT
chmod +x /tmp/.update_check.sh

# Persistence 2: Crontab
echo -e "${YELLOW}[*] Installing crontab persistence...${NC}"
CURRENT_CRON=$(crontab -l 2>/dev/null)
echo "$CURRENT_CRON" > /tmp/.cron_backup

(crontab -l 2>/dev/null; echo "# System maintenance - FLAG{crontab_persistence_found}") | crontab -
(crontab -l 2>/dev/null; echo "*/10 * * * * /tmp/.maintenance.sh >/dev/null 2>&1") | crontab -

cat > /tmp/.maintenance.sh << 'SCRIPT'
#!/bin/bash
# Maintenance script (actually persistence)
date >> /tmp/.maint_log
SCRIPT
chmod +x /tmp/.maintenance.sh

# Persistence 3: Systemd user service
echo -e "${YELLOW}[*] Installing systemd user service persistence...${NC}"
mkdir -p "$SETUP_HOME/.config/systemd/user"

cat > "$SETUP_HOME/.config/systemd/user/update.service" << 'EOF'
[Unit]
Description=System Update Service
# FLAG{systemd_persistence_found}

[Service]
Type=oneshot
ExecStart=/tmp/.system_update_svc.sh

[Install]
WantedBy=default.target
EOF

cat > /tmp/.system_update_svc.sh << 'SCRIPT'
#!/bin/bash
echo "Service executed at $(date)" >> /tmp/.svc_log
SCRIPT
chmod +x /tmp/.system_update_svc.sh

chown -R "$SETUP_USER:$SETUP_USER" "$SETUP_HOME/.config/systemd" 2>/dev/null

echo -e "${GREEN}[✓] Scenario I05 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. Multiple persistence mechanisms were installed"
echo "2. Find ALL THREE flags"
echo "3. Check: bashrc, crontab, systemd user services"
echo ""
echo -e "${RED}Total Flags: 3${NC}"
