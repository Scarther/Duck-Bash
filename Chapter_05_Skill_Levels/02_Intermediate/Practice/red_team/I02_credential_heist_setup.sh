#!/bin/bash
#######################################
# CTF Scenario I02: Credential Heist
# Red Team Setup Script
# Level: Intermediate
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          I02: Credential Heist                             ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

SETUP_USER="${SUDO_USER:-$USER}"
SETUP_HOME=$(eval echo "~$SETUP_USER")

echo -e "${YELLOW}[*] Simulating credential harvesting...${NC}"

# Create the harvesting script (evidence)
cat > /tmp/.harvest_creds.sh << 'SCRIPT'
#!/bin/bash
# Credential harvesting script
# Deployed by BadUSB

OUTPUT="/tmp/.harvested_creds.json"

echo "{" > $OUTPUT
echo '  "timestamp": "'$(date -Iseconds)'",' >> $OUTPUT
echo '  "hostname": "'$(hostname)'",' >> $OUTPUT
echo '  "user": "'$(whoami)'",' >> $OUTPUT
echo '  "wifi_networks": [' >> $OUTPUT

# Simulate WiFi credential grab (fake data)
echo '    {"ssid": "HomeNetwork", "password": "W1F1P@ss123"},' >> $OUTPUT
echo '    {"ssid": "CorpWiFi", "password": "C0rp0r@te!"}' >> $OUTPUT

echo '  ],' >> $OUTPUT
echo '  "browser_passwords": [' >> $OUTPUT
echo '    {"site": "mail.example.com", "user": "admin", "pass": "Mail2024!"},' >> $OUTPUT
echo '    {"site": "bank.example.com", "user": "user123", "pass": "B@nkP@ss"}' >> $OUTPUT
echo '  ],' >> $OUTPUT
echo '  "flag": "FLAG{credential_heist_detected}",' >> $OUTPUT
echo '  "exfil_status": "staged"' >> $OUTPUT
echo "}" >> $OUTPUT
SCRIPT

chmod +x /tmp/.harvest_creds.sh

# Execute the harvesting script
/tmp/.harvest_creds.sh

# Create additional artifacts
cat > /tmp/.browser_db_copy << 'EOF'
SQLite format 3
[Binary data simulated]
Extracted from: ~/.config/chromium/Default/Login Data
Contains encrypted credentials
FLAG embedded in harvested_creds.json
EOF

echo -e "${GREEN}[✓] Scenario I02 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. Credentials may have been harvested from this system"
echo "2. Find evidence of the credential theft"
echo "3. Locate the staged data and extract the flag"
