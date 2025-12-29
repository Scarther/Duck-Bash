#!/bin/bash
#######################################
# CTF Scenario I03: Network Beacon
# Red Team Setup Script
# Level: Intermediate
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          I03: Network Beacon                               ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}[*] Installing network beacon...${NC}"

# Create beacon script
cat > /tmp/.beacon.sh << 'SCRIPT'
#!/bin/bash
# Network beacon - calls home every 5 minutes
# C2 Configuration loaded from .c2_config.json

CONFIG="/tmp/.c2_config.json"
LOG="/tmp/.beacon.log"

if [ -f "$CONFIG" ]; then
    C2_SERVER=$(grep -o '"server": "[^"]*' $CONFIG | cut -d'"' -f4)
    C2_PORT=$(grep -o '"port": [0-9]*' $CONFIG | grep -o '[0-9]*')

    # Simulate beacon (doesn't actually connect)
    echo "[$(date)] Beacon sent to $C2_SERVER:$C2_PORT" >> $LOG
fi
SCRIPT

chmod +x /tmp/.beacon.sh

# Create C2 configuration
cat > /tmp/.c2_config.json << 'EOF'
{
    "beacon_config": {
        "server": "192.168.1.100",
        "port": 443,
        "protocol": "https",
        "interval": 300,
        "jitter": 0.2,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "flag": "FLAG{beacon_config_exposed}",
        "encryption": "aes-256-gcm",
        "fallback_servers": [
            "backup1.evil.com",
            "backup2.evil.com"
        ]
    }
}
EOF

# Create cron entry for beacon
cat > /etc/cron.d/network_check << 'EOF'
# Network connectivity check - LEGITIMATE LOOKING
# Actually a C2 beacon
*/5 * * * * root /tmp/.beacon.sh >/dev/null 2>&1
EOF

chmod 644 /etc/cron.d/network_check

# Create some beacon log entries
cat > /tmp/.beacon.log << 'EOF'
[2024-01-15 10:00:05] Beacon sent to 192.168.1.100:443
[2024-01-15 10:05:03] Beacon sent to 192.168.1.100:443
[2024-01-15 10:10:07] Beacon sent to 192.168.1.100:443
[2024-01-15 10:15:02] Command received: SLEEP 600
[2024-01-15 10:25:04] Beacon sent to 192.168.1.100:443
EOF

echo -e "${GREEN}[✓] Scenario I03 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. Suspicious network activity detected"
echo "2. Find the beacon and its configuration"
echo "3. Identify the C2 server and extract the flag"
