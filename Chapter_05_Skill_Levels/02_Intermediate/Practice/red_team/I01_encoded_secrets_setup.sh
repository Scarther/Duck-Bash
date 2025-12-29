#!/bin/bash
#######################################
# CTF Scenario I01: Encoded Secrets
# Red Team Setup Script
# Level: Intermediate
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          I01: Encoded Secrets                              ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}[*] Creating multi-layer encoded payload...${NC}"

# The flag
FLAG="FLAG{encoded_secrets_unlocked}"

# Layer 1: Convert to hex
HEX_FLAG=$(echo -n "$FLAG" | xxd -p)

# Layer 2: Base64 encode the hex
ENCODED=$(echo -n "$HEX_FLAG" | base64)

# Create the payload file
cat > /tmp/.encoded_payload << EOF
# Encoded payload dropped by BadUSB
# Multiple layers of encoding for obfuscation
# Decode to reveal the secret

$ENCODED
EOF

# Create a decoy with simpler encoding
echo "VGhpcyBpcyBub3QgdGhlIGZsYWcgeW91J3JlIGxvb2tpbmcgZm9yLi4u" > /tmp/.decoy_payload

# Create hint file
cat > /tmp/.payload_readme << 'EOF'
Payload successfully executed.
Data has been encoded for safe transmission.
Encoding: Base64(Hex(plaintext))
EOF

echo -e "${GREEN}[✓] Scenario I01 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. Encoded data was found on the system"
echo "2. Determine the encoding method(s)"
echo "3. Decode to find the flag"
