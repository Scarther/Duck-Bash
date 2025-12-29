#!/bin/bash
#######################################
# DT-01: Hidden File Dropper - SOLUTION
# This is the reference solution
#######################################

# Define the hidden file path
HIDDEN_FILE="/tmp/.payload_output_$(date +%s)"

# Create the hidden file with content
cat > "$HIDDEN_FILE" << EOF
═══════════════════════════════════════════════════════
 PAYLOAD EXECUTION LOG
 Simulated BadUSB Attack for Training
═══════════════════════════════════════════════════════

Timestamp: $(date)
Hostname:  $(hostname)
Username:  $(whoami)
Working Directory: $(pwd)

[*] Payload executed successfully
[*] System reconnaissance complete
[*] Data staged for exfiltration

Target Information:
- Kernel: $(uname -r)
- Architecture: $(uname -m)
- Uptime: $(uptime -p 2>/dev/null || echo "N/A")

═══════════════════════════════════════════════════════
 END OF LOG - FLAG{hidden_file_created}
═══════════════════════════════════════════════════════
EOF

# Set restrictive permissions
chmod 600 "$HIDDEN_FILE"

# Verification
if [ -f "$HIDDEN_FILE" ]; then
    echo "[ATTACK] Hidden file created successfully"
    echo "[ATTACK] Location: $HIDDEN_FILE"
    exit 0
else
    echo "[ATTACK] Failed to create hidden file"
    exit 1
fi
