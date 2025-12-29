#!/bin/bash
#######################################
# DT-01: Hidden File Dropper - ATTACK
# YOUR TASK: Complete this script
#
# Requirements:
# - Create a hidden file in /tmp
# - Include timestamp, hostname, username
# - Make it look like "malware" output
#######################################

# === YOUR CODE STARTS HERE ===

# 1. Define the hidden file path
# Hint: Hidden files start with a dot (.)
HIDDEN_FILE="/tmp/._____"  # TODO: Complete the filename

# 2. Create the hidden file with content
# Hint: Use cat with heredoc or multiple echo statements
# TODO: Write your file creation code here
#
# Your file should contain:
# - A header/banner
# - Timestamp
# - Hostname
# - Username
# - Some "malicious" looking text (for training only)

# Example structure (complete this):
# cat > "$HIDDEN_FILE" << 'EOF'
# ... your content here ...
# EOF

# 3. (Optional) Set restrictive permissions
# Hint: chmod 600 makes file readable only by owner

# === YOUR CODE ENDS HERE ===

# Verification (don't modify this)
if [ -f "$HIDDEN_FILE" ]; then
    echo "[ATTACK] Hidden file created successfully"
    echo "[ATTACK] Location: $HIDDEN_FILE"
    exit 0
else
    echo "[ATTACK] Failed to create hidden file"
    exit 1
fi
