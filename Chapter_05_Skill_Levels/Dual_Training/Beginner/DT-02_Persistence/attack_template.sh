#!/bin/bash
#######################################
# DT-02: Cron Persistence - ATTACK
# YOUR TASK: Complete this script
#######################################

# === YOUR CODE STARTS HERE ===

# 1. Create the hidden persistence script
# TODO: Create /tmp/.persistence.sh with content that:
#   - Logs timestamp to /tmp/.beacon.log
#   - Simulates a beacon check-in
PERSIST_SCRIPT="/tmp/.persistence.sh"

# cat > "$PERSIST_SCRIPT" << 'EOF'
# #!/bin/bash
# # TODO: Your beacon simulation code
# EOF

# 2. Make script executable
# TODO: chmod +x "$PERSIST_SCRIPT"

# 3. Add cron entry
# TODO: Add entry that runs every 5 minutes
# Hint: (crontab -l 2>/dev/null; echo "*/5 * * * * $PERSIST_SCRIPT") | crontab -

# === YOUR CODE ENDS HERE ===

echo "[ATTACK] Persistence mechanism installed"
echo "[ATTACK] Check with: crontab -l"
