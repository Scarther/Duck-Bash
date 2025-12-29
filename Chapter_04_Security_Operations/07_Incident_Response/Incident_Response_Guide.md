# Incident Response Guide for BadUSB Attacks

## Overview

This guide provides a structured approach to responding to BadUSB incidents, from detection through recovery.

---

## Incident Response Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INCIDENT RESPONSE LIFECYCLE                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌────────────┐    ┌────────────┐    ┌────────────┐               │
│   │ PREPARATION│───►│ DETECTION  │───►│CONTAINMENT │               │
│   └────────────┘    └────────────┘    └─────┬──────┘               │
│         ▲                                    │                       │
│         │           ┌────────────┐    ┌─────▼──────┐               │
│         │           │  LESSONS   │◄───│ERADICATION │               │
│         │           │  LEARNED   │    └─────┬──────┘               │
│         │           └─────┬──────┘          │                       │
│         │                 │           ┌─────▼──────┐               │
│         └─────────────────┴───────────│  RECOVERY  │               │
│                                       └────────────┘               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Preparation

### IR Toolkit Setup

```bash
#!/bin/bash
#######################################
# IR Toolkit Setup Script
# Prepare system for incident response
#######################################

IR_DIR="/opt/ir_toolkit"
mkdir -p "$IR_DIR"/{bin,scripts,evidence}

echo "[*] Setting up IR toolkit..."

# Install essential tools
apt install -y \
    volatility3 \
    sleuthkit \
    autopsy \
    dc3dd \
    dcfldd \
    ewf-tools \
    foremost \
    binwalk \
    yara \
    chkrootkit \
    rkhunter \
    lsof \
    strace \
    ltrace

# Download additional tools
cd "$IR_DIR/bin"

# AVML for memory acquisition (Linux)
wget -q https://github.com/microsoft/avml/releases/latest/download/avml -O avml
chmod +x avml

# Create evidence collection script
cat > "$IR_DIR/scripts/collect_evidence.sh" << 'SCRIPT'
#!/bin/bash
# Quick evidence collection
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="/tmp/evidence_$TIMESTAMP"
mkdir -p "$OUTDIR"

# System info
uname -a > "$OUTDIR/system_info.txt"
date >> "$OUTDIR/system_info.txt"

# Running processes
ps auxf > "$OUTDIR/processes.txt"

# Network connections
ss -tulpn > "$OUTDIR/network.txt"
netstat -rn >> "$OUTDIR/network.txt"

# Open files
lsof > "$OUTDIR/open_files.txt" 2>/dev/null

# Cron jobs
for user in $(cut -d: -f1 /etc/passwd); do
    echo "=== $user ===" >> "$OUTDIR/cron_jobs.txt"
    crontab -u $user -l 2>/dev/null >> "$OUTDIR/cron_jobs.txt"
done

# Recent files
find /tmp /var/tmp /home -mmin -60 -ls > "$OUTDIR/recent_files.txt" 2>/dev/null

# USB device history
dmesg | grep -i usb > "$OUTDIR/usb_history.txt"

# Package and compress
tar -czf "${OUTDIR}.tar.gz" -C "$(dirname $OUTDIR)" "$(basename $OUTDIR)"
echo "[+] Evidence collected: ${OUTDIR}.tar.gz"
SCRIPT

chmod +x "$IR_DIR/scripts/collect_evidence.sh"

echo "[+] IR toolkit ready at: $IR_DIR"
```

### IR Contact List Template

```
═══════════════════════════════════════════════════════════════
                 INCIDENT RESPONSE CONTACTS
═══════════════════════════════════════════════════════════════

INTERNAL CONTACTS:
─────────────────
Security Team Lead:    _________________ Phone: _____________
IT Manager:            _________________ Phone: _____________
Legal Counsel:         _________________ Phone: _____________
Communications:        _________________ Phone: _____________
Executive Sponsor:     _________________ Phone: _____________

EXTERNAL CONTACTS:
─────────────────
IR Retainer Firm:      _________________ Phone: _____________
Law Enforcement:       _________________ Phone: _____________
Cyber Insurance:       _________________ Phone: _____________
Forensics Vendor:      _________________ Phone: _____________

ESCALATION THRESHOLDS:
─────────────────────
Level 1 (Low):    Security team handles
Level 2 (Medium): IT Manager notified
Level 3 (High):   Executive + Legal notified
Level 4 (Critical): External IR + Law Enforcement

═══════════════════════════════════════════════════════════════
```

---

## Phase 2: Detection & Analysis

### BadUSB Detection Script

```bash
#!/bin/bash
#######################################
# BadUSB Incident Detection
# Identify indicators of compromise
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

info() {
    echo -e "[INFO] $1"
}

ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

echo "════════════════════════════════════════════════════"
echo "         BadUSB Incident Detection"
echo "════════════════════════════════════════════════════"
echo ""

# 1. Check for known BadUSB devices
info "Checking for known BadUSB device VIDs..."
BADUSB_VIDS="0483 16D0 2341 16C0 2E8A"
for vid in $BADUSB_VIDS; do
    if lsusb | grep -qi "$vid"; then
        alert "Known BadUSB VID detected: $vid"
        lsusb | grep -i "$vid"
    fi
done

# 2. Check for rapid process creation
info "Checking recent process creation rate..."
RECENT_PROCS=$(ps -eo lstart | tail -n +2 | while read line; do
    date -d "$line" +%s 2>/dev/null
done | sort -rn | head -20)

# 3. Check for suspicious PowerShell/cmd activity
info "Checking for suspicious shell activity..."
if ps aux | grep -iE "powershell.*-w.*hidden|powershell.*-enc|cmd.*%TEMP%" | grep -v grep; then
    alert "Suspicious shell process detected"
fi

# 4. Check for persistence mechanisms
info "Checking cron for persistence..."
CRON_SUSPICIOUS=$(crontab -l 2>/dev/null | grep -iE "/tmp/|/var/tmp/|\\.sh|curl|wget|nc ")
if [ -n "$CRON_SUSPICIOUS" ]; then
    alert "Suspicious cron entry found"
    echo "$CRON_SUSPICIOUS"
fi

# 5. Check for recent file modifications in sensitive locations
info "Checking for recent suspicious files..."
RECENT_SUSPICIOUS=$(find /tmp /var/tmp /dev/shm -type f -mmin -30 -name ".*" 2>/dev/null)
if [ -n "$RECENT_SUSPICIOUS" ]; then
    warn "Hidden files created in last 30 minutes:"
    echo "$RECENT_SUSPICIOUS"
fi

# 6. Check network connections
info "Checking for suspicious network connections..."
SUSPICIOUS_PORTS="4444 5555 6666 7777 8888 9999"
for port in $SUSPICIOUS_PORTS; do
    if ss -tn state established "dport = :$port" 2>/dev/null | grep -q "$port"; then
        alert "Connection to suspicious port $port detected"
    fi
done

# 7. Check for data exfiltration indicators
info "Checking for potential data exfiltration..."
# Large outbound data
OUTBOUND=$(ss -tn state established 2>/dev/null | awk '{print $4}' | grep -v "127.0.0.1")
if [ -n "$OUTBOUND" ]; then
    info "Active outbound connections:"
    echo "$OUTBOUND" | head -10
fi

echo ""
echo "════════════════════════════════════════════════════"
if [ $FINDINGS -gt 0 ]; then
    echo -e "${RED}FINDINGS: $FINDINGS potential indicators detected${NC}"
    echo "Recommend immediate containment and investigation"
else
    echo -e "${GREEN}No obvious BadUSB indicators detected${NC}"
fi
echo "════════════════════════════════════════════════════"
```

### Triage Checklist

```
BADUSB INCIDENT TRIAGE CHECKLIST

Date/Time: _______________  Analyst: _______________

INITIAL ASSESSMENT:
☐ What triggered the alert/report?
☐ When was the activity first noticed?
☐ Which systems are potentially affected?
☐ Is the suspected USB device still connected?

EVIDENCE PRESERVATION:
☐ DO NOT power off the system (preserve memory)
☐ Screenshot current state
☐ Document USB devices currently connected
☐ Note any windows/applications open
☐ Record network connections (netstat/ss)

IMMEDIATE QUESTIONS:
☐ Was a user present when attack occurred?
☐ Did user notice anything unusual?
☐ Any pop-up windows or rapid typing observed?
☐ How long was the device connected?

SCOPE DETERMINATION:
☐ Single workstation or multiple?
☐ Any network indicators of lateral movement?
☐ Any data exfiltration observed?
☐ Any persistence mechanisms identified?

INITIAL SEVERITY:
☐ Low    - Contained, no data access
☐ Medium - Some data access, contained
☐ High   - Data exfil possible, spreading
☐ Critical - Active attacker, widespread

NEXT STEPS:
☐ Isolate affected system(s)
☐ Preserve evidence
☐ Begin detailed analysis
☐ Escalate as appropriate
```

---

## Phase 3: Containment

### Network Isolation Script

```bash
#!/bin/bash
#######################################
# Emergency Network Isolation
# Isolate potentially compromised host
#######################################

ACTION="${1:-isolate}"

isolate() {
    echo "[*] Isolating host from network..."

    # Save current rules for recovery
    iptables-save > /tmp/iptables_pre_isolation.rules
    ip6tables-save > /tmp/ip6tables_pre_isolation.rules

    # Flush existing rules
    iptables -F
    iptables -X
    ip6tables -F
    ip6tables -X

    # Default deny
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    ip6tables -P INPUT DROP
    ip6tables -P OUTPUT DROP
    ip6tables -P FORWARD DROP

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established (for IR tools already connected)
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow specific IR subnet (customize)
    # iptables -A INPUT -s 192.168.100.0/24 -j ACCEPT
    # iptables -A OUTPUT -d 192.168.100.0/24 -j ACCEPT

    echo "[+] Host isolated"
    echo "[*] Recovery command: iptables-restore < /tmp/iptables_pre_isolation.rules"
}

restore() {
    echo "[*] Restoring network access..."
    if [ -f /tmp/iptables_pre_isolation.rules ]; then
        iptables-restore < /tmp/iptables_pre_isolation.rules
        ip6tables-restore < /tmp/ip6tables_pre_isolation.rules
        echo "[+] Network restored"
    else
        echo "[!] No backup rules found"
    fi
}

case "$ACTION" in
    isolate) isolate ;;
    restore) restore ;;
    *) echo "Usage: $0 [isolate|restore]" ;;
esac
```

### Process Termination

```bash
#!/bin/bash
#######################################
# Terminate Malicious Processes
# With evidence preservation
#######################################

PID="$1"

if [ -z "$PID" ]; then
    echo "Usage: $0 <PID>"
    echo ""
    echo "Suspicious processes:"
    ps aux | grep -iE "powershell|cmd.*-c|nc.*-e|/tmp/\." | grep -v grep
    exit 1
fi

EVIDENCE_DIR="/tmp/ir_evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "[*] Preserving evidence for PID $PID..."

# Capture process info
ps -p "$PID" -o pid,ppid,user,start,command > "$EVIDENCE_DIR/process_info.txt"

# Capture memory map
cat /proc/$PID/maps > "$EVIDENCE_DIR/memory_map.txt" 2>/dev/null

# Capture environment
cat /proc/$PID/environ | tr '\0' '\n' > "$EVIDENCE_DIR/environment.txt" 2>/dev/null

# Capture open files
ls -la /proc/$PID/fd/ > "$EVIDENCE_DIR/open_files.txt" 2>/dev/null

# Capture network connections
ls -la /proc/$PID/fd/ | grep socket > "$EVIDENCE_DIR/sockets.txt" 2>/dev/null

# Copy executable if accessible
cp /proc/$PID/exe "$EVIDENCE_DIR/executable" 2>/dev/null

# Terminate process
echo "[*] Terminating PID $PID..."
kill -9 "$PID"

echo "[+] Process terminated"
echo "[+] Evidence saved to: $EVIDENCE_DIR"
```

---

## Phase 4: Eradication

### Persistence Removal Script

```bash
#!/bin/bash
#######################################
# Remove BadUSB Persistence
# Clean up common persistence mechanisms
#######################################

BACKUP_DIR="/tmp/ir_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "[*] Searching for and removing persistence..."
echo "[*] Backups saved to: $BACKUP_DIR"
echo ""

# 1. Check and clean crontabs
echo "[*] Checking crontabs..."
for user in $(cut -d: -f1 /etc/passwd); do
    CRON=$(crontab -u $user -l 2>/dev/null)
    if echo "$CRON" | grep -qiE "/tmp/|/var/tmp/|curl|wget|nc |base64"; then
        echo "[!] Suspicious crontab for $user:"
        echo "$CRON" | grep -iE "/tmp/|/var/tmp/|curl|wget|nc |base64"
        crontab -u $user -l > "$BACKUP_DIR/crontab_$user.bak"

        read -p "Remove suspicious entries? (y/n) " answer
        if [ "$answer" = "y" ]; then
            crontab -u $user -l | grep -viE "/tmp/|/var/tmp/|curl|wget|nc |base64" | crontab -u $user -
            echo "[+] Cleaned crontab for $user"
        fi
    fi
done

# 2. Check systemd services
echo ""
echo "[*] Checking systemd services..."
for service in /etc/systemd/system/*.service /home/*/.config/systemd/user/*.service; do
    if [ -f "$service" ]; then
        if grep -qiE "/tmp/|/var/tmp/|curl|wget|nc " "$service" 2>/dev/null; then
            echo "[!] Suspicious service: $service"
            cat "$service"
            cp "$service" "$BACKUP_DIR/"

            read -p "Remove this service? (y/n) " answer
            if [ "$answer" = "y" ]; then
                systemctl disable "$(basename $service)" 2>/dev/null
                rm "$service"
                echo "[+] Removed: $service"
            fi
        fi
    fi
done

# 3. Check rc.local
echo ""
echo "[*] Checking rc.local..."
if [ -f /etc/rc.local ]; then
    if grep -qiE "/tmp/|curl|wget|nc " /etc/rc.local; then
        echo "[!] Suspicious entries in rc.local:"
        grep -iE "/tmp/|curl|wget|nc " /etc/rc.local
        cp /etc/rc.local "$BACKUP_DIR/"
    fi
fi

# 4. Check bash profiles
echo ""
echo "[*] Checking shell profiles..."
for profile in /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /root/.bashrc; do
    if [ -f "$profile" ]; then
        if grep -qiE "curl|wget|nc |/tmp/|base64" "$profile" 2>/dev/null; then
            echo "[!] Suspicious entries in: $profile"
            grep -iE "curl|wget|nc |/tmp/|base64" "$profile"
            cp "$profile" "$BACKUP_DIR/$(basename $profile).$(dirname $profile | tr '/' '_')"
        fi
    fi
done

# 5. Check for suspicious files
echo ""
echo "[*] Checking for suspicious files in temp directories..."
find /tmp /var/tmp /dev/shm -type f \( -name ".*" -o -perm -111 \) 2>/dev/null | while read file; do
    echo "[!] Suspicious file: $file"
    ls -la "$file"
    file "$file"
    cp "$file" "$BACKUP_DIR/" 2>/dev/null
done

echo ""
echo "[+] Eradication check complete"
echo "[*] Review backups in: $BACKUP_DIR"
```

---

## Phase 5: Recovery

### System Verification

```bash
#!/bin/bash
#######################################
# Post-Incident System Verification
#######################################

echo "════════════════════════════════════════════════════"
echo "         Post-Incident Verification"
echo "════════════════════════════════════════════════════"
echo ""

PASS=0
FAIL=0

check() {
    if eval "$2"; then
        echo "[PASS] $1"
        ((PASS++))
    else
        echo "[FAIL] $1"
        ((FAIL++))
    fi
}

# Process checks
echo "[*] Process Verification"
check "No suspicious PowerShell processes" "! pgrep -f 'powershell.*hidden'"
check "No suspicious nc/ncat processes" "! pgrep -f 'nc.*-e|ncat.*-e'"
check "No processes from /tmp" "! ps aux | grep -E '^.*/tmp/' | grep -v grep"
echo ""

# Persistence checks
echo "[*] Persistence Verification"
check "No suspicious cron entries" "! crontab -l 2>/dev/null | grep -iE '/tmp/|curl.*\\|'"
check "No suspicious systemd services" "! ls /etc/systemd/system/*.service 2>/dev/null | xargs grep -l '/tmp/'"
echo ""

# Network checks
echo "[*] Network Verification"
check "No connections to port 4444" "! ss -tn | grep ':4444'"
check "No connections to port 5555" "! ss -tn | grep ':5555'"
check "No unusual listening ports" "! ss -tulpn | grep -vE ':22|:80|:443|127.0.0.1'"
echo ""

# File system checks
echo "[*] File System Verification"
check "No hidden executables in /tmp" "! find /tmp -type f -name '.*' -perm -111 2>/dev/null | grep -q ."
check "No scripts in /dev/shm" "! find /dev/shm -type f -name '*.sh' 2>/dev/null | grep -q ."
echo ""

echo "════════════════════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed"
echo "════════════════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "System may still be compromised. Review failed checks."
    exit 1
fi
```

---

## Phase 6: Lessons Learned

### Incident Report Template

```markdown
# Incident Report

## Executive Summary
- **Incident ID:** IR-YYYY-NNN
- **Date Detected:** YYYY-MM-DD HH:MM
- **Date Contained:** YYYY-MM-DD HH:MM
- **Date Resolved:** YYYY-MM-DD HH:MM
- **Severity:** [Low/Medium/High/Critical]
- **Type:** BadUSB Attack

## Timeline
| Time | Event |
|------|-------|
| HH:MM | Initial detection |
| HH:MM | Containment initiated |
| HH:MM | Analysis complete |
| HH:MM | Eradication complete |
| HH:MM | Recovery complete |

## Technical Details

### Attack Vector
[Describe the BadUSB device and how it was introduced]

### Payload Analysis
[Describe what the payload did]

### Indicators of Compromise
- USB VID/PID: XXXX:XXXX
- Process names: [list]
- File paths: [list]
- Network IOCs: [list]

### Affected Systems
[List affected systems]

### Data Impact
[Describe any data accessed/exfiltrated]

## Response Actions
1. [Action taken]
2. [Action taken]
3. [Action taken]

## Root Cause
[What allowed this to happen]

## Recommendations
1. [Recommendation]
2. [Recommendation]
3. [Recommendation]

## Appendices
- A: Evidence inventory
- B: Timeline details
- C: Technical analysis
```

---

## Quick Reference

### IR Commands Cheatsheet

```bash
# Isolate host
iptables -I OUTPUT -j DROP

# Capture memory (Linux)
/opt/ir_toolkit/bin/avml /tmp/memory.lime

# List all processes with network connections
lsof -i -P -n

# Find recently modified files
find / -mmin -30 -type f 2>/dev/null

# Check for persistence
crontab -l; cat /etc/rc.local; systemctl list-unit-files --type=service

# Capture disk image
dcfldd if=/dev/sda of=/mnt/evidence/disk.dd hash=sha256

# Check USB history
dmesg | grep -i usb | tail -50
```

---

[← Back to Security Operations](../README.md)
