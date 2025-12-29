# Endpoint Detection and Response (EDR) Guide

## Overview

This guide covers EDR solutions and techniques for detecting BadUSB attacks at the endpoint level.

---

## EDR Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        EDR ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ENDPOINT AGENT                         CENTRAL CONSOLE            │
│   ┌────────────────────┐                ┌──────────────────────┐    │
│   │ Process Monitor    │──────────────► │ Event Collection     │    │
│   ├────────────────────┤                ├──────────────────────┤    │
│   │ File System Watch  │──────────────► │ Threat Intelligence  │    │
│   ├────────────────────┤                ├──────────────────────┤    │
│   │ Network Monitor    │──────────────► │ Behavioral Analysis  │    │
│   ├────────────────────┤                ├──────────────────────┤    │
│   │ Registry Monitor   │──────────────► │ Alert Generation     │    │
│   ├────────────────────┤                ├──────────────────────┤    │
│   │ Response Actions   │◄────────────── │ Response Automation  │    │
│   └────────────────────┘                └──────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Detection Points

### Process Tree Analysis

```
Normal User Activity:
explorer.exe
├── chrome.exe
├── notepad.exe
└── word.exe

BadUSB Attack Pattern:
explorer.exe
└── cmd.exe (spawned by HID injection)
    └── powershell.exe -w hidden -ep bypass
        └── net.exe (network recon)
        └── curl.exe (data exfil)
```

### Detection Script

```bash
#!/bin/bash
#######################################
# Process Tree Analyzer
# Detect suspicious parent-child relationships
#######################################

SUSPICIOUS_PATTERNS=(
    "explorer.exe.*cmd.exe"
    "explorer.exe.*powershell.exe"
    "cmd.exe.*powershell.exe.*-w.*hidden"
    "powershell.exe.*-enc"
    "powershell.exe.*-ep.*bypass"
)

echo "[*] Analyzing process trees..."

# Get process tree (Linux simulation)
ps auxf > /tmp/proctree.txt

for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
    MATCHES=$(grep -iE "$pattern" /tmp/proctree.txt)
    if [ -n "$MATCHES" ]; then
        echo "[ALERT] Suspicious pattern detected: $pattern"
        echo "$MATCHES"
        echo ""
    fi
done

rm /tmp/proctree.txt
```

---

## Sysmon Configuration for EDR

### Comprehensive Sysmon Config

```xml
<!--
    Sysmon Configuration for BadUSB Detection
    Install: sysmon64 -accepteula -i config.xml
-->
<Sysmon schemaversion="4.50">
    <HashAlgorithms>SHA256</HashAlgorithms>

    <EventFiltering>
        <!-- Process Creation (Event ID 1) -->
        <RuleGroup name="ProcessCreate" groupRelation="or">
            <ProcessCreate onmatch="include">
                <!-- Capture all PowerShell -->
                <Image condition="contains">powershell</Image>
                <Image condition="contains">pwsh</Image>
                <!-- Capture command prompts -->
                <Image condition="contains">cmd.exe</Image>
                <!-- Capture scripting hosts -->
                <Image condition="contains">wscript</Image>
                <Image condition="contains">cscript</Image>
                <Image condition="contains">mshta</Image>
                <!-- Capture network tools -->
                <Image condition="contains">curl</Image>
                <Image condition="contains">wget</Image>
                <Image condition="contains">certutil</Image>
                <!-- Capture admin tools -->
                <Image condition="contains">reg.exe</Image>
                <Image condition="contains">schtasks</Image>
                <Image condition="contains">net.exe</Image>
            </ProcessCreate>
        </RuleGroup>

        <!-- Network Connections (Event ID 3) -->
        <RuleGroup name="NetworkConnect" groupRelation="or">
            <NetworkConnect onmatch="include">
                <Image condition="contains">powershell</Image>
                <Image condition="contains">cmd.exe</Image>
                <DestinationPort condition="is">4444</DestinationPort>
                <DestinationPort condition="is">5555</DestinationPort>
                <DestinationPort condition="is">8080</DestinationPort>
            </NetworkConnect>
        </RuleGroup>

        <!-- Registry Modifications (Event ID 13) -->
        <RuleGroup name="RegistryEvent" groupRelation="or">
            <RegistryEvent onmatch="include">
                <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
                <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
                <TargetObject condition="contains">Policies\Explorer</TargetObject>
            </RegistryEvent>
        </RuleGroup>

        <!-- File Creation (Event ID 11) -->
        <RuleGroup name="FileCreate" groupRelation="or">
            <FileCreate onmatch="include">
                <TargetFilename condition="contains">\Temp\</TargetFilename>
                <TargetFilename condition="contains">\AppData\</TargetFilename>
                <TargetFilename condition="end with">.ps1</TargetFilename>
                <TargetFilename condition="end with">.bat</TargetFilename>
                <TargetFilename condition="end with">.vbs</TargetFilename>
            </FileCreate>
        </RuleGroup>

        <!-- DNS Queries (Event ID 22) -->
        <RuleGroup name="DnsQuery" groupRelation="or">
            <DnsQuery onmatch="include">
                <Image condition="contains">powershell</Image>
                <Image condition="contains">cmd.exe</Image>
            </DnsQuery>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

---

## EDR-Like Detection Script

```bash
#!/bin/bash
#######################################
# Lightweight EDR Simulation
# For training and testing
#######################################

LOG_FILE="/var/log/mini_edr.log"
ALERT_FILE="/var/log/edr_alerts.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

alert() {
    local severity="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$severity] $message" | tee -a "$ALERT_FILE"
}

# Monitor processes
monitor_processes() {
    log "[*] Starting process monitor..."

    local previous_pids=$(ps -eo pid --no-headers | sort)

    while true; do
        current_pids=$(ps -eo pid --no-headers | sort)
        new_pids=$(comm -13 <(echo "$previous_pids") <(echo "$current_pids"))

        for pid in $new_pids; do
            if [ -d "/proc/$pid" ]; then
                cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
                ppid=$(grep PPid /proc/$pid/status 2>/dev/null | awk '{print $2}')
                parent_cmd=$(cat /proc/$ppid/cmdline 2>/dev/null | tr '\0' ' ')

                log "NEW: PID=$pid CMD=$cmdline PPID=$ppid"

                # Check for suspicious patterns
                if echo "$cmdline" | grep -qiE "base64|curl.*\|.*sh|wget.*\|.*sh|/dev/tcp"; then
                    alert "HIGH" "Suspicious command: $cmdline"
                fi

                if echo "$cmdline" | grep -qiE "nc.*-e|ncat.*-e|bash.*-i"; then
                    alert "CRITICAL" "Potential reverse shell: $cmdline"
                fi
            fi
        done

        previous_pids="$current_pids"
        sleep 1
    done
}

# Monitor file changes
monitor_files() {
    log "[*] Starting file monitor..."

    inotifywait -m -r -e create,modify,delete \
        /tmp /var/tmp /home 2>/dev/null | while read path action file; do

        log "FILE: $action $path$file"

        # Alert on suspicious files
        if [[ "$file" =~ \.(sh|py|pl|ps1|bat)$ ]]; then
            if [[ "$path" =~ (tmp|\.cache) ]]; then
                alert "MEDIUM" "Script created in temp: $path$file"
            fi
        fi
    done
}

# Monitor network connections
monitor_network() {
    log "[*] Starting network monitor..."

    while true; do
        ss -tulpn 2>/dev/null | grep -v "127.0.0.1" | while read line; do
            port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
            proc=$(echo "$line" | awk '{print $7}')

            # Alert on suspicious ports
            if [[ "$port" =~ ^(4444|5555|6666|8888|9999)$ ]]; then
                alert "HIGH" "Suspicious port listening: $port by $proc"
            fi
        done
        sleep 10
    done
}

# Main
echo "╔════════════════════════════════════════════════════════════╗"
echo "║           Mini EDR - Training Tool                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Start monitors in background
monitor_processes &
PROC_PID=$!

monitor_files &
FILE_PID=$!

monitor_network &
NET_PID=$!

log "[+] All monitors started"
log "[*] Process monitor PID: $PROC_PID"
log "[*] File monitor PID: $FILE_PID"
log "[*] Network monitor PID: $NET_PID"
log "[*] Alerts logged to: $ALERT_FILE"

# Wait for interrupt
trap "kill $PROC_PID $FILE_PID $NET_PID 2>/dev/null; exit" INT TERM

wait
```

---

## Common EDR Evasion and Detection

### Known Evasion Techniques

| Technique | Description | Detection |
|-----------|-------------|-----------|
| PPID Spoofing | Fake parent process | Check handle inheritance |
| Direct syscalls | Bypass API hooks | Kernel-level monitoring |
| Memory-only execution | No file on disk | Memory scanning |
| Time stomping | Modify timestamps | Compare to MFT |
| Log tampering | Clear/modify logs | Log integrity checking |

### Anti-Evasion Monitoring

```bash
#!/bin/bash
#######################################
# Anti-Evasion Detection
#######################################

echo "[*] Checking for evasion indicators..."

# Check for unusual process trees
echo "[*] Checking process relationships..."
ps -eo pid,ppid,cmd --forest | while read line; do
    pid=$(echo "$line" | awk '{print $1}')
    ppid=$(echo "$line" | awk '{print $2}')

    if [ "$ppid" = "1" ]; then
        cmd=$(echo "$line" | awk '{$1=$2=""; print $0}')
        if echo "$cmd" | grep -qiE "powershell|cmd\.exe|bash"; then
            echo "[!] Orphaned shell process: $cmd"
        fi
    fi
done

# Check for memory-only execution
echo ""
echo "[*] Checking for memory-only execution..."
for pid in /proc/[0-9]*; do
    if [ -d "$pid" ]; then
        exe=$(readlink "$pid/exe" 2>/dev/null)
        if echo "$exe" | grep -q "(deleted)"; then
            echo "[!] Deleted executable still running: $pid $exe"
        fi
    fi
done

# Check for hidden files in temp
echo ""
echo "[*] Checking for hidden files in temp..."
find /tmp /var/tmp -name ".*" -type f 2>/dev/null | while read file; do
    echo "[!] Hidden file: $file"
done
```

---

## Response Actions

### Automated Response Script

```bash
#!/bin/bash
#######################################
# EDR Response Actions
# Execute containment measures
#######################################

ACTION="$1"
TARGET="$2"

usage() {
    echo "Usage: $0 <action> <target>"
    echo ""
    echo "Actions:"
    echo "  isolate    - Network isolate host"
    echo "  kill       - Kill process by PID"
    echo "  quarantine - Move file to quarantine"
    echo "  block_user - Disable user account"
    echo "  collect    - Collect forensic data"
    exit 1
}

isolate_host() {
    echo "[*] Isolating host from network..."

    # Save current rules
    iptables-save > /tmp/iptables_backup.rules

    # Block all outbound except essential
    iptables -F OUTPUT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT  # DNS
    iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT       # Localhost
    iptables -A OUTPUT -j DROP

    echo "[+] Host isolated. Restore with: iptables-restore < /tmp/iptables_backup.rules"
}

kill_process() {
    local pid="$1"
    echo "[*] Killing process $pid..."

    # Capture process info first
    ps -p "$pid" -o pid,ppid,cmd >> /var/log/killed_processes.log 2>/dev/null

    kill -9 "$pid"
    echo "[+] Process $pid terminated"
}

quarantine_file() {
    local file="$1"
    local quarantine="/var/quarantine"

    mkdir -p "$quarantine"

    echo "[*] Quarantining: $file"

    # Calculate hash before moving
    sha256sum "$file" >> "$quarantine/hashes.log"

    # Move with timestamp
    mv "$file" "$quarantine/$(date +%Y%m%d_%H%M%S)_$(basename $file)"

    echo "[+] File quarantined"
}

collect_forensics() {
    local output_dir="/tmp/forensics_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"

    echo "[*] Collecting forensic data..."

    # System info
    uname -a > "$output_dir/system_info.txt"
    date >> "$output_dir/system_info.txt"

    # Processes
    ps auxf > "$output_dir/processes.txt"

    # Network
    ss -tulpn > "$output_dir/network_connections.txt"
    netstat -rn > "$output_dir/routes.txt"

    # Users
    who > "$output_dir/logged_in_users.txt"
    last > "$output_dir/login_history.txt"

    # Recent files
    find /tmp /var/tmp -mmin -60 -ls > "$output_dir/recent_files.txt" 2>/dev/null

    # Memory info
    free -m > "$output_dir/memory.txt"

    # Create archive
    tar -czf "${output_dir}.tar.gz" -C "$(dirname $output_dir)" "$(basename $output_dir)"

    echo "[+] Forensics collected: ${output_dir}.tar.gz"
}

case "$ACTION" in
    isolate)    isolate_host ;;
    kill)       kill_process "$TARGET" ;;
    quarantine) quarantine_file "$TARGET" ;;
    collect)    collect_forensics ;;
    *)          usage ;;
esac
```

---

## EDR Metrics and KPIs

### Detection Effectiveness

```
Key Metrics:

1. Mean Time to Detect (MTTD)
   - Time from attack start to detection
   - Goal: < 1 minute for BadUSB

2. Mean Time to Respond (MTTR)
   - Time from detection to containment
   - Goal: < 5 minutes

3. False Positive Rate
   - Percentage of alerts that are benign
   - Goal: < 10%

4. Coverage
   - Percentage of endpoints with EDR
   - Goal: 100%
```

### Monitoring Dashboard Script

```bash
#!/bin/bash
#######################################
# EDR Metrics Dashboard
#######################################

ALERT_LOG="/var/log/edr_alerts.log"

clear
echo "╔════════════════════════════════════════════════════════════╗"
echo "║               EDR Metrics Dashboard                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Total alerts today
TOTAL=$(grep "$(date '+%Y-%m-%d')" "$ALERT_LOG" 2>/dev/null | wc -l)
echo "Alerts Today: $TOTAL"

# By severity
echo ""
echo "By Severity:"
echo "  CRITICAL: $(grep "$(date '+%Y-%m-%d')" "$ALERT_LOG" 2>/dev/null | grep -c CRITICAL)"
echo "  HIGH:     $(grep "$(date '+%Y-%m-%d')" "$ALERT_LOG" 2>/dev/null | grep -c HIGH)"
echo "  MEDIUM:   $(grep "$(date '+%Y-%m-%d')" "$ALERT_LOG" 2>/dev/null | grep -c MEDIUM)"
echo "  LOW:      $(grep "$(date '+%Y-%m-%d')" "$ALERT_LOG" 2>/dev/null | grep -c LOW)"

# Recent alerts
echo ""
echo "Recent Alerts (Last 5):"
tail -5 "$ALERT_LOG" 2>/dev/null || echo "  No alerts found"
```

---

[← Back to Security Operations](../README.md)
