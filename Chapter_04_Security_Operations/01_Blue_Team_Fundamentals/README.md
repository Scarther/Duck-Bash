# Chapter 4.1: Blue Team Fundamentals

## What is Blue Team?

The **Blue Team** is responsible for defending organizations against cyber attacks. While Red Team simulates attackers, Blue Team protects, detects, and responds to threats.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      RED TEAM vs BLUE TEAM                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│        RED TEAM                              BLUE TEAM                       │
│        ────────                              ─────────                       │
│                                                                              │
│   ┌─────────────┐                       ┌─────────────┐                     │
│   │  ATTACK     │                       │  DEFEND     │                     │
│   │  SIMULATE   │ ◀──── Adversary ────▶ │  PROTECT    │                     │
│   │  EXPLOIT    │       Simulation      │  DETECT     │                     │
│   └─────────────┘                       └─────────────┘                     │
│                                                                              │
│   • Penetration testing                  • Security monitoring               │
│   • Vulnerability assessment             • Incident response                 │
│   • Social engineering                   • Threat hunting                    │
│   • Physical security testing            • Security hardening                │
│                                                                              │
│   Goal: Find weaknesses                  Goal: Prevent/detect attacks        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why Blue Team Matters for This Training

Even if you're learning offensive techniques (DuckyScript, wireless attacks), understanding defense is crucial:

1. **Better Attacks**: Know what defenders look for → evade detection
2. **Complete Picture**: Security requires both perspectives
3. **Real Value**: Most jobs are defensive security
4. **Ethical Requirement**: Know how to protect, not just attack

---

## Core Blue Team Concepts

### 1. Defense in Depth

Never rely on a single security control. Layer your defenses:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DEFENSE IN DEPTH                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   LAYER 1: PHYSICAL                                                          │
│   ──────────────────                                                         │
│   • Locked doors, badge access                                               │
│   • Security cameras                                                         │
│   • USB port blockers                     ← Stops BadUSB at source!          │
│                                                                              │
│   LAYER 2: NETWORK                                                           │
│   ────────────────                                                           │
│   • Firewalls                                                                │
│   • IDS/IPS                              ← Detects Pineapple attacks         │
│   • Network segmentation                                                     │
│   • Wireless monitoring                  ← Detects rogue APs                 │
│                                                                              │
│   LAYER 3: ENDPOINT                                                          │
│   ─────────────────                                                          │
│   • Antivirus/EDR                        ← Detects malicious payloads        │
│   • Host-based firewall                                                      │
│   • Application whitelisting                                                 │
│   • USB device control                   ← Blocks unknown HID devices        │
│                                                                              │
│   LAYER 4: APPLICATION                                                       │
│   ────────────────────                                                       │
│   • Input validation                                                         │
│   • Authentication/Authorization                                             │
│   • Secure coding practices                                                  │
│                                                                              │
│   LAYER 5: DATA                                                              │
│   ─────────────                                                              │
│   • Encryption                                                               │
│   • Access controls                                                          │
│   • DLP (Data Loss Prevention)           ← Detects data exfiltration         │
│                                                                              │
│   An attacker must bypass ALL layers to succeed.                             │
│   A defender only needs ONE layer to detect/stop the attack.                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 2. The Cyber Kill Chain

Understanding how attacks progress helps defenders interrupt them:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CYBER KILL CHAIN                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STAGE              DESCRIPTION                 DEFENSE OPPORTUNITY         │
│  ─────              ───────────                 ───────────────────         │
│                                                                              │
│  1. RECONNAISSANCE  Research the target         Monitor for scanning        │
│     └── BadUSB: N/A (physical access)          Network monitoring           │
│     └── Pineapple: WiFi scanning               WIDS alerts                  │
│                                                                              │
│  2. WEAPONIZATION   Create the attack payload   N/A (happens off-site)      │
│     └── BadUSB: Write DuckyScript                                           │
│     └── Pineapple: Configure attack                                         │
│                                                                              │
│  3. DELIVERY        Get payload to target       Physical security           │
│     └── BadUSB: Insert USB device              USB port controls            │
│     └── Pineapple: Deploy near target          RF detection                 │
│                                                                              │
│  4. EXPLOITATION    Execute the payload         EDR, App control            │
│     └── BadUSB: Keystrokes execute             Process monitoring           │
│     └── Pineapple: Capture handshakes          Wireless IDS                 │
│                                                                              │
│  5. INSTALLATION    Establish persistence       Endpoint monitoring         │
│     └── BadUSB: Registry, scheduled tasks      Change detection             │
│     └── Pineapple: N/A (external device)                                    │
│                                                                              │
│  6. COMMAND & CTRL  Establish communication     Network monitoring          │
│     └── BadUSB: Reverse shell, beacon          Firewall, proxy              │
│     └── Pineapple: Direct control              Traffic analysis             │
│                                                                              │
│  7. ACTIONS ON OBJ  Achieve attacker's goal     DLP, monitoring             │
│     └── BadUSB: Data theft, ransomware         Data loss prevention         │
│     └── Pineapple: Credential capture          Password policies            │
│                                                                              │
│  KEY INSIGHT: The earlier you detect, the easier to stop!                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 3. MITRE ATT&CK Framework

A knowledge base of adversary tactics and techniques:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     MITRE ATT&CK OVERVIEW                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TACTIC = WHY (the attacker's goal)                                          │
│  TECHNIQUE = HOW (method to achieve goal)                                    │
│                                                                              │
│  RELEVANT TACTICS FOR BADUSB:                                                │
│  ────────────────────────────                                                │
│  • Initial Access (T1200 - Hardware Additions)                               │
│  • Execution (T1059.001 - PowerShell)                                        │
│  • Persistence (T1547.001 - Registry Run Keys)                               │
│  • Credential Access (T1555 - Credentials from Password Stores)              │
│  • Exfiltration (T1041 - Exfiltration Over C2 Channel)                       │
│                                                                              │
│  RELEVANT TACTICS FOR WIFI PINEAPPLE:                                        │
│  ─────────────────────────────────────                                       │
│  • Initial Access (T1557.002 - ARP Cache Poisoning)                          │
│  • Credential Access (T1040 - Network Sniffing)                              │
│  • Collection (T1557 - Adversary in the Middle)                              │
│                                                                              │
│  For each technique, ATT&CK provides:                                        │
│  • Description                                                               │
│  • Detection methods                                                         │
│  • Mitigation strategies                                                     │
│  • Real-world examples                                                       │
│                                                                              │
│  Website: https://attack.mitre.org                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detecting BadUSB Attacks

### What to Monitor

| Indicator | Detection Method | Tool |
|-----------|------------------|------|
| New USB HID device | USB device logging | Windows Event Log, udev |
| Rapid keystrokes | Input rate monitoring | EDR, custom scripts |
| PowerShell -w hidden | Command line logging | Sysmon, Event ID 4688 |
| Registry Run key changes | Registry monitoring | Sysmon, Event ID 4657 |
| Suspicious processes | Process monitoring | EDR, Event ID 4688 |

### Detection Script (Windows PowerShell)

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitor for potential BadUSB attacks
.DESCRIPTION
    Watches for new HID devices and suspicious command patterns
#>

# Function to check recent USB events
function Get-RecentUSBDevices {
    Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-PnP'
        StartTime = (Get-Date).AddMinutes(-10)
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match 'HID|keyboard'
    }
}

# Function to check suspicious PowerShell
function Get-SuspiciousPowerShell {
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        StartTime = (Get-Date).AddMinutes(-10)
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match 'hidden|bypass|downloadstring|invoke-expression'
    }
}

# Main monitoring loop
Write-Host "Monitoring for BadUSB indicators..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray

while ($true) {
    # Check USB events
    $usbEvents = Get-RecentUSBDevices
    if ($usbEvents) {
        Write-Warning "New USB HID device detected!"
        $usbEvents | Format-List TimeCreated, Message
    }

    # Check PowerShell events
    $psEvents = Get-SuspiciousPowerShell
    if ($psEvents) {
        Write-Warning "Suspicious PowerShell activity!"
        $psEvents | Format-List TimeCreated, Message
    }

    Start-Sleep -Seconds 5
}
```

---

## Detecting WiFi Pineapple Attacks

### What to Monitor

| Attack | Indicator | Detection |
|--------|-----------|-----------|
| Rogue AP | SSID from unknown BSSID | WIDS, manual scanning |
| Deauth | High volume of deauth frames | Wireless IDS |
| Evil Twin | Duplicate SSID | WIDS, signal triangulation |
| Handshake Capture | Deauth followed by client reconnect | Traffic analysis |

### Detection Script (Linux Bash)

```bash
#!/bin/bash
#######################################
# WiFi Pineapple Detection Script
# Purpose: Monitor for rogue APs and attacks
#######################################

# Configuration
INTERFACE="wlan0"
KNOWN_APS_FILE="/etc/security/known_aps.txt"
LOG_FILE="/var/log/wifi_security.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Create known APs file if it doesn't exist
if [ ! -f "$KNOWN_APS_FILE" ]; then
    log "Creating known APs file. Please add your legitimate APs."
    touch "$KNOWN_APS_FILE"
fi

# Start monitoring
log "Starting WiFi security monitoring..."

# Enable monitor mode
airmon-ng start "$INTERFACE" > /dev/null 2>&1
MON_IF="${INTERFACE}mon"

# Continuous scan
while true; do
    # Quick scan
    timeout 10 airodump-ng "$MON_IF" -w /tmp/scan --output-format csv 2>/dev/null

    if [ -f /tmp/scan-01.csv ]; then
        # Check each detected AP
        while IFS=',' read -r bssid _ _ _ _ _ _ _ _ _ _ _ _ essid _; do
            # Skip empty lines and header
            [[ "$bssid" =~ ^BSSID ]] && continue
            [[ -z "$essid" ]] && continue

            # Check if AP is known
            if ! grep -q "$bssid" "$KNOWN_APS_FILE" 2>/dev/null; then
                # Unknown AP detected
                log "ALERT: Unknown AP detected - BSSID: $bssid, SSID: $essid"

                # Check if SSID matches a known network (potential evil twin)
                if grep -q "$essid" "$KNOWN_APS_FILE" 2>/dev/null; then
                    log "CRITICAL: Possible Evil Twin attack! SSID '$essid' from unknown BSSID"
                fi
            fi
        done < /tmp/scan-01.csv

        rm -f /tmp/scan-01.csv
    fi

    sleep 30
done
```

---

## Prevention Controls

### For BadUSB

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| USB Device Control | Whitelist by VID/PID | High |
| Physical Port Locks | USB port blockers | High |
| USB Guard (Linux) | USBGuard daemon | High |
| GPO Restrictions | Device Installation policies | Medium |
| User Awareness | Training on USB risks | Medium |

### For WiFi Attacks

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| WPA3 | Upgrade wireless security | High |
| WIDS/WIPS | Deploy wireless IDS | High |
| 802.1X | Certificate-based auth | High |
| Network Segmentation | Isolate WiFi traffic | Medium |
| Regular Audits | Authorized pen testing | Medium |

---

## Blue Team Tools

### For BadUSB Detection

| Tool | Purpose | Platform |
|------|---------|----------|
| USBGuard | Block unauthorized USB devices | Linux |
| Device Control (GPO) | USB policy enforcement | Windows |
| Sysmon | Advanced logging | Windows |
| CrowdStrike/SentinelOne | EDR with USB monitoring | All |

### For WiFi Security

| Tool | Purpose | Platform |
|------|---------|----------|
| Kismet | Wireless IDS | Linux |
| airodump-ng | Network monitoring | Linux |
| Cisco WIDS | Enterprise wireless IDS | Cisco |
| Aruba/Mist | Cloud-managed WIDS | Enterprise |

---

## Practice: Build Your Detection Lab

### Step 1: Enable Enhanced Logging

```powershell
# Windows - Enable command line logging
# Run as Administrator

# Enable Process Creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable PowerShell logging
$basePath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
New-Item -Path "$basePath\ScriptBlockLogging" -Force
Set-ItemProperty -Path "$basePath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable Module logging
New-Item -Path "$basePath\ModuleLogging" -Force
Set-ItemProperty -Path "$basePath\ModuleLogging" -Name "EnableModuleLogging" -Value 1
```

### Step 2: Install Sysmon

```powershell
# Download Sysmon from Microsoft Sysinternals
# Install with default config
sysmon64 -accepteula -i

# Or with custom config for BadUSB detection
sysmon64 -accepteula -i sysmon-config.xml
```

### Step 3: Test Your Detection

1. Run a simple BadUSB payload (Hello World)
2. Check your logs:
   - Event ID 4688: Process creation
   - Event ID 1 (Sysmon): Process creation with command line
   - PowerShell Operational log: Script execution
3. Write detection rules for what you see

---

## Summary

**Key Blue Team Concepts**:
- Defense in Depth: Layer your security
- Kill Chain: Understand attack progression
- MITRE ATT&CK: Standardized framework
- Detection: Know what to look for
- Prevention: Controls to stop attacks

**Detection Priorities for This Training**:
- USB device monitoring
- Process and command line logging
- Wireless network monitoring
- Registry and persistence monitoring

---

## Next Steps

1. **[Security Monitoring & SIEM](../02_Security_Monitoring_SIEM/)** - Centralized log analysis
2. **[EDR Deep Dive](../03_EDR/)** - Endpoint Detection and Response
3. **[Building Detection Rules](../02_Security_Monitoring_SIEM/Writing_Detection_Rules.md)** - Create your own rules

---

[← Back to Security Operations](../README.md) | [Next: Security Monitoring & SIEM →](../02_Security_Monitoring_SIEM/)
