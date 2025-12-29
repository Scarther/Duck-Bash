# Lab Environment Setup Guide

## Overview

This guide provides complete instructions for setting up an isolated lab environment for BadUSB and WiFi security training.

---

## Minimum Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8 GB | 16 GB |
| CPU | 4 cores | 8 cores |
| Storage | 100 GB | 250 GB |
| Network | Isolated | Isolated + Internet VM |

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                                  │
│                     (Your physical computer)                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │
│   │  Windows 10 │    │  Windows 11 │    │   Kali     │            │
│   │   Target    │    │   Target    │    │  Attacker  │            │
│   │     VM      │    │     VM      │    │    VM      │            │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘            │
│          │                  │                  │                    │
│          └──────────────────┼──────────────────┘                    │
│                             │                                       │
│                    ┌────────┴────────┐                              │
│                    │  Isolated NAT   │                              │
│                    │    Network      │                              │
│                    │  192.168.100.0  │                              │
│                    └─────────────────┘                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## VM Setup Scripts

### 1. Create Isolated Network (VirtualBox)

```bash
#!/bin/bash
#######################################
# Create Isolated Lab Network
# For VirtualBox
#######################################

NETWORK_NAME="BadUSB_Lab"
NETWORK_CIDR="192.168.100.0/24"
DHCP_LOW="192.168.100.100"
DHCP_HIGH="192.168.100.200"

echo "[*] Creating isolated NAT network: $NETWORK_NAME"

# Create NAT network
VBoxManage natnetwork add \
    --netname "$NETWORK_NAME" \
    --network "$NETWORK_CIDR" \
    --enable \
    --dhcp on

# Configure DHCP
VBoxManage natnetwork modify \
    --netname "$NETWORK_NAME" \
    --dhcp on \
    --dhcp-server-ip 192.168.100.1 \
    --lower-ip "$DHCP_LOW" \
    --upper-ip "$DHCP_HIGH"

echo "[+] Network created successfully"
echo "[*] Attach VMs to network: $NETWORK_NAME"
```

### 2. Windows Target VM Setup

```powershell
#######################################
# Windows Target VM Configuration
# Run as Administrator
#######################################

Write-Host "[*] Configuring Windows target VM for BadUSB training..."

# Enable PowerShell logging (for Blue Team training)
$logPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# Script Block Logging
New-Item -Path "$logPath\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$logPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Module Logging
New-Item -Path "$logPath\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "$logPath\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Transcription
New-Item -Path "$logPath\Transcription" -Force | Out-Null
Set-ItemProperty -Path "$logPath\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "$logPath\Transcription" -Name "OutputDirectory" -Value "C:\PSLogs"
New-Item -Path "C:\PSLogs" -ItemType Directory -Force | Out-Null

# Enable command line in process creation events
$auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $auditPath -Force | Out-Null
Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# Install Sysmon (download separately)
Write-Host "[*] Download Sysmon from: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"

Write-Host "[+] Windows target configured for training"
Write-Host "[*] Restart required for some settings"
```

### 3. Kali Attacker VM Setup

```bash
#!/bin/bash
#######################################
# Kali Attacker VM Setup
# BadUSB Training Configuration
#######################################

echo "[*] Configuring Kali for BadUSB training..."

# Update system
apt update && apt upgrade -y

# Install essential tools
apt install -y \
    git \
    python3-pip \
    golang \
    aircrack-ng \
    hashcat \
    john \
    wireshark \
    tcpdump \
    nmap \
    netcat-openbsd \
    dnsutils \
    curl \
    wget

# Install Python tools
pip3 install \
    scapy \
    requests \
    flask \
    pyautogui

# Create lab directories
mkdir -p ~/lab/{payloads,loot,logs,tools}

# Clone useful repositories
cd ~/lab/tools
git clone https://github.com/hak5/usbrubberducky-payloads.git 2>/dev/null || true
git clone https://github.com/I-Am-Jakoby/Flipper-Zero-BadUSB.git 2>/dev/null || true

# Create simple HTTP server script for exfil testing
cat > ~/lab/tools/exfil_server.py << 'EOF'
#!/usr/bin/env python3
"""Simple HTTP server for receiving exfiltrated data"""
from flask import Flask, request
import datetime

app = Flask(__name__)

@app.route('/collect', methods=['POST', 'GET'])
def collect():
    timestamp = datetime.datetime.now().isoformat()
    data = request.data.decode() if request.data else request.args.to_dict()

    with open('/root/lab/loot/collected.log', 'a') as f:
        f.write(f"[{timestamp}]\n{data}\n{'='*50}\n")

    print(f"[+] Data received: {data[:100]}...")
    return "OK"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

chmod +x ~/lab/tools/exfil_server.py

echo "[+] Kali attacker VM configured"
echo "[*] Start exfil server: python3 ~/lab/tools/exfil_server.py"
```

---

## USB Passthrough Configuration

### VirtualBox USB Setup

```bash
#!/bin/bash
# Enable USB passthrough for Flipper Zero

# Add user to vboxusers group
sudo usermod -aG vboxusers $USER

# Create udev rule for Flipper Zero
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="0483", ATTR{idProduct}=="5740", MODE="0666"' | \
    sudo tee /etc/udev/rules.d/99-flipper.rules

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

echo "[+] USB passthrough configured"
echo "[*] Log out and back in for group changes"
```

### VMware USB Setup

```
1. VM Settings → USB Controller
2. Select "USB 3.0" compatibility
3. Check "Show all USB input devices"
4. Connect Flipper Zero and select "Connect to VM"
```

---

## Network Isolation Verification

```bash
#!/bin/bash
#######################################
# Verify Lab Network Isolation
#######################################

echo "[*] Verifying network isolation..."

# Check if we can reach the internet
if ping -c 1 8.8.8.8 &>/dev/null; then
    echo "[WARNING] Internet is reachable - lab may not be isolated"
else
    echo "[OK] Cannot reach internet"
fi

# Check local network
if ping -c 1 192.168.100.1 &>/dev/null; then
    echo "[OK] Lab network gateway reachable"
else
    echo "[ERROR] Cannot reach lab network gateway"
fi

# List network interfaces
echo ""
echo "[*] Network interfaces:"
ip addr show | grep -E "^[0-9]+:|inet "

# Check routing
echo ""
echo "[*] Routing table:"
ip route
```

---

## Snapshot Strategy

```
Recommended Snapshots:
├── Windows Target
│   ├── "Clean Install" - Fresh Windows
│   ├── "Logging Enabled" - With PowerShell/Sysmon logging
│   └── "Vulnerable" - With deliberate misconfigurations
│
├── Kali Attacker
│   ├── "Clean Install" - Fresh Kali
│   └── "Tools Ready" - With all tools configured
│
└── Take snapshots BEFORE each exercise
    └── Restore after to clean state
```

---

## Quick Start Commands

### Start Lab VMs
```bash
# Start all lab VMs
VBoxManage startvm "Windows10-Target" --type headless
VBoxManage startvm "Kali-Attacker" --type gui
```

### Connect to VMs
```bash
# SSH to Kali (if configured)
ssh root@192.168.100.x

# RDP to Windows (from Kali)
xfreerdp /v:192.168.100.x /u:user /p:password
```

### Reset Lab
```bash
# Restore all VMs to clean snapshots
VBoxManage snapshot "Windows10-Target" restore "Logging Enabled"
VBoxManage snapshot "Kali-Attacker" restore "Tools Ready"
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| USB not passing through | Add user to vboxusers, restart |
| Network not isolated | Check NAT network config |
| Flipper not recognized | Install udev rules, reconnect |
| PowerShell logs missing | Run setup as Admin, restart |

---

[← Back to Technical Addendum](../README.md)
