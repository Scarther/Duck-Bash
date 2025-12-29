# Lab Environment Setup

## Overview

A proper lab environment is essential for safe payload development and testing. This guide covers setting up isolated test environments for both USB and wireless attacks.

---

## USB BadUSB Testing Lab

### Virtual Machine Setup

#### Recommended VMs
| Purpose | OS | Notes |
|---------|----|----|
| Primary Target | Windows 10/11 | Fully patched |
| Legacy Target | Windows 7 | Unpatched for testing |
| macOS Target | macOS VM | For Apple testing |
| Linux Target | Ubuntu/Kali | General Linux |

#### VM Configuration
```
Hypervisor: VirtualBox, VMware, or Hyper-V

Windows Test VM:
├── RAM: 4 GB minimum
├── Disk: 60 GB
├── Network: NAT or Isolated
├── USB: Enable USB passthrough
└── Snapshots: Clean state + various configs

Snapshot Strategy:
├── Base Install (clean)
├── Post-Updates
├── With AV Enabled
├── With AV Disabled
└── Domain Joined (if applicable)
```

### USB Passthrough Configuration

#### VirtualBox
```bash
# Add user to vboxusers group (Linux host)
sudo usermod -aG vboxusers $USER

# VM Settings:
# Settings → USB → Enable USB Controller
# Add USB Device Filter for Flipper/Ducky
```

#### VMware
```
# VM Settings → USB Controller
# Select "USB 3.0" or "USB 2.0"
# Check "Show all USB input devices"
# Check "Automatically connect new USB devices"
```

### Isolated Network Setup
```
┌─────────────────────────────────────────────────────────────┐
│                    USB LAB NETWORK                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐           │
│   │ Host PC  │     │ Target   │     │ Logging  │           │
│   │ (dev)    │────▶│   VM     │────▶│  Server  │           │
│   └──────────┘     └──────────┘     └──────────┘           │
│        │                │                │                  │
│        │    USB         │                │                  │
│        │  Passthrough   │                │                  │
│        ▼                ▼                ▼                  │
│   ┌─────────────────────────────────────────────┐          │
│   │              Isolated Network               │          │
│   │              (No internet)                  │          │
│   └─────────────────────────────────────────────┘          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Wireless Testing Lab

### Hardware Requirements

#### Minimum Setup
| Item | Purpose | Recommendation |
|------|---------|----------------|
| WiFi Adapter 1 | Monitor/Attack | Alfa AWUS036ACH |
| WiFi Adapter 2 | Client Simulation | Any supported |
| Access Point | Target Network | Dedicated router |
| Faraday Bag | RF Isolation | Commercial bag |

#### Recommended Setup
```
Full Lab Equipment:
├── WiFi Pineapple (Mark VII or Nano)
├── 2-3 USB WiFi adapters
│   ├── Alfa AWUS036ACH (RTL8812AU)
│   ├── Alfa AWUS036ACM (MT7612U)
│   └── Panda PAU09 (RT5572)
├── Dedicated test router
├── Faraday cage/bag
├── Spectrum analyzer (optional)
└── Client devices (phones, laptops)
```

### RF Isolation

#### Faraday Cage/Bag
```
Purpose: Prevent RF leakage during testing

Options:
├── Commercial Faraday bag (~$30-100)
├── DIY Faraday cage (metal mesh)
├── Shielded room (professional)
└── Low-power testing + physical distance

Testing Isolation:
1. Place all wireless devices in Faraday enclosure
2. Verify no external signals inside
3. Verify no internal signals outside
4. Monitor with spectrum analyzer
```

#### Low-Power Testing
```bash
# Reduce TX power to minimize leakage
iw dev wlan0 set txpower fixed 100   # 1 dBm

# Very low for close-range testing
iw dev wlan0 set txpower fixed 0     # Minimum
```

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                 WIRELESS LAB TOPOLOGY                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────────────────────────────────────────────┐  │
│   │                   FARADAY ENCLOSURE                  │  │
│   │                                                       │  │
│   │   ┌──────────┐   ┌──────────┐   ┌──────────┐        │  │
│   │   │  Target  │   │  WiFi    │   │  Test    │        │  │
│   │   │    AP    │◄──│ Pineapple│◄──│ Client   │        │  │
│   │   └──────────┘   └──────────┘   └──────────┘        │  │
│   │       ▲               ▲               ▲              │  │
│   │       │               │               │              │  │
│   │       └───────────────┼───────────────┘              │  │
│   │                       │                              │  │
│   │              ┌────────┴────────┐                     │  │
│   │              │   Test Laptop   │                     │  │
│   │              │   (monitoring)  │                     │  │
│   │              └─────────────────┘                     │  │
│   │                                                       │  │
│   └─────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Target Network Configuration

### WPA2-Personal Test Network
```bash
# Router configuration:
SSID: TestNetwork
Security: WPA2-Personal
Password: TestPassword123  # Known for testing
Channel: 6 (fixed)
Band: 2.4 GHz
```

### WPA2-Enterprise Test Network
```bash
# FreeRADIUS setup for testing

# Install
apt install freeradius freeradius-utils

# Configure users (/etc/freeradius/3.0/users)
testuser Cleartext-Password := "testpass123"

# Start RADIUS
systemctl start freeradius

# Configure AP for RADIUS
# Server: <RADIUS_IP>
# Port: 1812
# Secret: testing123
```

### Open Network with Captive Portal
```bash
# For captive portal testing
# Use lightweight HTTP server

# Start web server
python3 -m http.server 80

# DNS redirect (dnsmasq)
address=/#/192.168.1.1
```

---

## Monitoring Setup

### Traffic Capture
```bash
# Capture all traffic
tcpdump -i wlan0 -w /tmp/capture.pcap

# Monitor mode capture
airmon-ng start wlan0
airodump-ng wlan0mon -w /tmp/scan

# Wireshark filter for testing
wlan.bssid == AA:BB:CC:DD:EE:FF
```

### Logging Configuration

#### Windows Event Logging
```powershell
# Enable PowerShell logging
# Group Policy: Administrative Templates → Windows Components → PowerShell

# Enable ScriptBlock Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable Module Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
```

#### Sysmon Installation
```powershell
# Download Sysmon
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with default config
sysmon64.exe -accepteula -i

# Install with SwiftOnSecurity config
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

---

## Safety Checklist

### Before Testing
```
□ VMs have current snapshots
□ Network is isolated (no internet access)
□ Faraday enclosure in use (wireless)
□ Low TX power configured
□ Logging enabled
□ No production systems connected
□ Authorization documented
```

### During Testing
```
□ Monitor for RF leakage
□ Check network isolation
□ Log all activities
□ Use dedicated test credentials
□ Don't use production data
□ Time-limit sessions
```

### After Testing
```
□ Revert VM snapshots
□ Clear test credentials
□ Archive logs
□ Document findings
□ Secure captured data
□ Clean up tools
```

---

## Quick Lab Scripts

### VM Snapshot Script
```bash
#!/bin/bash
# Snapshot management for VirtualBox

VM_NAME="Windows10-Test"

# Create snapshot
VBoxManage snapshot "$VM_NAME" take "pre-test-$(date +%Y%m%d_%H%M%S)"

# List snapshots
VBoxManage snapshot "$VM_NAME" list

# Restore to snapshot
VBoxManage snapshot "$VM_NAME" restore "clean-state"
```

### Wireless Lab Reset
```bash
#!/bin/bash
# Reset wireless lab environment

# Stop services
sudo systemctl stop hostapd dnsmasq

# Reset interfaces
sudo airmon-ng stop wlan0mon 2>/dev/null
sudo ip addr flush dev wlan0
sudo systemctl restart NetworkManager

# Clear temp files
rm -f /tmp/*.cap /tmp/*.csv

echo "Wireless lab reset complete"
```

### Monitoring Start Script
```bash
#!/bin/bash
# Start lab monitoring

LOG_DIR="/var/log/lab/$(date +%Y%m%d)"
mkdir -p "$LOG_DIR"

# Start tcpdump
tcpdump -i any -w "$LOG_DIR/traffic.pcap" &

# Start process monitor
ps auxf > "$LOG_DIR/processes_start.txt"

# Monitor USB events
udevadm monitor --udev > "$LOG_DIR/usb_events.txt" &

echo "Monitoring started. Logs in $LOG_DIR"
```

---

[← Cracking Reference](../07_Cracking_Reference/) | [Back to Technical Addendum](../README.md) | [Next: Tool Integration →](../09_Tool_Integration/)
