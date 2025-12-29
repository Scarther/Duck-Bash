# Basic WiFi Pineapple Payloads (PP-B01 to PP-B10)

## Overview

Basic payloads introduce fundamental WiFi Pineapple operations: scanning, monitoring, and simple automation.

### Skill Level Characteristics
- **Code Length**: 10-50 lines Bash
- **Purpose**: Learning device capabilities
- **Risk**: Low - mostly passive/read-only
- **Complexity**: Simple logic, clear output

---

## Payload Index

| ID | Name | Type | Description |
|----|------|------|-------------|
| [PP-B01](PP-B01_Hello_World.md) | Hello World | Test | Verify device functionality |
| [PP-B02](PP-B02_Handshake_Alert.md) | Handshake Alert | Alert | Notify on capture |
| [PP-B03](PP-B03_Client_Alert.md) | Client Alert | Alert | Notify on connection |
| [PP-B04](PP-B04_Basic_Scan.md) | Basic Scan | Recon | Scan nearby networks |
| [PP-B05](PP-B05_Deauth_Test.md) | Deauth Test | Test | Send test deauth |
| [PP-B06](PP-B06_System_Status.md) | System Status | Info | Display status |
| [PP-B07](PP-B07_Battery_Check.md) | Battery Check | Info | Battery level |
| [PP-B08](PP-B08_Interface_Status.md) | Interface Status | Info | Check interfaces |
| [PP-B09](PP-B09_Log_Viewer.md) | Log Viewer | Info | View logs |
| [PP-B10](PP-B10_Quick_Recon.md) | Quick Recon | Recon | Fast summary |

---

## Bash Basics for Pineapple

### Script Structure

```bash
#!/bin/bash
#
# Payload: PP-BXX
# Description: What this payload does
# Type: User/Alert/Recon
#

# Variables
INTERFACE="wlan1"
OUTPUT="/tmp/output.txt"

# Main logic
echo "Starting payload..."

# Cleanup (optional)
echo "Complete"
```

### Common Commands

| Command | Purpose |
|---------|---------|
| `iwconfig` | View wireless interface settings |
| `airmon-ng` | Enable/disable monitor mode |
| `airodump-ng` | Capture wireless traffic |
| `aireplay-ng` | Inject packets (deauth, etc.) |
| `hostapd` | Create access points |
| `dnsmasq` | DHCP/DNS for rogue AP |

---

## Learning Objectives

After completing Basic payloads:
- [ ] Understand Pineapple file structure
- [ ] Write basic Bash scripts
- [ ] Scan for nearby networks
- [ ] Monitor wireless traffic
- [ ] Use PineAP features

---

[← Back to Chapter 02](../README.md) | [Next: PP-B01 Hello World →](PP-B01_Hello_World.md)
