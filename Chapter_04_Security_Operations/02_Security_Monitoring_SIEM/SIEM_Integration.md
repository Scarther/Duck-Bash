# SIEM Integration Guide

## Overview

This guide covers Security Information and Event Management (SIEM) integration for detecting BadUSB attacks and related threats.

---

## SIEM Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SIEM ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   DATA SOURCES                    SIEM PLATFORM                      │
│   ┌──────────────┐               ┌──────────────────────────────┐   │
│   │ Endpoints    │───────────────│  Collection & Parsing        │   │
│   │ (Sysmon,     │               ├──────────────────────────────┤   │
│   │  EDR, AV)    │               │  Normalization               │   │
│   ├──────────────┤               ├──────────────────────────────┤   │
│   │ Network      │───────────────│  Correlation Engine          │   │
│   │ (Firewall,   │               ├──────────────────────────────┤   │
│   │  IDS/IPS)    │               │  Detection Rules             │   │
│   ├──────────────┤               ├──────────────────────────────┤   │
│   │ Applications │───────────────│  Alerting                    │   │
│   │ (Web, DB,    │               ├──────────────────────────────┤   │
│   │  Auth)       │               │  Dashboards & Reporting      │   │
│   └──────────────┘               └──────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Log Source Configuration

### Windows Event Forwarding

```powershell
#######################################
# Windows Event Forwarding Setup
# Forward security events to SIEM
#######################################

# Enable Windows Remote Management
winrm quickconfig -force

# Configure event subscription
$subscription = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>BadUSB-Detection</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Forward security events for BadUSB detection</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Custom</ConfigurationMode>
    <Query>
        <![CDATA[
        <QueryList>
            <Query Id="0" Path="Security">
                <Select Path="Security">*[System[(EventID=4688)]]</Select>
                <Select Path="Security">*[System[(EventID=6416)]]</Select>
            </Query>
            <Query Id="1" Path="Microsoft-Windows-Sysmon/Operational">
                <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
            </Query>
            <Query Id="2" Path="Microsoft-Windows-PowerShell/Operational">
                <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4104)]]</Select>
            </Query>
        </QueryList>
        ]]>
    </Query>
</Subscription>
"@

# Apply subscription
wecutil cs subscription.xml
```

### Syslog Configuration (Linux)

```bash
#!/bin/bash
#######################################
# Rsyslog Configuration for SIEM
#######################################

SIEM_SERVER="192.168.1.100"
SIEM_PORT="514"

cat > /etc/rsyslog.d/50-siem.conf << EOF
# Forward all logs to SIEM
*.* @${SIEM_SERVER}:${SIEM_PORT}

# Forward specific facilities
auth,authpriv.* @${SIEM_SERVER}:${SIEM_PORT}
kern.* @${SIEM_SERVER}:${SIEM_PORT}

# Include structured data
\$ActionFileDefaultTemplate RSYSLOG_SyslogProtocol23Format
EOF

# Restart rsyslog
systemctl restart rsyslog

echo "[+] Syslog forwarding configured to $SIEM_SERVER:$SIEM_PORT"
```

---

## Splunk Integration

### BadUSB Detection Searches

```spl
# Splunk Search: USB Device Connections
index=windows sourcetype=WinEventLog:Security EventCode=6416
| stats count by dest, DeviceDescription, ClassGuid
| sort -count

# Splunk Search: Rapid PowerShell Execution after USB
index=windows sourcetype=WinEventLog:Security EventCode=6416
| join dest [search index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104]
| where _time - usb_time < 30
| table _time, dest, ScriptBlockText

# Splunk Search: Suspicious Process Spawning
index=windows sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| where ParentImage LIKE "%explorer.exe"
| where (Image LIKE "%powershell.exe" OR Image LIKE "%cmd.exe")
| where CommandLine LIKE "%-w hidden%" OR CommandLine LIKE "%-ep bypass%"
| table _time, Computer, User, Image, CommandLine
```

### Splunk Alert Configuration

```spl
# Alert: BadUSB Keystroke Injection Pattern
index=windows sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| where ParentImage LIKE "%explorer.exe"
| where Image LIKE "%powershell.exe" OR Image LIKE "%cmd.exe"
| bin _time span=10s
| stats count by _time, Computer
| where count > 5
| table _time, Computer, count

# Alert settings:
# Trigger: Number of results > 0
# Throttle: 5 minutes per Computer
# Action: Send to SOC queue
```

### Splunk Dashboard XML

```xml
<dashboard>
  <label>BadUSB Detection Dashboard</label>
  <row>
    <panel>
      <title>USB Device Connections (24h)</title>
      <chart>
        <search>
          <query>
            index=windows sourcetype=WinEventLog:Security EventCode=6416
            | timechart span=1h count by dest
          </query>
          <earliest>-24h</earliest>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
    <panel>
      <title>Suspicious PowerShell Activity</title>
      <table>
        <search>
          <query>
            index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
            | where ScriptBlockText LIKE "%-hidden%" OR ScriptBlockText LIKE "%-enc %"
            | table _time, Computer, ScriptBlockText
            | head 10
          </query>
          <earliest>-24h</earliest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Known BadUSB Device VIDs</title>
      <table>
        <search>
          <query>
            index=windows sourcetype=WinEventLog:Security EventCode=6416
            | rex field=_raw "VID_(?<VendorID>[0-9A-F]{4})"
            | where VendorID IN ("0483", "16D0", "2341", "16C0")
            | table _time, dest, VendorID, DeviceDescription
          </query>
          <earliest>-7d</earliest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

---

## Elastic SIEM Integration

### Elasticsearch Index Template

```json
{
  "index_patterns": ["badusb-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "host": {
          "properties": {
            "name": { "type": "keyword" },
            "ip": { "type": "ip" }
          }
        },
        "event": {
          "properties": {
            "type": { "type": "keyword" },
            "action": { "type": "keyword" },
            "outcome": { "type": "keyword" }
          }
        },
        "usb": {
          "properties": {
            "vendor_id": { "type": "keyword" },
            "product_id": { "type": "keyword" },
            "device_class": { "type": "keyword" }
          }
        },
        "process": {
          "properties": {
            "name": { "type": "keyword" },
            "command_line": { "type": "text" },
            "parent": {
              "properties": {
                "name": { "type": "keyword" }
              }
            }
          }
        }
      }
    }
  }
}
```

### Kibana Detection Rules

```json
{
  "name": "BadUSB Rapid Keystroke Injection",
  "description": "Detects rapid process creation after USB device connection",
  "risk_score": 75,
  "severity": "high",
  "type": "eql",
  "query": "sequence by host.name with maxspan=30s [device where event.action == \"connected\" and device.bus.type == \"usb\"] [process where event.action == \"start\" and (process.name == \"powershell.exe\" or process.name == \"cmd.exe\")]",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0001",
        "name": "Initial Access"
      },
      "technique": [
        {
          "id": "T1091",
          "name": "Replication Through Removable Media"
        }
      ]
    }
  ]
}
```

### Logstash Pipeline

```ruby
# /etc/logstash/conf.d/badusb-detection.conf

input {
  beats {
    port => 5044
    tags => ["endpoint"]
  }

  syslog {
    port => 5514
    tags => ["network"]
  }
}

filter {
  # USB device detection
  if [event][code] == "6416" {
    mutate {
      add_tag => ["usb_device"]
    }

    grok {
      match => { "message" => "VID_%{WORD:usb.vendor_id}&PID_%{WORD:usb.product_id}" }
    }

    # Check against known BadUSB VIDs
    if [usb][vendor_id] in ["0483", "16D0", "2341", "16C0"] {
      mutate {
        add_tag => ["potential_badusb"]
        add_field => { "alert.severity" => "high" }
      }
    }
  }

  # PowerShell script block detection
  if [event][code] == "4104" {
    if [ScriptBlockText] =~ /(-w\s*hidden|-ep\s*bypass|-enc\s)/ {
      mutate {
        add_tag => ["suspicious_powershell"]
        add_field => { "alert.severity" => "medium" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "badusb-%{+YYYY.MM.dd}"
  }

  # Alert on high severity
  if "potential_badusb" in [tags] {
    email {
      to => "soc@company.com"
      subject => "BadUSB Alert: %{host.name}"
      body => "Potential BadUSB device detected\n\nHost: %{host.name}\nVID: %{usb.vendor_id}\nPID: %{usb.product_id}"
    }
  }
}
```

---

## Wazuh Integration

### Wazuh Rules for BadUSB

```xml
<!-- /var/ossec/etc/rules/badusb_rules.xml -->

<group name="badusb,">

  <!-- USB Device Connection -->
  <rule id="100100" level="3">
    <if_sid>60000</if_sid>
    <field name="win.system.eventID">^6416$</field>
    <description>USB device connected</description>
    <group>usb,pci_dss_10.2.5,</group>
  </rule>

  <!-- Known BadUSB VID -->
  <rule id="100101" level="12">
    <if_sid>100100</if_sid>
    <regex>VID_0483|VID_16D0|VID_2341|VID_16C0</regex>
    <description>Potential BadUSB device detected</description>
    <group>badusb,attack,</group>
  </rule>

  <!-- Rapid PowerShell after USB -->
  <rule id="100102" level="10">
    <if_sid>91801</if_sid>
    <field name="win.system.eventID">^4104$</field>
    <field name="ScriptBlockText">-w hidden|-ep bypass</field>
    <description>Suspicious PowerShell execution (possible BadUSB)</description>
    <group>badusb,execution,</group>
  </rule>

  <!-- Process creation from explorer -->
  <rule id="100103" level="8">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.parentImage">\\explorer.exe$</field>
    <field name="win.eventdata.image">powershell.exe$|cmd.exe$</field>
    <description>Shell spawned from explorer (possible BadUSB)</description>
    <group>badusb,execution,</group>
  </rule>

</group>
```

---

## Custom SIEM Integration Script

### Log Forwarder

```bash
#!/bin/bash
#######################################
# Custom Log Forwarder
# Send structured events to SIEM
#######################################

SIEM_ENDPOINT="${SIEM_ENDPOINT:-http://siem.local:8080/api/events}"
LOG_QUEUE="/var/log/siem_queue"

mkdir -p "$LOG_QUEUE"

send_event() {
    local severity="$1"
    local event_type="$2"
    local message="$3"
    local details="$4"

    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local hostname=$(hostname)

    local json=$(cat << EOF
{
  "@timestamp": "$timestamp",
  "host": {
    "name": "$hostname"
  },
  "event": {
    "severity": "$severity",
    "type": "$event_type"
  },
  "message": "$message",
  "details": $details
}
EOF
)

    # Try to send, queue if fails
    if curl -s -X POST -H "Content-Type: application/json" \
        -d "$json" "$SIEM_ENDPOINT" > /dev/null 2>&1; then
        return 0
    else
        echo "$json" >> "$LOG_QUEUE/pending.json"
        return 1
    fi
}

# Process queued events
process_queue() {
    if [ -f "$LOG_QUEUE/pending.json" ]; then
        while IFS= read -r event; do
            if curl -s -X POST -H "Content-Type: application/json" \
                -d "$event" "$SIEM_ENDPOINT" > /dev/null 2>&1; then
                : # Success
            else
                echo "$event" >> "$LOG_QUEUE/pending_new.json"
            fi
        done < "$LOG_QUEUE/pending.json"

        mv "$LOG_QUEUE/pending_new.json" "$LOG_QUEUE/pending.json" 2>/dev/null
    fi
}

# Example usage
# send_event "high" "usb_device" "BadUSB device detected" '{"vid":"0483","pid":"5740"}'
```

---

## SIEM Use Cases for BadUSB

### Detection Use Cases

| Use Case | Data Source | Logic |
|----------|-------------|-------|
| Unknown USB VID | Windows Security 6416 | VID not in whitelist |
| Rapid keystroke | Sysmon Event 1 | Multiple process creations in <10s |
| PowerShell flags | PowerShell 4104 | Contains -w hidden, -ep bypass |
| Registry persistence | Sysmon Event 13 | Run key modification |
| Scheduled task creation | Windows Security 4698 | New task with hidden PS |

### Correlation Rules

```
Rule: BadUSB Attack Chain
Condition:
  1. USB device connection (6416) within 5 minutes
  2. Followed by PowerShell execution (4104) within 30 seconds
  3. Followed by network connection (Sysmon 3) within 60 seconds
  4. To external IP (not RFC1918)

Severity: Critical
Response: Alert SOC, Isolate endpoint
```

---

## Testing SIEM Detection

```bash
#!/bin/bash
#######################################
# SIEM Detection Test Script
# Simulate events for testing rules
#######################################

echo "[*] SIEM Detection Test"
echo "[*] This script generates test events"
echo ""

# Generate USB event (simulated log)
echo "[1/3] Simulating USB connection event..."
logger -t "SIEM-TEST" "USB Device Connected VID=0483 PID=5740"

# Generate process event
echo "[2/3] Simulating process creation..."
logger -t "SIEM-TEST" "Process: powershell.exe -w hidden -ep bypass"

# Generate network event
echo "[3/3] Simulating network connection..."
logger -t "SIEM-TEST" "Network: Connection to 8.8.8.8:443"

echo ""
echo "[+] Test events generated"
echo "[*] Check SIEM for alerts matching 'SIEM-TEST'"
```

---

[← Back to Security Operations](../README.md)
