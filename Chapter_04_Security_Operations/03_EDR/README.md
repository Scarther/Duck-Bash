# Endpoint Detection and Response (EDR)

## Overview

EDR solutions provide visibility into endpoint activity, enabling detection of malicious behaviors that traditional antivirus misses. This section covers EDR deployment and configuration for detecting USB/HID and related attacks.

---

## EDR Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      EDR ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ENDPOINTS                           EDR PLATFORM                  │
│                                                                      │
│   ┌──────────────┐                   ┌────────────────────────┐    │
│   │   Endpoint   │                   │                        │    │
│   │    Agent     │──────────────────▶│    Cloud/On-Prem       │    │
│   │              │                   │    Console             │    │
│   │  ┌────────┐  │                   │                        │    │
│   │  │Sensors │  │  Telemetry        │  ┌──────────────────┐  │    │
│   │  └────────┘  │                   │  │ Threat Detection │  │    │
│   │  ┌────────┐  │                   │  │ Engine           │  │    │
│   │  │Response│  │◀──────────────────│  └──────────────────┘  │    │
│   │  └────────┘  │  Commands         │                        │    │
│   └──────────────┘                   │  ┌──────────────────┐  │    │
│                                       │  │ Behavioral       │  │    │
│   ┌──────────────┐                   │  │ Analytics        │  │    │
│   │   Endpoint   │                   │  └──────────────────┘  │    │
│   │    Agent     │──────────────────▶│                        │    │
│   └──────────────┘                   │  ┌──────────────────┐  │    │
│                                       │  │ Threat Intel     │  │    │
│   ┌──────────────┐                   │  │ Integration      │  │    │
│   │   Endpoint   │                   │  └──────────────────┘  │    │
│   │    Agent     │──────────────────▶│                        │    │
│   └──────────────┘                   └────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## EDR Capabilities for HID Attack Detection

### Telemetry Collection

| Data Type | Detection Use | Examples |
|-----------|---------------|----------|
| Process events | Payload execution | PowerShell spawned from explorer |
| Registry events | Persistence detection | Run key modifications |
| File events | Payload drops | Script files in temp directories |
| Network events | C2 communication | Outbound connections |
| USB events | Device connection | New HID device attached |
| Module loads | Code injection | Suspicious DLL loads |

### Behavioral Detection

```
BadUSB Behavioral Indicators:
├── Process Chain Anomalies
│   ├── explorer.exe → powershell.exe (rapid)
│   ├── explorer.exe → cmd.exe (rapid)
│   └── Multiple shells in quick succession
│
├── Keystroke Patterns
│   ├── Input rate >50 characters/second
│   ├── No mouse movement during input
│   └── Consistent timing (machine-like)
│
├── Command Patterns
│   ├── Encoded PowerShell (-enc)
│   ├── Download cradles
│   ├── AMSI bypass attempts
│   └── Hidden window execution
│
└── Persistence Patterns
    ├── Registry Run key modification
    ├── Scheduled task creation
    ├── Startup folder writes
    └── Service installation
```

---

## EDR Platforms

### Commercial Solutions

| Platform | USB/HID Detection | Key Features |
|----------|-------------------|--------------|
| CrowdStrike Falcon | Excellent | USB device visibility, behavioral AI |
| Microsoft Defender for Endpoint | Good | Native Windows integration |
| SentinelOne | Excellent | Autonomous response, storyline |
| Carbon Black | Good | Process tree analysis |
| Cortex XDR | Good | Network+endpoint correlation |

### Open Source / Free Options

| Platform | Capabilities | Notes |
|----------|--------------|-------|
| Wazuh | Good for logging | Requires Sysmon integration |
| OSSEC | Basic | File integrity focus |
| Velociraptor | Excellent hunting | Requires expertise |
| osquery | Good visibility | Query-based, no real-time |

---

## Detection Queries

### CrowdStrike Falcon (Event Search)

```sql
-- USB HID Device Connection
event_platform=win event_simpleName=UsbDeviceConnected
| search VendorId IN ("0x0483", "0xFEED", "0x1337")
| table _time ComputerName VendorId ProductId DeviceInstanceId

-- Rapid Process Creation from Explorer
event_platform=win event_simpleName=ProcessRollup2
| search ParentBaseFileName="explorer.exe"
| bucket span=30s _time
| stats count by ComputerName _time
| where count > 5
| table _time ComputerName count

-- PowerShell with Encoded Commands
event_platform=win event_simpleName=ProcessRollup2
| search FileName="powershell.exe" CommandLine="*-enc*"
| table _time ComputerName CommandLine ParentBaseFileName

-- Registry Persistence Detection
event_platform=win event_simpleName=AsepValueUpdate
| search RegPath="*CurrentVersion\\Run*"
| table _time ComputerName RegPath RegValueName RegValueData
```

### Microsoft Defender for Endpoint (KQL)

```kql
// USB Device with Suspicious VID/PID
DeviceEvents
| where ActionType == "UsbDriveMount" or ActionType == "UsbDriveDriveLetterChanged"
| where AdditionalFields contains "0483" or AdditionalFields contains "FEED"
| project Timestamp, DeviceName, ActionType, AdditionalFields

// Rapid Command Execution Pattern
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName == "explorer.exe"
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe")
| summarize count() by DeviceName, bin(Timestamp, 30s)
| where count_ > 3
| project Timestamp, DeviceName, count_

// PowerShell Encoded Command Execution
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc" or 
        ProcessCommandLine contains "-EncodedCommand" or
        ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName

// Registry Run Key Modification
DeviceRegistryEvents
| where RegistryKey contains "CurrentVersion\\Run"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName

// Suspicious Process Tree (BadUSB Pattern)
DeviceProcessEvents
| where InitiatingProcessFileName == "explorer.exe"
| where FileName in ("powershell.exe", "cmd.exe")
| join kind=inner (
    DeviceProcessEvents
    | where FileName in ("net.exe", "whoami.exe", "systeminfo.exe", "reg.exe")
) on DeviceId
| where Timestamp1 between (Timestamp .. (Timestamp + 60s))
| project Timestamp, DeviceName, ParentProcess=FileName, ChildProcess=FileName1
```

### SentinelOne (Deep Visibility)

```sql
-- USB Device Events
EventType = "USB Device Connected" 
| where VendorId in ("0483", "FEED", "1337")
| columns EndpointName, VendorId, ProductId, DeviceDescription

-- PowerShell from Explorer
EventType = "Process Creation"
| where ParentProcessName = "explorer.exe" 
    AND ProcessName in ("powershell.exe", "cmd.exe")
| columns EndpointName, ProcessName, CommandLine, Timestamp

-- Encoded PowerShell
EventType = "Process Creation"
| where ProcessName = "powershell.exe"
| where CommandLine contains "-enc" OR CommandLine contains "encodedcommand"
| columns EndpointName, CommandLine, ParentProcessName

-- Registry Persistence
EventType = "Registry Value Modified"
| where RegistryPath contains "Run"
| columns EndpointName, RegistryPath, RegistryValueName, RegistryValueData
```

---

## Response Actions

### Automated Response Options

```
EDR Response Capabilities:
├── Isolation
│   ├── Network isolation (block all traffic except EDR)
│   ├── USB device blocking
│   └── User session termination
│
├── Process Actions
│   ├── Kill process
│   ├── Kill process tree
│   ├── Block process hash
│   └── Quarantine executable
│
├── File Actions
│   ├── Delete file
│   ├── Quarantine file
│   └── Rollback changes (if available)
│
├── Registry Actions
│   ├── Delete registry key
│   ├── Restore registry value
│   └── Monitor for recreation
│
└── Investigation
    ├── Memory dump collection
    ├── Forensic package creation
    ├── Timeline extraction
    └── Artifact collection
```

### Response Playbook: BadUSB Detection

```
┌─────────────────────────────────────────────────────────────────────┐
│               BADUSB RESPONSE PLAYBOOK                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  TRIGGER: Alert for suspicious USB HID + rapid command execution    │
│                                                                      │
│  STEP 1: ASSESS (5 minutes)                                         │
│  ────────────────────────                                           │
│  □ Review alert details in EDR console                              │
│  □ Check process tree and command lines                             │
│  □ Identify affected user and system                                │
│  □ Determine if authorized testing or actual attack                 │
│                                                                      │
│  STEP 2: CONTAIN (10 minutes)                                       │
│  ─────────────────────────                                          │
│  □ Isolate endpoint from network (via EDR)                          │
│  □ Block USB device (if still connected)                            │
│  □ Kill any malicious processes                                     │
│  □ Notify user and manager                                          │
│                                                                      │
│  STEP 3: INVESTIGATE (30 minutes)                                   │
│  ──────────────────────────────                                     │
│  □ Collect forensic package                                         │
│  □ Analyze full attack timeline                                     │
│  □ Identify any persistence mechanisms                              │
│  □ Check for lateral movement                                       │
│  □ Determine data access/exfiltration                               │
│                                                                      │
│  STEP 4: ERADICATE (15 minutes)                                     │
│  ─────────────────────────────                                      │
│  □ Remove persistence mechanisms                                    │
│  □ Delete dropped files                                             │
│  □ Reset compromised credentials                                    │
│  □ Block identified IOCs organization-wide                          │
│                                                                      │
│  STEP 5: RECOVER (30 minutes)                                       │
│  ───────────────────────────                                        │
│  □ Restore system from clean backup if needed                       │
│  □ Remove network isolation                                         │
│  □ Verify normal operation                                          │
│  □ Enhanced monitoring for 24-48 hours                              │
│                                                                      │
│  STEP 6: DOCUMENT                                                   │
│  ────────────────                                                   │
│  □ Complete incident report                                         │
│  □ Update detection rules if needed                                 │
│  □ Share IOCs with threat intel team                                │
│  □ Schedule lessons learned review                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## EDR Policy Configuration

### USB Device Control Policy

```yaml
# Example USB Device Control Policy
usb_policy:
  name: "USB HID Restriction"
  description: "Control HID device access"

  rules:
    - name: "Block Unknown HID"
      action: block
      device_type: hid
      condition:
        not_in_whitelist: true
      alert: true
      alert_severity: high

    - name: "Allow Known Keyboards"
      action: allow
      device_type: keyboard
      condition:
        vendor_id:
          - "045E"  # Microsoft
          - "046D"  # Logitech
          - "413C"  # Dell
        product_id_whitelist: true
      log: true

    - name: "Allow Known Mice"
      action: allow
      device_type: mouse
      condition:
        vendor_id:
          - "045E"  # Microsoft
          - "046D"  # Logitech
      log: true

    - name: "Alert on BadUSB Patterns"
      action: alert
      device_type: hid
      condition:
        vendor_id:
          - "0483"  # Flipper Zero
          - "FEED"  # Generic BadUSB
          - "1337"  # Hak5
      alert_severity: critical
      response:
        - isolate_endpoint
        - collect_forensics
```

### Behavioral Detection Policy

```yaml
# Behavioral Detection Rules
behavioral_rules:
  - name: "Rapid Process Execution"
    description: "Multiple shells from explorer in short time"
    conditions:
      parent_process: "explorer.exe"
      child_process:
        - "powershell.exe"
        - "cmd.exe"
        - "wscript.exe"
      count_threshold: 3
      time_window: 30s
    action: alert
    severity: high

  - name: "PowerShell Download Cradle"
    description: "PowerShell downloading and executing code"
    conditions:
      process: "powershell.exe"
      command_contains:
        - "downloadstring"
        - "downloadfile"
        - "invoke-webrequest"
        - "net.webclient"
      and:
        - "iex"
        - "invoke-expression"
    action: alert
    severity: critical

  - name: "Registry Persistence"
    description: "Run key modification"
    conditions:
      registry_path_contains: "CurrentVersion\\Run"
      action: "create|modify"
      exclude_process:
        - "msiexec.exe"
        - "setup.exe"
    action: alert
    severity: high
```

---

## Deployment Best Practices

### Pre-Deployment

```
□ Inventory all endpoints
□ Identify high-value targets for priority deployment
□ Plan rollout phases
□ Configure baseline policies
□ Set up alerting channels
□ Train SOC team on platform
□ Document escalation procedures
```

### Deployment

```
□ Deploy to test group first
□ Validate telemetry collection
□ Tune false positives
□ Validate response actions
□ Phase rollout to production
□ Monitor for agent issues
□ Verify coverage metrics
```

### Post-Deployment

```
□ Regular policy reviews
□ False positive tuning
□ Detection rule updates
□ Agent version management
□ Coverage gap analysis
□ Response playbook testing
□ Integration with SIEM/SOAR
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│                    EDR QUICK REFERENCE                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  BADUSB DETECTION PATTERNS:                                         │
│  ├── explorer.exe → powershell.exe (rapid)                         │
│  ├── explorer.exe → cmd.exe (rapid)                                 │
│  ├── Encoded PowerShell commands                                    │
│  ├── Registry Run key modifications                                 │
│  └── Suspicious VID/PID (0483, FEED, 1337)                         │
│                                                                      │
│  KEY QUERIES:                                                       │
│  ├── Process creation from explorer.exe                            │
│  ├── USB device connection events                                   │
│  ├── PowerShell with -enc flag                                      │
│  └── Registry persistence locations                                 │
│                                                                      │
│  RESPONSE ACTIONS:                                                  │
│  ├── Network isolation                                              │
│  ├── Process termination                                            │
│  ├── USB device blocking                                            │
│  ├── Forensic collection                                            │
│  └── Credential reset                                               │
│                                                                      │
│  TUNING PRIORITIES:                                                 │
│  ├── Whitelist legitimate admin tools                              │
│  ├── Exclude approved deployment software                          │
│  ├── Adjust timing thresholds per environment                      │
│  └── Baseline normal USB device patterns                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Security Monitoring & SIEM](../02_Security_Monitoring_SIEM/) | [Back to Security Operations](../README.md) | [Next: Network Monitoring IDS/IPS →](../04_Network_Monitoring_IDS_IPS/)
