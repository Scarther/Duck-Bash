# Defensive Signatures & Detection Rules

## USB BadUSB Detection

### Windows Event Log Indicators

#### USB Device Connection (Event ID 2003, 2010)
```xml
<!-- New USB Device Connected -->
<Event>
  <System>
    <EventID>2003</EventID>
    <Provider Name="Microsoft-Windows-DriverFrameworks-UserMode"/>
  </System>
  <UserData>
    <UMDFHostDeviceArrivalBegin>
      <DeviceId>USB\VID_0483&amp;PID_5740</DeviceId>
    </UMDFHostDeviceArrivalBegin>
  </UserData>
</Event>
```

#### Sigma Rule: Suspicious USB HID Device
```yaml
title: Suspicious USB HID Device Connection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects known BadUSB device identifiers
logsource:
    product: windows
    service: driver-framework
detection:
    selection:
        EventID: 2003
        DeviceId|contains:
            - 'VID_0483&PID_5740'  # Flipper Zero default
            - 'VID_FEED'           # Common BadUSB
            - 'VID_1337'           # Hak5 devices
    condition: selection
falsepositives:
    - Legitimate STM32 development boards
level: high
```

### Keystroke Timing Analysis

#### Detection Script (PowerShell)
```powershell
# Monitor for rapid keystroke injection
$threshold = 50  # characters per second
$lastTime = Get-Date
$charCount = 0
$alertThreshold = 100

# Hook keyboard input (requires admin)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public class KeyboardHook {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
}
"@

while ($true) {
    $currentTime = Get-Date
    $elapsed = ($currentTime - $lastTime).TotalSeconds

    if ($elapsed -ge 1) {
        $rate = $charCount / $elapsed
        if ($rate -gt $threshold) {
            Write-Warning "Suspicious keystroke rate: $rate chars/sec"
            # Alert logic here
        }
        $charCount = 0
        $lastTime = $currentTime
    }

    Start-Sleep -Milliseconds 10
}
```

### Sysmon Detection Rules

#### Sysmon Config for HID Attacks
```xml
<Sysmon schemaversion="4.50">
    <EventFiltering>
        <!-- Process Creation from unusual parents -->
        <ProcessCreate onmatch="include">
            <!-- PowerShell from explorer (RUN dialog) -->
            <Rule groupRelation="and">
                <ParentImage condition="end with">explorer.exe</ParentImage>
                <Image condition="end with">powershell.exe</Image>
            </Rule>
            <!-- CMD from explorer -->
            <Rule groupRelation="and">
                <ParentImage condition="end with">explorer.exe</ParentImage>
                <Image condition="end with">cmd.exe</Image>
            </Rule>
        </ProcessCreate>

        <!-- Registry modifications (persistence) -->
        <RegistryEvent onmatch="include">
            <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
            <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
        </RegistryEvent>

        <!-- File creation in startup -->
        <FileCreate onmatch="include">
            <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
        </FileCreate>
    </EventFiltering>
</Sysmon>
```

---

## Wireless Attack Detection

### Rogue AP Detection

#### Kismet Alerts Configuration
```conf
# /etc/kismet/kismet_alerts.conf

# Alert on duplicate SSID
alert=APSPOOF,5/min,1/sec
alert_apspoof_allowed=AA:BB:CC:DD:EE:FF,11:22:33:44:55:66

# Alert on deauth floods
alert=DEAUTHFLOOD,10/min,2/sec

# Alert on disassociation floods
alert=DISASSOCIATEFLOOD,10/min,2/sec

# Alert on probe response floods
alert=PROBERESPONSEFLOOD,50/min,5/sec
```

#### Deauthentication Detection Script
```bash
#!/bin/bash
# Monitor for deauth attacks

INTERFACE="wlan0mon"
THRESHOLD=10
WINDOW=60

airmon-ng start wlan0 2>/dev/null

# Count deauth packets
tcpdump -i "$INTERFACE" -c 1000 'type mgt subtype deauth' 2>/dev/null | \
while read line; do
    DEAUTH_COUNT=$((DEAUTH_COUNT + 1))

    if [ $DEAUTH_COUNT -gt $THRESHOLD ]; then
        echo "[ALERT] Deauthentication attack detected!"
        echo "Count: $DEAUTH_COUNT in last $WINDOW seconds"
        # Send alert
    fi
done
```

### Evil Twin Detection

#### BSSID Monitoring Script
```bash
#!/bin/bash
# Detect duplicate SSIDs with different BSSIDs

KNOWN_APS="/etc/known_aps.conf"
# Format: SSID,BSSID
# CompanyWiFi,AA:BB:CC:DD:EE:FF

airodump-ng wlan0mon -w /tmp/scan --output-format csv 2>/dev/null &
sleep 30
kill %1

while IFS=',' read ssid known_bssid; do
    # Find all BSSIDs for this SSID
    grep "$ssid" /tmp/scan-01.csv | while read line; do
        found_bssid=$(echo "$line" | cut -d',' -f1 | xargs)

        if [ "$found_bssid" != "$known_bssid" ]; then
            echo "[ALERT] Potential Evil Twin detected!"
            echo "SSID: $ssid"
            echo "Expected: $known_bssid"
            echo "Found: $found_bssid"
        fi
    done
done < "$KNOWN_APS"
```

### Sigma Rules for Wireless

#### WIDS Alert: Deauth Storm
```yaml
title: Wireless Deauthentication Storm
id: wireless-deauth-001
status: experimental
description: Detects high volume of deauthentication frames
logsource:
    product: kismet
    service: wireless
detection:
    selection:
        alert_type: DEAUTHFLOOD
    condition: selection
level: high
tags:
    - attack.impact
    - attack.t1498
```

---

## YARA Rules

### BadUSB Payload Patterns
```yara
rule BadUSB_DuckyScript_Payload
{
    meta:
        description = "Detects DuckyScript payload patterns"
        author = "Security Trainer"
        date = "2024-01-01"

    strings:
        $header1 = "REM " nocase
        $header2 = "DELAY "
        $cmd1 = "GUI r" nocase
        $cmd2 = "STRING powershell" nocase
        $cmd3 = "STRING cmd" nocase
        $cmd4 = "ENTER"
        $exfil1 = "Invoke-WebRequest" nocase
        $exfil2 = "curl " nocase
        $exfil3 = "wget " nocase

    condition:
        ($header1 or $header2) and
        ($cmd1 or $cmd2 or $cmd3) and
        $cmd4 and
        any of ($exfil*)
}

rule Flipper_BadUSB_Payload
{
    meta:
        description = "Detects Flipper Zero BadUSB payload"

    strings:
        $id = "ID "
        $delay = "DELAY"
        $string = "STRING"
        $gui = "GUI"
        $altcode = "ALTCODE"

    condition:
        $id at 0 and
        2 of ($delay, $string, $gui, $altcode)
}
```

### Captured Credential Patterns
```yara
rule Captured_Credentials_Log
{
    meta:
        description = "Detects credential harvester log files"

    strings:
        $header1 = "Username:"
        $header2 = "Password:"
        $header3 = "Timestamp:"
        $header4 = "Client IP:"
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/

    condition:
        3 of ($header*) or
        ($header1 and $header2 and $email)
}
```

---

## Snort/Suricata Rules

### Wireless Attack Signatures
```
# Deauthentication flood
alert wifi any any -> any any (msg:"Deauth flood detected"; \
    wifi.type:0; wifi.subtype:12; \
    threshold:type both, track by_src, count 20, seconds 10; \
    classtype:attempted-dos; sid:1000001; rev:1;)

# Beacon flood
alert wifi any any -> any any (msg:"Beacon flood detected"; \
    wifi.type:0; wifi.subtype:8; \
    threshold:type both, track by_src, count 100, seconds 10; \
    classtype:attempted-dos; sid:1000002; rev:1;)

# Suspicious probe response
alert wifi any any -> any any (msg:"Probe response flood"; \
    wifi.type:0; wifi.subtype:5; \
    threshold:type both, track by_src, count 50, seconds 10; \
    classtype:attempted-recon; sid:1000003; rev:1;)
```

### Captive Portal Detection
```
# HTTP credential capture attempt
alert http any any -> any any (msg:"Captive portal login detected"; \
    content:"POST"; http_method; \
    content:"password"; http_client_body; nocase; \
    content:"login"; http_uri; nocase; \
    classtype:credential-theft; sid:1000010; rev:1;)

# DNS redirect to captive portal
alert dns any any -> any any (msg:"DNS redirect to local IP"; \
    dns.query; content:"."; \
    pcre:"/192\.168\.(4|1)\.\d+/"; \
    classtype:trojan-activity; sid:1000011; rev:1;)
```

---

## EDR Detection Queries

### Microsoft Defender for Endpoint (KQL)
```kql
// Rapid keystroke injection
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName == "explorer.exe"
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe")
| summarize count() by DeviceName, bin(Timestamp, 1m)
| where count_ > 5

// USB device with suspicious VID/PID
DeviceEvents
| where ActionType == "UsbDriveMount" or ActionType == "UsbDriveDriveLetterChanged"
| where AdditionalFields contains "0483" or AdditionalFields contains "FEED"
| project Timestamp, DeviceName, AdditionalFields

// PowerShell encoded command execution
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, ProcessCommandLine
```

### CrowdStrike Falcon (SPL)
```spl
// USB HID device connection
event_platform=win event_simpleName=UsbDeviceConnected
| where VendorId IN ("0x0483", "0xFEED", "0x1337")
| table _time, ComputerName, VendorId, ProductId, DeviceInstanceId

// Rapid process creation
event_platform=win event_simpleName=ProcessRollup2
| where ParentBaseFileName="explorer.exe"
| bucket span=1m _time
| stats count by ComputerName, _time
| where count > 10
```

---

## Quick Detection Summary

```
┌─────────────────────────────────────────────────────────────┐
│              DETECTION PRIORITY MATRIX                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  HIGH PRIORITY:                                              │
│  ├── USB HID device with known BadUSB VID/PID              │
│  ├── Rapid keystroke injection patterns                    │
│  ├── PowerShell spawned from explorer.exe                  │
│  ├── Deauthentication packet floods                        │
│  └── Duplicate SSID with different BSSID                   │
│                                                              │
│  MEDIUM PRIORITY:                                            │
│  ├── New USB device connection                             │
│  ├── Registry Run key modifications                        │
│  ├── Unusual DNS responses                                 │
│  └── High beacon rate from unknown AP                      │
│                                                              │
│  LOW PRIORITY (context-dependent):                          │
│  ├── USB keyboard connection                               │
│  ├── PowerShell execution                                  │
│  └── Normal probe requests                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← Tool Integration](../09_Tool_Integration/) | [Back to Technical Addendum](../README.md) | [Next: Legal Compliance →](../11_Legal_Compliance/)
