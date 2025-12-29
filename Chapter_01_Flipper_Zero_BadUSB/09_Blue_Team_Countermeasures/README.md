# Blue Team Countermeasures

## Overview

This section provides comprehensive defensive strategies, detection techniques, and response procedures for protecting against BadUSB attacks. Designed for security operations, incident response, and security architecture teams.

---

## Detection Strategies

### USB Device Monitoring

```
┌─────────────────────────────────────────────────────────────────────┐
│                    USB ATTACK INDICATORS                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INDICATORS OF BADUSB ATTACK:                                        │
│  ├── Rapid keystroke input (>1000 chars/min)                        │
│  │   Normal typing: 200-400 chars/min                               │
│  │   BadUSB: 1000-5000+ chars/min                                   │
│  │                                                                   │
│  ├── USB HID device insertion events                                │
│  │   Event ID 6416 (Security log)                                   │
│  │   Sysmon Event ID 1 with USB parent                              │
│  │                                                                   │
│  ├── PowerShell execution after USB insertion                       │
│  │   Correlation: USB insert + PS within 5 seconds                  │
│  │                                                                   │
│  └── Unusual VID/PID combinations                                   │
│       Known Flipper Zero: 0483:5740                                 │
│       Spoofed devices: Check against hardware inventory             │
│                                                                      │
│  DETECTION TOOLS:                                                    │
│  ├── Windows Event Log (Security 6416)                              │
│  ├── Sysmon USB monitoring                                          │
│  ├── USB forensics tools (USBDeview, etc.)                          │
│  ├── EDR USB monitoring capabilities                                │
│  └── Keystroke timing analysis tools                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Windows Event Log Monitoring

```
KEY EVENT IDS:

Security Log:
├── 4624 - Logon event (context for timeline)
├── 4688 - Process creation (with command line)
├── 6416 - New external device connected
└── 4657 - Registry modification

Sysmon:
├── Event ID 1  - Process creation
├── Event ID 11 - File creation
├── Event ID 12 - Registry key created/deleted
├── Event ID 13 - Registry value set
├── Event ID 19 - WMI filter created
├── Event ID 20 - WMI consumer created
└── Event ID 21 - WMI binding created

PowerShell:
├── 4103 - Module logging
├── 4104 - Script block logging
└── 4105 - Transcription
```

### PowerShell Logging Configuration

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ENABLE POWERSHELL LOGGING                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  RECOMMENDED SETTINGS:                                               │
│  ├── Script Block Logging (Event 4104)                              │
│  ├── Module Logging (Event 4103)                                    │
│  └── Transcription (file-based)                                     │
│                                                                      │
│  GPO PATH:                                                           │
│  Computer Configuration                                              │
│   └── Administrative Templates                                       │
│       └── Windows Components                                         │
│           └── Windows PowerShell                                     │
│               ├── Turn on Module Logging                            │
│               ├── Turn on PowerShell Script Block Logging           │
│               └── Turn on PowerShell Transcription                  │
│                                                                      │
│  REGISTRY (Alternative):                                             │
│  HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell               │
│  ├── EnableScriptBlockLogging = 1                                   │
│  ├── EnableModuleLogging = 1                                        │
│  └── EnableTranscripting = 1                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Command Line Auditing

```
ENABLE PROCESS CREATION EVENTS:

GPO Path:
Computer Configuration
 └── Windows Settings
     └── Security Settings
         └── Advanced Audit Policy
             └── Detailed Tracking
                 └── Audit Process Creation: Success

Include Command Line:
Computer Configuration
 └── Administrative Templates
     └── System
         └── Audit Process Creation
             └── Include command line in process creation events: Enabled

DETECTION QUERIES (PowerShell suspicious patterns):
├── "powershell.*-w hidden"
├── "powershell.*-ep bypass"
├── "powershell.*-enc"
├── "powershell.*-nop"
├── "cmd.*/c.*powershell"
├── "IEX.*IWR"
└── "Invoke-Expression.*WebRequest"
```

---

## Prevention Measures

### USB Device Control

```
┌─────────────────────────────────────────────────────────────────────┐
│                    USB CONTROL OPTIONS                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. GROUP POLICY USB RESTRICTIONS                                    │
│  ├── Block all removable storage                                    │
│  │   Computer Config > Admin Templates > System > Removable Storage │
│  │   - All Removable Storage classes: Deny all access               │
│  │                                                                   │
│  ├── Block specific device classes                                  │
│  │   Computer Config > Admin Templates > System > Device Installation│
│  │   - Prevent installation of devices matching these IDs           │
│  │                                                                   │
│  └── Whitelist specific devices                                     │
│       Allow only approved VID/PID combinations                      │
│                                                                      │
│  2. ENDPOINT PROTECTION USB CONTROL                                  │
│  ├── Device type filtering (storage, HID, etc.)                     │
│  ├── VID/PID whitelisting                                           │
│  ├── Serial number tracking                                         │
│  └── Real-time block/allow decisions                                │
│                                                                      │
│  3. PHYSICAL USB PORT BLOCKERS                                       │
│  ├── Hardware locks (keyed port covers)                             │
│  ├── USB data blockers (power only)                                 │
│  └── BIOS-level USB disable (extreme)                               │
│                                                                      │
│  KNOWN BADUSB DEVICE IDS TO BLOCK:                                   │
│  ├── 0483:5740 - Flipper Zero (default)                             │
│  ├── 1532:0110 - Rubber Ducky patterns                              │
│  ├── 16D0:0753 - Digispark                                          │
│  └── 2341:8036 - Arduino Leonardo                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Application Whitelisting

```
┌─────────────────────────────────────────────────────────────────────┐
│                    APPLICATION CONTROL                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  TECHNOLOGIES:                                                       │
│  ├── Windows Defender Application Control (WDAC)                    │
│  │   Modern, robust, Microsoft recommended                          │
│  │                                                                   │
│  ├── AppLocker                                                      │
│  │   Easier to configure, Enterprise/Education editions             │
│  │                                                                   │
│  └── Third-party solutions                                          │
│       Carbon Black, McAfee, etc.                                    │
│                                                                      │
│  RECOMMENDED BLOCKS:                                                 │
│  ├── Unsigned scripts                                               │
│  ├── Unknown executables                                            │
│  ├── Scripts from user-writable locations                           │
│  ├── PowerShell download cradles                                    │
│  └── LOLBins from non-standard paths                                │
│                                                                      │
│  POWERSHELL CONSTRAINED LANGUAGE MODE:                               │
│  ├── Prevents most offensive techniques                             │
│  ├── Blocks .NET access, COM, WMI                                   │
│  ├── Enable via WDAC policy                                         │
│  └── Test thoroughly before deployment                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Endpoint Detection and Response (EDR)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    EDR CAPABILITIES                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  CORE CAPABILITIES:                                                  │
│  ├── Behavioral analysis                                            │
│  │   Detect malicious patterns regardless of signature              │
│  │                                                                   │
│  ├── Memory scanning                                                │
│  │   Detect fileless malware                                        │
│  │                                                                   │
│  ├── Network traffic analysis                                       │
│  │   Identify C2 communications                                     │
│  │                                                                   │
│  └── Automated response                                             │
│       Kill processes, isolate hosts                                 │
│                                                                      │
│  BADUSB DETECTION FOCUS:                                             │
│  ├── Unusual process chains                                         │
│  │   explorer.exe → powershell.exe (from USB event)                 │
│  │                                                                   │
│  ├── Memory-only execution                                          │
│  │   PowerShell without script file                                 │
│  │                                                                   │
│  ├── Credential access attempts                                     │
│  │   Mimikatz patterns, LSASS access                                │
│  │                                                                   │
│  └── Rapid keyboard input                                           │
│       Typing speed analysis                                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Response Procedures

### USB Incident Response Playbook

```
┌─────────────────────────────────────────────────────────────────────┐
│                    USB INCIDENT RESPONSE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. ISOLATE                                                         │
│  ├── Disconnect USB device (preserve evidence)                      │
│  │   Do NOT insert into another system                              │
│  │                                                                   │
│  ├── Preserve the device in evidence bag                            │
│  │   Document chain of custody                                      │
│  │                                                                   │
│  └── Network quarantine if needed                                   │
│       Isolate host from network                                     │
│                                                                      │
│  2. ANALYZE                                                         │
│  ├── USB device forensic imaging                                    │
│  │   Use write-blocker                                              │
│  │   Extract payload files                                          │
│  │                                                                   │
│  ├── Timeline analysis                                              │
│  │   Correlate USB insert with system events                        │
│  │                                                                   │
│  └── Payload extraction and analysis                                │
│       Identify capabilities and IOCs                                │
│                                                                      │
│  3. CONTAIN                                                         │
│  ├── Identify all affected systems                                  │
│  │   Check for lateral movement                                     │
│  │                                                                   │
│  ├── Check for persistence mechanisms                               │
│  │   Registry, scheduled tasks, WMI                                 │
│  │                                                                   │
│  └── Credential reset if needed                                     │
│       Assume credentials compromised                                │
│                                                                      │
│  4. ERADICATE                                                       │
│  ├── Remove malware/persistence                                     │
│  │   Use IOCs from analysis                                         │
│  │                                                                   │
│  ├── Patch vulnerabilities                                          │
│  │   USB policy, PowerShell settings                                │
│  │                                                                   │
│  └── Update controls                                                │
│       Block identified device IDs                                   │
│                                                                      │
│  5. RECOVER                                                         │
│  ├── Restore systems from clean state                               │
│  │   Use known-good backup                                          │
│  │                                                                   │
│  ├── Verify integrity                                               │
│  │   Compare file hashes                                            │
│  │                                                                   │
│  └── Resume operations                                              │
│       Monitor closely                                               │
│                                                                      │
│  6. LESSONS LEARNED                                                 │
│  ├── Update detection rules                                         │
│  │   Add new IOCs to SIEM                                           │
│  │                                                                   │
│  ├── Improve controls                                               │
│  │   USB policy, awareness training                                 │
│  │                                                                   │
│  └── Document and share                                             │
│       Internal report, threat intel sharing                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Forensic Analysis

```
USB DEVICE ANALYSIS:
1. Image the USB device (use write-blocker)
   - dd if=/dev/sdX of=usb_image.dd bs=4k
   - FTK Imager for GUI

2. Extract payload files
   - Mount image read-only
   - Copy all .txt, .ducky files

3. Analyze script contents
   - Review DuckyScript payloads
   - Identify commands and capabilities

4. Identify IOCs
   - C2 URLs
   - File paths
   - Registry keys
   - Scheduled task names

HOST ANALYSIS:
1. Memory capture
   - volatility, WinPMEM
   - Analyze for injected code

2. Event log analysis
   - PowerShell logs (4103, 4104)
   - Process creation (4688)
   - USB events (6416)

3. Registry analysis
   - Run/RunOnce keys
   - USBStor history
   - Recent commands

4. File system timeline
   - MFT analysis
   - Prefetch files
   - Recent files
```

---

## Security Awareness Training

### Training Scenarios

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SECURITY AWARENESS EXERCISES                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. USB DROP TEST                                                   │
│  ├── Plant labeled USB drives ("Confidential", "Payroll")          │
│  ├── Track who plugs them in (via callback payload)                 │
│  ├── Educational payload shows awareness message                    │
│  └── Measure and report statistics                                  │
│                                                                      │
│  2. TAILGATING ASSESSMENT                                           │
│  ├── Test physical access controls                                  │
│  ├── Combine with USB plant during access                           │
│  └── Evaluate badge-checking habits                                 │
│                                                                      │
│  3. SOCIAL ENGINEERING                                              │
│  ├── "IT needs to update your computer"                             │
│  ├── "Here's the USB with meeting files"                            │
│  ├── Test employee response to pretexts                             │
│  └── Document susceptibility metrics                                │
│                                                                      │
│  4. PHISHING + USB COMBO                                            │
│  ├── Email claiming USB was sent                                    │
│  ├── "Your ordered USB drive has arrived"                           │
│  └── Test multi-vector awareness                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Training Content

```
ESSENTIAL TOPICS:
├── USB attack risks
│   - BadUSB explained in simple terms
│   - Real-world attack examples
│   - Potential impact (data loss, ransomware)
│
├── Social engineering tactics
│   - Common pretexts used
│   - Authority and urgency tricks
│   - Verification procedures
│
├── Physical security importance
│   - Tailgating risks
│   - Clean desk policy
│   - Device security
│
├── Reporting procedures
│   - What to report
│   - Who to contact
│   - Incident hotline number
│
└── Safe USB handling
    - Never plug in unknown USBs
    - Report found devices to security
    - Use approved devices only
    - Verify IT requests through official channels

TRAINING METHODS:
├── In-person training
│   Live demonstrations of attacks
│
├── Online modules
│   Self-paced learning
│
├── Phishing simulations
│   Ongoing testing
│
└── USB drop exercises
    Annual assessment
```

---

## Detection Rules

### Sigma Rules

```yaml
# Detect PowerShell with suspicious flags after USB insertion
title: Suspicious PowerShell After USB Device Connection
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    usb_connect:
        EventID: 1
        ParentImage|endswith: '\explorer.exe'
    powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - '-w hidden'
            - '-ep bypass'
            - '-enc'
            - '-nop'
    timeframe: 30s
    condition: usb_connect and powershell
level: high
```

```yaml
# Detect rapid keyboard input (BadUSB indicator)
title: Possible BadUSB Rapid Keystroke Activity
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
    filter:
        # Multiple process creations within short window
        # indicating rapid command execution
    condition: selection | count() by Computer > 10
    timeframe: 10s
level: medium
```

### YARA Rules

```yara
rule BadUSB_DuckyScript_Payload {
    meta:
        description = "Detects DuckyScript payload files"
        author = "Security Team"

    strings:
        $delay = "DELAY" ascii wide
        $string = "STRING " ascii wide
        $gui = "GUI " ascii wide
        $enter = "ENTER" ascii wide
        $rem = "REM " ascii wide

    condition:
        filesize < 50KB and
        3 of them
}
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│               BLUE TEAM COUNTERMEASURES QUICK REFERENCE              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DETECTION:                                                          │
│  ├── Enable PowerShell logging (4103, 4104)                         │
│  ├── Enable process command line auditing (4688)                    │
│  ├── Monitor USB events (6416)                                      │
│  ├── Deploy Sysmon with USB monitoring                              │
│  └── Correlate USB insert → PowerShell execution                    │
│                                                                      │
│  PREVENTION:                                                         │
│  ├── USB device control (GPO or EDR)                                │
│  ├── Block known BadUSB VID/PIDs                                    │
│  ├── Enable PowerShell Constrained Language                         │
│  ├── Application whitelisting (WDAC/AppLocker)                      │
│  └── Physical USB port locks                                        │
│                                                                      │
│  RESPONSE:                                                           │
│  ├── Isolate: Disconnect device, quarantine host                    │
│  ├── Analyze: USB forensics, payload extraction                     │
│  ├── Contain: Check lateral movement, persistence                   │
│  ├── Eradicate: Remove malware, update controls                     │
│  └── Recover: Restore, verify, lessons learned                      │
│                                                                      │
│  AWARENESS:                                                          │
│  ├── USB drop exercises                                             │
│  ├── Regular security training                                      │
│  ├── Clear reporting procedures                                     │
│  └── Physical security emphasis                                     │
│                                                                      │
│  KEY INDICATORS:                                                     │
│  ├── Rapid keystroke input (>1000 chars/min)                        │
│  ├── PowerShell hidden window execution                             │
│  ├── Unknown USB HID device insertion                               │
│  └── Process chain: explorer → cmd/powershell                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Red Team Tactics](../08_Red_Team_Tactics/) | [Back to Flipper Zero](../README.md)
