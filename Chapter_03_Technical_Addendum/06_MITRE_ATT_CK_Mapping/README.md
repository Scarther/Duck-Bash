# MITRE ATT&CK Framework Mapping

## Overview

This reference maps BadUSB and WiFi attack techniques to the MITRE ATT&CK framework for proper documentation, detection, and defense planning.

---

## Initial Access (TA0001)

### T1091 - Replication Through Removable Media
**BadUSB Payloads**: FZ-B*, PP-B*

```
Technique: Adversaries may use removable media to gain access
           to systems by exploiting autorun or user interaction.

BadUSB Application:
├── USB device auto-enumeration as HID
├── Automatic keystroke injection
└── No user action required beyond insertion

Detection:
├── New USB device connection events
├── Unusual HID device enumeration
└── Rapid keystroke patterns

Mitigation:
├── USB device whitelisting
├── Group Policy USB restrictions
└── Endpoint USB monitoring
```

### T1200 - Hardware Additions
**Devices**: Flipper Zero, USB Rubber Ducky, WiFi Pineapple

```
Technique: Adversaries may introduce malicious hardware devices
           to gain access or maintain presence.

Application:
├── Rogue USB devices (BadUSB)
├── Rogue access points (Pineapple)
├── Network implants
└── Keyloggers

Detection:
├── Hardware inventory management
├── Network device monitoring
├── Physical security audits
└── Wireless scanning

Mitigation:
├── Physical access controls
├── USB port disabling
├── 802.1X network access control
└── Wireless IDS/IPS
```

---

## Execution (TA0002)

### T1059.001 - Command and Scripting: PowerShell
**Payloads**: FZ-I01, FZ-I05, FZ-A03

```
Technique: PowerShell execution for reconnaissance and payload delivery

DuckyScript Example:
├── GUI r → powershell
├── Encoded commands
├── Download cradles
└── AMSI bypass attempts

Detection:
├── PowerShell logging (ScriptBlock, Module)
├── Process creation with powershell.exe
├── Encoded command detection
└── Suspicious PowerShell arguments

Mitigation:
├── PowerShell Constrained Language Mode
├── AppLocker/WDAC policies
├── Script signing requirements
└── PowerShell v2 removal
```

### T1059.003 - Command and Scripting: Windows Command Shell
**Payloads**: FZ-B05, FZ-I02, PP-B*

```
Technique: CMD.exe execution for system interaction

DuckyScript Example:
├── GUI r → cmd
├── Command chaining
├── Environment variable abuse
└── Native Windows commands

Detection:
├── Process creation logging
├── Command line auditing
├── Unusual cmd.exe child processes
└── Obfuscated commands

Mitigation:
├── Application whitelisting
├── Command line logging
├── User training
└── Privilege restrictions
```

### T1204.002 - User Execution: Malicious File
**Payloads**: Credential harvesting payloads

```
Technique: Relying on user to execute malicious content

Application:
├── Captive portal credential forms
├── Phishing pages via Evil Twin
├── Fake software update prompts
└── Social engineering

Detection:
├── Web content filtering
├── SSL certificate validation
├── User behavior analytics
└── Unusual authentication patterns

Mitigation:
├── Security awareness training
├── Certificate pinning
├── VPN requirements
└── Multi-factor authentication
```

---

## Persistence (TA0003)

### T1547.001 - Boot or Logon Autostart: Registry Run Keys
**Payloads**: FZ-A04, persistence payloads

```
Technique: Adding programs to Run keys for persistence

DuckyScript Targets:
├── HKCU\Software\Microsoft\Windows\CurrentVersion\Run
├── HKLM\Software\Microsoft\Windows\CurrentVersion\Run
├── Startup folder
└── Scheduled tasks

Detection:
├── Registry key monitoring
├── Autoruns analysis
├── File integrity monitoring
└── Process lineage tracking

Mitigation:
├── Registry auditing
├── Application control
├── Least privilege
└── Regular autoruns review
```

### T1136.001 - Create Account: Local Account
**Payloads**: FZ-A02

```
Technique: Creating local accounts for persistence

DuckyScript Implementation:
├── net user /add commands
├── net localgroup administrators
├── Hidden user creation
└── Password policy bypass

Detection:
├── Account creation events (4720)
├── Security group changes (4732)
├── Unusual account names
└── Off-hours account activity

Mitigation:
├── Privileged access management
├── Account creation restrictions
├── Multi-factor authentication
└── Regular account audits
```

---

## Privilege Escalation (TA0004)

### T1548.002 - Bypass UAC
**Payloads**: FZ-A01, FZ-A03

```
Technique: Bypassing User Account Control to elevate privileges

Methods:
├── fodhelper.exe bypass
├── eventvwr.exe bypass
├── Auto-elevate exploitation
└── DLL hijacking

Detection:
├── UAC bypass indicators
├── Unusual parent-child relationships
├── Registry key modifications
└── Suspicious COM object usage

Mitigation:
├── UAC set to "Always Notify"
├── Remove local admin rights
├── Application control
└── Endpoint detection
```

---

## Defense Evasion (TA0005)

### T1562.001 - Impair Defenses: Disable Security Tools
**Payloads**: FZ-A05

```
Technique: Disabling security software to avoid detection

Targets:
├── Windows Defender
├── Windows Firewall
├── Third-party AV
├── EDR agents
└── Logging services

Detection:
├── Security service status monitoring
├── Process termination events
├── Registry changes to security settings
└── Tamper protection alerts

Mitigation:
├── Tamper protection
├── Privileged access management
├── Security tool monitoring
└── Immutable logging
```

### T1027 - Obfuscated Files or Information
**Payloads**: Encoded payloads

```
Technique: Encoding or encrypting payloads to evade detection

DuckyScript Methods:
├── Base64 encoding
├── Character substitution
├── PowerShell encoded commands
└── Variable obfuscation

Detection:
├── Encoded command detection
├── Entropy analysis
├── Behavioral analysis
└── AMSI scanning

Mitigation:
├── Script logging
├── AMSI enforcement
├── Behavioral detection
└── Content inspection
```

---

## Credential Access (TA0006)

### T1557.001 - LLMNR/NBT-NS Poisoning
**Payloads**: PP-I05 (DNS Spoof)

```
Technique: Poisoning name resolution to capture credentials

WiFi Pineapple Implementation:
├── DNS spoofing
├── Captive portal
├── Credential interception
└── Responder-style attacks

Detection:
├── Unusual DNS responses
├── Multiple name resolution failures
├── Network traffic analysis
└── Honeypot credentials

Mitigation:
├── Disable LLMNR/NBT-NS
├── Network segmentation
├── DNS security (DNSSEC)
└── 802.1X authentication
```

### T1110.002 - Brute Force: Password Cracking
**Payloads**: PP-A03 (WPA Cracker)

```
Technique: Offline password cracking of captured hashes

Application:
├── WPA handshake cracking
├── PMKID cracking
├── MSCHAPv2 hash cracking
└── Dictionary attacks

Detection:
├── Multiple failed authentication attempts
├── Hash dumping indicators
├── Password spray patterns
└── Honeypot credentials

Mitigation:
├── Strong password policies
├── Account lockout
├── MFA enforcement
└── Password managers
```

---

## Discovery (TA0007)

### T1016 - System Network Configuration Discovery
**Payloads**: FZ-B03, FZ-I01

```
Technique: Gathering network configuration information

Commands:
├── ipconfig /all
├── netstat -an
├── route print
├── arp -a

Detection:
├── Command execution logging
├── Network enumeration patterns
├── Unusual discovery activity
└── Behavioral baselines

Mitigation:
├── Least privilege
├── Command logging
├── Network segmentation
└── Monitoring
```

### T1018 - Remote System Discovery
**Payloads**: FZ-I05, PP-B04

```
Technique: Identifying remote systems on network

Methods:
├── Net view commands
├── Network scanning (nmap)
├── Ping sweeps
├── ARP scanning

Detection:
├── Network traffic analysis
├── Port scan detection
├── Unusual outbound connections
└── ICMP flood detection

Mitigation:
├── Network segmentation
├── Firewall rules
├── IDS/IPS
└── Network monitoring
```

---

## Collection (TA0009)

### T1119 - Automated Collection
**Payloads**: FZ-I07, FZ-A04

```
Technique: Automated gathering of sensitive data

DuckyScript Targets:
├── Browser credentials
├── SSH keys
├── WiFi passwords
├── Document harvesting
└── Clipboard data

Detection:
├── File access patterns
├── Unusual archive creation
├── Data staging indicators
└── Exfiltration patterns

Mitigation:
├── Data loss prevention
├── Credential management
├── Encryption
└── Access controls
```

---

## Exfiltration (TA0010)

### T1048.002 - Exfiltration Over Alternative Protocol: Exfil Over Asymmetric Encrypted Non-C2
**Payloads**: FZ-E03

```
Technique: Exfiltrating data over encrypted channels

Methods:
├── HTTPS exfiltration
├── DNS tunneling
├── Cloud storage upload
└── Encoded transfers

Detection:
├── Unusual outbound traffic
├── DNS query anomalies
├── Cloud storage monitoring
└── Encrypted traffic analysis

Mitigation:
├── Network monitoring
├── SSL inspection
├── Cloud access security broker
└── Data loss prevention
```

---

## Quick Reference Matrix

| Payload ID | ATT&CK Techniques |
|------------|-------------------|
| FZ-B01-05 | T1091, T1059.003, T1016 |
| FZ-I01-05 | T1059.001, T1018, T1016 |
| FZ-A01-05 | T1548.002, T1547.001, T1136.001, T1562.001 |
| PP-B01-10 | T1200, T1595 |
| PP-I01-10 | T1557.001, T1040, T1071 |
| PP-A01-05 | T1110.002, T1557.001, T1056 |

---

[← Keyboard Layouts](../05_Keyboard_Layouts/) | [Back to Technical Addendum](../README.md) | [Next: Cracking Reference →](../07_Cracking_Reference/)
