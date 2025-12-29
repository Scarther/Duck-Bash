# GitHub Payload Resources

## Overview

This document catalogs the most useful DuckyScript and BadUSB payload repositories on GitHub. Use these for learning, reference, and inspiration when developing your own payloads.

> **Legal Disclaimer**: All repositories mentioned are for **authorized security testing and educational purposes only**.

---

## Top Flipper Zero Repositories

### 1. I-Am-Jakoby/Flipper-Zero-BadUSB
- **URL**: https://github.com/I-Am-Jakoby/Flipper-Zero-BadUSB
- **Stars**: 5,815+ | **Forks**: 734+
- **Description**: Optimized plug-and-play payloads using short URLs for compact one-liners

**Notable Payloads**:
| Payload | Description | Red/Blue |
|---------|-------------|----------|
| WiFi Grabber | Extracts saved WiFi passwords, uploads to Dropbox/Discord | Red Team |
| IP Grabber | Retrieves target IP addresses | Red Team |
| Credz-Plz | Credential harvesting via fake prompts | Red Team |
| Browser Data | Retrieves browsing history and bookmarks | Red Team |
| Speech to Text | Activates microphone, converts to text, exfiltrates | Red Team |
| Wallpaper Taunter | Displays collected info as wallpaper | Red Team (Demo) |

**Learning Value**: Well-documented with explanations of techniques used.

---

### 2. FalsePhilosopher/badusb
- **URL**: https://github.com/FalsePhilosopher/badusb
- **Stars**: 1,600+ | **Forks**: 233+
- **Description**: Comprehensive payload library with organized categories

**Categories**:
- Exfiltration - Data extraction via Dropbox, GitHub, Discord webhooks
- Credentials - Password grabbers and credential harvesters
- Remote Access - Reverse shell establishment
- Phishing - Social engineering payloads
- Recon - System reconnaissance scripts
- Pranks - Harmless demonstration scripts

**OS Support**: Windows, Linux, macOS

---

### 3. UberGuidoZ/Flipper
- **URL**: https://github.com/UberGuidoZ/Flipper
- **Stars**: 16,400+
- **Description**: Comprehensive "playground and dump" of Flipper Zero resources

**Contents**:
- BadUSB scripts
- SubGHz files
- NFC data
- Infrared files
- Documentation

---

### 4. UberGuidoZ/Flipper_Zero-BadUsb
- **URL**: https://github.com/UberGuidoZ/Flipper_Zero-BadUsb
- **Description**: Extensive BadUSB script collection in DuckyScript 1.0

**Features**:
- Non-US keyboard layout converters
- Wide range of payloads
- Well-documented installation instructions

---

## Official Hak5 Repositories

### USB Rubber Ducky (Official)
- **URL**: https://github.com/hak5/usbrubberducky-payloads
- **Stars**: 5,396+
- **Description**: The official USB Rubber Ducky payload repository

**Payload Categories**:
| Category | Description | Notable Payloads |
|----------|-------------|------------------|
| Credentials | Authentication/sensitive data extraction | SamDumpDucky, BitLockerKeyDump |
| Exfiltration | Data extraction from target systems | Windows Privilege Excalibur |
| Execution | Command execution payloads | Elevated PowerShell |
| Remote Access | Backdoor establishment | ReverseDuckyUltimate |
| Recon | System reconnaissance | Various info-gathering |

**Key Extensions (Reusable Components)**:
- `PASSIVE_WINDOWS_DETECT` - OS detection
- `WINDOWS_ELEVATED_EXECUTION` - Privilege escalation
- `WINDOWS_FILELESS_HID_EXFIL` - Exfil via keyboard LEDs
- `ROLLING_POWERSHELL_EXECUTION` - Obfuscated execution

---

### Bash Bunny (Official)
- **URL**: https://github.com/hak5/bashbunny-payloads
- **Stars**: 2,862+
- **Description**: Linux machine in a USB form factor

**Capabilities**:
- Emulates Ethernet, serial, storage, and keyboards simultaneously
- Languages: DuckyScript + Bash

---

### WiFi Pineapple Pager (Official)
- **URL**: https://github.com/hak5/wifipineapplepager-payloads
- **Description**: Portable wireless auditing device payloads

**Languages**: DuckyScript + Bash scripting

---

## MITRE ATT&CK Aligned Resources

### Starvinci/BadUsb-Library
- **URL**: https://github.com/Starvinci/BadUsb-Library
- **Description**: 374 BadUSB payloads organized by MITRE ATT&CK Framework

**Value for Training**:
- Structured for learning offensive techniques
- Defensive context provided
- MITRE mapping: BadUSB = T1200 (Hardware Additions)

---

## Budget Alternatives

### Digispark ATtiny85 Repositories

#### MTK911/Attiny85
- **URL**: https://github.com/MTK911/Attiny85
- **Description**: RubberDucky-like payloads for DigiSpark ATtiny85

**Notable Payloads**:
- WiFi Password Stealer
- Windows Crasher

**IDE**: Arduino with DigiKeyboard.h library

---

### Raspberry Pi Pico Repositories

#### dbisu/pico-ducky (Most Popular)
- **URL**: https://github.com/dbisu/pico-ducky
- **Description**: Create USB Rubber Ducky using Raspberry Pi Pico

**Features**:
- Supports DuckyScript 1.0 and some 3.0 features
- Multiple payload storage
- Pico W: Web interface for payload management

**Setup Time**: Under 5 minutes

---

## GitHub Topic Pages

Use these to discover more repositories:

| Topic | URL |
|-------|-----|
| flipper-zero-payload | https://github.com/topics/flipper-zero-payload |
| badusb-payloads | https://github.com/topics/badusb-payloads |
| badusb | https://github.com/topics/badusb |
| ducky-payloads | https://github.com/topics/ducky-payloads |
| duckyscript | https://github.com/topics/duckyscript |
| hid-attacks | https://github.com/topics/hid-attacks |
| digispark-payload | https://github.com/topics/digispark-payload |
| pico-ducky | https://github.com/topics/pico-ducky |

---

## Development Tools

### PayloadStudio (Hak5)
- **URL**: payloadstudio.hak5.org
- **Description**: Web-based IDE for payload development

**Features**:
- Syntax highlighting
- Auto-completion
- Live error-checking
- Device targeting

### DuckyBuilder
- **URL**: https://github.com/ridercz/DuckyBuilder
- **Description**: Build system for multiple keyboard layouts

---

## Summary: Top Picks by Purpose

| Purpose | Repository | Why |
|---------|-----------|-----|
| Learning | hak5/usbrubberducky-payloads | Official, well-documented |
| Flipper Zero | I-Am-Jakoby/Flipper-Zero-BadUSB | Plug-and-play, optimized |
| Comprehensive | UberGuidoZ/Flipper | 16K+ stars, everything |
| MITRE Aligned | Starvinci/BadUsb-Library | Framework-based learning |
| Budget | dbisu/pico-ducky | $4 Pico, quick setup |
| Multi-Platform | FalsePhilosopher/badusb | Windows/Linux/macOS |

---

## Recommended Learning Path

1. **Start**: hak5/usbrubberducky-payloads - Study official payloads
2. **Practice**: I-Am-Jakoby collection - Test on your devices
3. **Expand**: UberGuidoZ/Flipper - Explore comprehensive collection
4. **Map**: Starvinci/BadUsb-Library - Understand MITRE ATT&CK context
5. **Create**: Develop your own based on learned patterns

---

## Blue Team Note

For each repository studied, document:
1. What artifacts the payload creates
2. What detection opportunities exist
3. What prevention measures would block it

This dual-perspective learning is essential for security professionals.

---

[← Back to Tool Integration](README.md) | [Next: Metasploit Integration →](Metasploit_Integration.md)
