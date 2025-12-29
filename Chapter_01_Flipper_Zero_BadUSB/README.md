# Chapter 1: Flipper Zero BadUSB

## Overview

This chapter covers everything you need to know about using the Flipper Zero's BadUSB functionality, from basic "Hello World" payloads to advanced attack chains.

---

## Chapter Contents

| Section | Description | Skill Level |
|---------|-------------|-------------|
| [01_Fundamentals](01_Fundamentals/) | Core concepts, DuckyScript syntax | Beginner |
| [02_Basic_Scripts](02_Basic_Scripts/) | Simple payloads (FZ-B01 to FZ-B15) | Beginner |
| [03_Intermediate_Scripts](03_Intermediate_Scripts/) | Recon, extraction, persistence (FZ-I01 to FZ-I15) | Intermediate |
| [04_Advanced_Scripts](04_Advanced_Scripts/) | Bypasses, shells, chains (FZ-A01 to FZ-A10) | Advanced |
| [05_Expert_Scripts](05_Expert_Scripts/) | Full frameworks (FZ-E01 to FZ-E05) | Expert |
| [06_Deployment_Strategies](06_Deployment_Strategies/) | Physical access tactics | Advanced |
| [07_Development_Creation](07_Development_Creation/) | Building your own payloads | Intermediate |
| [08_Red_Team_Tactics](08_Red_Team_Tactics/) | Offensive operations | Advanced |
| [09_Blue_Team_Countermeasures](09_Blue_Team_Countermeasures/) | Detection & prevention | All Levels |

---

## Learning Path

```
Week 1-2 (Basic)
├── 01_Fundamentals - Understand DuckyScript
├── 02_Basic_Scripts - FZ-B01 through FZ-B05
└── Practice in lab environment

Week 3-4 (Intermediate)
├── 02_Basic_Scripts - Complete FZ-B06 through FZ-B15
├── 03_Intermediate_Scripts - Start FZ-I01 through FZ-I08
└── 09_Blue_Team_Countermeasures - Detection basics

Week 5-6 (Advanced)
├── 03_Intermediate_Scripts - Complete FZ-I09 through FZ-I15
├── 04_Advanced_Scripts - FZ-A01 through FZ-A06
└── 08_Red_Team_Tactics - MITRE mapping

Week 7+ (Expert)
├── 04_Advanced_Scripts - Complete FZ-A07 through FZ-A10
├── 05_Expert_Scripts - Full frameworks
├── 06_Deployment_Strategies - Field operations
└── 07_Development_Creation - Create your own
```

---

## Payload Index

### Basic Level (FZ-B01 to FZ-B15)

| ID | Name | Target OS | Description |
|----|------|-----------|-------------|
| FZ-B01 | Hello World - Windows | Windows | Open Notepad, type message |
| FZ-B02 | Hello World - macOS | macOS | Open TextEdit, type message |
| FZ-B03 | Hello World - Linux | Linux | Open gedit, type message |
| FZ-B04 | System Info - Windows | Windows | Display basic system info |
| FZ-B05 | System Info - macOS | macOS | Display basic system info |
| FZ-B06 | System Info - Linux | Linux | Display basic system info |
| FZ-B07 | Open Website | All | Open browser to URL |
| FZ-B08 | Lock Workstation - Windows | Windows | Lock the screen |
| FZ-B09 | Lock Workstation - macOS | macOS | Lock the screen |
| FZ-B10 | Lock Workstation - Linux | Linux | Lock the screen |
| FZ-B11 | Screenshot | Windows | Capture screen |
| FZ-B12 | Wallpaper Prank | Windows | Change wallpaper |
| FZ-B13 | Rick Roll | All | Open Rick Roll video |
| FZ-B14 | WiFi Password Display | Windows | Show WiFi passwords on screen |
| FZ-B15 | Create Desktop Message | Windows | Create text file on desktop |

### Intermediate Level (FZ-I01 to FZ-I15)

| ID | Name | Target OS | Description |
|----|------|-----------|-------------|
| FZ-I01 | Comprehensive System Recon | Windows | Full system enumeration |
| FZ-I02 | WiFi Password Extractor | Windows | Extract and save WiFi passwords |
| FZ-I03 | Network Reconnaissance | Windows | Network mapping |
| FZ-I04 | User Enumeration | Windows | List all users and groups |
| FZ-I05 | Installed Software | Windows | List all installed programs |
| FZ-I06 | Browser Data Locator | Windows | Find browser data locations |
| FZ-I07 | Clipboard Capture | Windows | Capture clipboard contents |
| FZ-I08 | Scheduled Task Persistence | Windows | Create persistent backdoor |
| FZ-I09 | Registry Persistence | Windows | Registry-based persistence |
| FZ-I10 | Download and Execute | Windows | Download and run payload |
| FZ-I11 | Process Snapshot | Windows | List running processes |
| FZ-I12 | Startup Enumeration | Windows | List startup items |
| FZ-I13 | Environment Variables | Windows | Dump environment vars |
| FZ-I14 | Recent Files | Windows | List recently accessed files |
| FZ-I15 | macOS System Info | macOS | Comprehensive macOS recon |

### Advanced Level (FZ-A01 to FZ-A10)

| ID | Name | Target OS | Description |
|----|------|-----------|-------------|
| FZ-A01 | Multi-Stage Recon | Windows | Phased reconnaissance |
| FZ-A02 | Reverse Shell | Windows | Establish reverse connection |
| FZ-A03 | AMSI Bypass | Windows | Bypass Antimalware Scan Interface |
| FZ-A04 | UAC Bypass (fodhelper) | Windows | Bypass User Account Control |
| FZ-A05 | Keylogger | Windows | Capture keystrokes |
| FZ-A06 | DNS Exfiltration | Windows | Exfiltrate data via DNS |
| FZ-A07 | Credential Phishing Popup | Windows | Fake login prompt |
| FZ-A08 | Network Share Enumeration | Windows | Map network shares |
| FZ-A09 | Complete Attack Chain | Windows | Full attack lifecycle |
| FZ-A10 | Anti-Forensics | Windows | Evidence cleanup |

### Expert Level (FZ-E01 to FZ-E05)

| ID | Name | Target OS | Description |
|----|------|-----------|-------------|
| FZ-E01 | Advanced Persistence Framework | Windows | Multiple persistence methods |
| FZ-E02 | Full Stealth Recon | Windows | Minimally detectable recon |
| FZ-E03 | Domain Reconnaissance | Windows | Active Directory enumeration |
| FZ-E04 | Data Harvester | Windows | Comprehensive data collection |
| FZ-E05 | Complete Engagement Payload | Windows | Full red team payload |

---

## Prerequisites

Before starting this chapter:
- [ ] Flipper Zero with firmware installed
- [ ] MicroSD card formatted and inserted
- [ ] Test environment (VMs recommended)
- [ ] Basic understanding of command line

---

## Quick Start

1. Read [01_Fundamentals](01_Fundamentals/) to understand DuckyScript
2. Try [FZ-B01 Hello World](02_Basic_Scripts/FZ-B01_Hello_World.md) in your lab
3. Progress through each skill level
4. Always study the Blue Team countermeasures

---

[← Back to Main README](../README.md) | [Next: Fundamentals →](01_Fundamentals/)
