# Chapter 2: WiFi Pineapple Pager

## Overview

This chapter covers the WiFi Pineapple Pager - a compact wireless auditing platform. Learn to scan networks, capture handshakes, deploy rogue APs, and detect wireless attacks.

---

## Chapter Contents

| Section | Description | Skill Level |
|---------|-------------|-------------|
| [01_Fundamentals](01_Fundamentals/) | Device overview, Bash basics | Beginner |
| [02_Basic_Payloads](02_Basic_Payloads/) | Simple payloads (PP-B01 to PP-B10) | Beginner |
| [03_Intermediate_Payloads](03_Intermediate_Payloads/) | Logging, tracking (PP-I01 to PP-I10) | Intermediate |
| [04_Advanced_Payloads](04_Advanced_Payloads/) | Evil Twin, PMKID (PP-A01 to PP-A05) | Advanced |
| [05_Red_Team_Tactics](05_Red_Team_Tactics/) | Wireless attack operations | Advanced |
| [06_Blue_Team_Countermeasures](06_Blue_Team_Countermeasures/) | Rogue AP detection, WIDS | All Levels |

---

## Key Differences from Flipper Zero

```
┌─────────────────────────────────────────────────────────────────────────────┐
│               FLIPPER ZERO vs WIFI PINEAPPLE PAGER                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FLIPPER ZERO                        WIFI PINEAPPLE PAGER                   │
│  ────────────                        ───────────────────                    │
│  Language: DuckyScript               Language: Bash                          │
│  Attack: USB/Keyboard injection      Attack: Wireless networks               │
│  Target: Single computer             Target: WiFi infrastructure             │
│  Connection: USB                     Connection: Wireless (802.11)           │
│  Range: Physical access              Range: Up to 100m+ with antenna         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Learning Path

```
Week 1-2 (Basic)
├── 01_Fundamentals - Understand device and Bash
├── 02_Basic_Payloads - PP-B01 through PP-B05
└── Practice in isolated lab

Week 3-4 (Intermediate)
├── 02_Basic_Payloads - Complete PP-B06 through PP-B10
├── 03_Intermediate_Payloads - PP-I01 through PP-I05
└── 06_Blue_Team - Detection basics

Week 5+ (Advanced)
├── 03_Intermediate_Payloads - Complete PP-I06 through PP-I10
├── 04_Advanced_Payloads - PP-A01 through PP-A05
├── 05_Red_Team_Tactics - Field operations
└── 06_Blue_Team - WIDS deployment
```

---

## Payload Index

### Basic Level (PP-B01 to PP-B10)

| ID | Name | Type | Description |
|----|------|------|-------------|
| PP-B01 | Hello World | User | Test device functionality |
| PP-B02 | Handshake Alert | Alert | Notify on handshake capture |
| PP-B03 | Client Connected Alert | Alert | Notify on client connection |
| PP-B04 | Basic Scan | User | Scan nearby networks |
| PP-B05 | Deauth Burst | User | Send deauth packets |
| PP-B06 | System Status | User | Display device status |
| PP-B07 | Battery Check | User | Display battery level |
| PP-B08 | Interface Status | User | Check wireless interfaces |
| PP-B09 | Log Viewer | User | Display recent logs |
| PP-B10 | Quick Recon | User | Fast network summary |

### Intermediate Level (PP-I01 to PP-I10)

| ID | Name | Type | Description |
|----|------|------|-------------|
| PP-I01 | Network Scanner | User | Comprehensive WiFi scan |
| PP-I02 | Handshake Logger | Alert | Log detailed handshake info |
| PP-I03 | Client Tracker | Alert | Track connected clients |
| PP-I04 | Probe Logger | User | Capture probe requests |
| PP-I05 | SSID Pool Manager | User | Manage PineAP SSID pool |
| PP-I06 | AP Recon | Recon | Detailed AP reconnaissance |
| PP-I07 | Channel Hopper | User | Monitor multiple channels |
| PP-I08 | Signal Mapper | User | Map signal strengths |
| PP-I09 | Client Deauth | User | Targeted client disconnect |
| PP-I10 | Data Exfil | User | Send data to remote server |

### Advanced Level (PP-A01 to PP-A05)

| ID | Name | Type | Description |
|----|------|------|-------------|
| PP-A01 | Evil Twin Attack | User | Create rogue AP matching target |
| PP-A02 | Captive Portal | User | Credential capture portal |
| PP-A03 | Handshake Hunter | User | Automated handshake capture |
| PP-A04 | PMKID Attack | Recon | Capture PMKID without client |
| PP-A05 | Full Spectrum Audit | User | Comprehensive WiFi audit |

---

## Prerequisites

Before starting this chapter:
- [ ] WiFi Pineapple Pager (or similar device)
- [ ] Isolated test network (NEVER test on networks you don't own)
- [ ] Basic Linux/Bash knowledge
- [ ] Understanding of WiFi protocols (helpful)

---

## Important Legal Warning

**Wireless attacks are ILLEGAL without explicit authorization.**

- Only test on networks you own OR have written permission to test
- Using these techniques on unauthorized networks is a federal crime
- Many techniques can disrupt legitimate network users
- Always work in an isolated lab environment when learning

---

## Quick Start

1. Read [01_Fundamentals](01_Fundamentals/) to understand the device
2. Set up an isolated test network
3. Try [PP-B01 Hello World](02_Basic_Payloads/PP-B01_Hello_World.md)
4. Progress through skill levels
5. Always study Blue Team countermeasures

---

[← Back to Main README](../README.md) | [Next: Fundamentals →](01_Fundamentals/)
