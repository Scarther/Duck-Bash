# Chapter 2.4: WiFi Pineapple Advanced Payloads

## Overview

Advanced WiFi Pineapple payloads for sophisticated wireless security assessments. These payloads implement complex attack chains, evasion techniques, and enterprise-grade targeting.

---

## Prerequisites

Before attempting advanced payloads, ensure you:

1. **Completed Basic & Intermediate**: Mastered PP-B and PP-I series
2. **Strong Bash Skills**: Comfortable with complex scripts
3. **Networking Knowledge**: TCP/IP, 802.11, authentication protocols
4. **Tool Proficiency**: aircrack-ng suite, hostapd, RADIUS concepts
5. **Legal Authorization**: Written permission for all testing

---

## Advanced Payloads

| ID | Name | Target | Complexity |
|----|------|--------|------------|
| [PP-A01](PP-A01_Credential_Harvester.md) | Credential Harvester | Network Users | High |
| [PP-A02](PP-A02_Multi_Stage_Attack.md) | Multi-Stage Attack | Enterprise Networks | High |
| [PP-A03](PP-A03_Automated_WPA_Cracker.md) | Automated WPA Cracker | WPA/WPA2 Networks | High |
| [PP-A04](PP-A04_WIDS_Evasion.md) | WIDS Evasion | Protected Networks | Very High |
| [PP-A05](PP-A05_Enterprise_Attack.md) | Enterprise Attack Suite | WPA2-Enterprise | Expert |

---

## Payload Summaries

### PP-A01: Credential Harvester
A comprehensive credential harvesting system combining:
- Evil Twin access point
- Multiple captive portal templates (hotel, corporate, airport, etc.)
- Real-time traffic interception
- Automatic credential logging
- Remote notification support

### PP-A02: Multi-Stage Attack Framework
Orchestrated attack progression through:
- **Stage 1**: Passive reconnaissance
- **Stage 2**: Target analysis and selection
- **Stage 3**: Attack execution (WEP/WPA/Evil Twin)
- **Stage 4**: Persistence and reporting

### PP-A03: Automated WPA Cracker
Complete WPA/WPA2 cracking automation:
- PMKID extraction (clientless attack)
- Handshake capture with intelligent deauth
- Multi-wordlist dictionary attacks
- Pattern-based password generation
- Hashcat/John integration

### PP-A04: Wireless IDS Evasion
Techniques to avoid WIDS detection:
- MAC address rotation with vendor spoofing
- Timing randomization and jitter
- Transmit power control
- Behavioral mimicry
- Adaptive detection avoidance

### PP-A05: Enterprise Attack Suite
Targeting WPA2-Enterprise (802.1X):
- Rogue RADIUS server deployment
- EAP credential harvesting
- MSCHAPv2 hash capture
- Certificate impersonation
- Offline hash cracking

---

## Technical Requirements

### Hardware
- WiFi Pineapple (Mark VII, Tetra, or Nano)
- External WiFi adapter (recommended)
- SD card with 4GB+ free space
- Power supply for extended operations

### Software Dependencies
```bash
# Core tools (usually pre-installed)
aircrack-ng
hostapd
dnsmasq
tcpdump

# Advanced tools (may need installation)
hostapd-wpe          # Enterprise attacks
hcxdumptool          # PMKID capture
hashcat              # GPU cracking
freeradius           # RADIUS server
```

### Wordlists
```
/sd/wordlists/
├── rockyou.txt          # Classic leaked passwords
├── common_wifi.txt      # WiFi-specific passwords
├── corporate.txt        # Business patterns
└── custom_target.txt    # Target-specific
```

---

## Attack Complexity Chart

```
┌─────────────────────────────────────────────────────────────┐
│                ADVANCED PAYLOAD COMPLEXITY                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Complexity                                                  │
│      ▲                                                       │
│      │                                             PP-A05   │
│  10 ─┤                                    PP-A04   ████████ │
│      │                           PP-A03   ███████  ████████ │
│   8 ─┤                  PP-A02   ███████  ███████  ████████ │
│      │         PP-A01   ███████  ███████  ███████  ████████ │
│   6 ─┤         ███████  ███████  ███████  ███████  ████████ │
│      │         ███████  ███████  ███████  ███████  ████████ │
│   4 ─┤         ███████  ███████  ███████  ███████  ████████ │
│      │         ███████  ███████  ███████  ███████  ████████ │
│   2 ─┤         ███████  ███████  ███████  ███████  ████████ │
│      │         ███████  ███████  ███████  ███████  ████████ │
│   0 ─┼─────────────────────────────────────────────────────▶│
│             Credential  Multi    WPA      WIDS   Enterprise │
│             Harvester   Stage   Cracker  Evasion  Attack    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Red Team vs Blue Team

### Red Team Use Cases

| Scenario | Recommended Payload |
|----------|---------------------|
| External WiFi assessment | PP-A01, PP-A03 |
| Full enterprise audit | PP-A02, PP-A05 |
| Evasion testing | PP-A04 |
| Credential gathering | PP-A01, PP-A05 |
| WPA password audit | PP-A03 |

### Blue Team Detection Focus

| Payload | Detection Priority |
|---------|-------------------|
| PP-A01 | Rogue AP detection, DNS monitoring |
| PP-A02 | Multi-stage correlation |
| PP-A03 | Deauth storm detection |
| PP-A04 | Behavioral analysis, baseline deviation |
| PP-A05 | Certificate validation, RADIUS logging |

---

## Best Practices

### Operational Security
1. **Authorization**: Document all testing scope
2. **Logging**: Maintain detailed operation logs
3. **Data Handling**: Secure captured credentials
4. **Cleanup**: Remove all traces after testing
5. **Reporting**: Document vulnerabilities found

### Attack Optimization
1. **Timing**: Target busy hours for credential attacks
2. **Positioning**: Optimize signal coverage
3. **Patience**: Use slow, evasive techniques
4. **Adaptation**: Adjust to environment

### Legal Compliance
1. **Written Permission**: Required before any testing
2. **Scope Limits**: Stay within agreed boundaries
3. **Data Protection**: Handle PII appropriately
4. **Incident Response**: Have procedures ready

---

## Skill Progression

```
Basic Payloads (PP-B)
        │
        ▼
Intermediate Payloads (PP-I)
        │
        ▼
┌───────┴───────┐
│               │
▼               ▼
PP-A01         PP-A03
Credential     WPA
Harvester      Cracker
        │
        ▼
      PP-A02
   Multi-Stage
        │
        ▼
      PP-A04
   WIDS Evasion
        │
        ▼
      PP-A05
   Enterprise
```

---

## Learning Resources

### Recommended Reading
- 802.11 Wireless Networks: The Definitive Guide
- Practical Packet Analysis
- RADIUS documentation
- Hashcat wiki

### Practice Labs
1. Set up a test WPA2 network
2. Configure a lab WIDS (Kismet)
3. Deploy test WPA2-Enterprise
4. Practice credential cracking

---

## Navigation

[← Intermediate Payloads](../03_Intermediate_Payloads/README.md) | [Back to Chapter 2](../README.md) | [Red Team Tactics →](../05_Red_Team_Tactics/README.md)
