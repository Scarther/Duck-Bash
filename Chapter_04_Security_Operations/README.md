# Chapter 04: Security Operations

## Overview

This chapter provides comprehensive defensive security guidance for detecting, preventing, and responding to USB HID attacks and wireless threats. Content is designed for blue team practitioners, security analysts, and IT professionals responsible for protecting organizational assets.

---

## Learning Objectives

By completing this chapter, you will be able to:

- Implement effective monitoring for USB/HID and wireless attacks
- Configure SIEM, EDR, and IDS/IPS for payload detection
- Understand botnet infrastructure for threat modeling
- Apply security hardening to reduce attack surface
- Execute incident response procedures for compromise scenarios
- Leverage threat intelligence for proactive defense

---

## Chapter Structure

```
Chapter_04_Security_Operations/
├── 01_Blue_Team_Fundamentals/     # Defensive mindset and core concepts
├── 02_Security_Monitoring_SIEM/   # Log aggregation and correlation
├── 03_EDR/                        # Endpoint detection and response
├── 04_Network_Monitoring_IDS_IPS/ # Network-based detection
├── 05_Botnet_Understanding/       # Adversary infrastructure knowledge
├── 06_Security_Hardening/         # Preventive controls
├── 07_Incident_Response/          # Response procedures and playbooks
└── 08_Threat_Intelligence/        # Intel gathering and application
```

---

## Defense-in-Depth Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DEFENSE-IN-DEPTH LAYERS                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    PHYSICAL SECURITY                         │   │
│  │    USB port locks, device inspection, access controls        │   │
│  │  ┌─────────────────────────────────────────────────────┐    │   │
│  │  │                NETWORK SECURITY                      │    │   │
│  │  │    WIDS, NAC, network segmentation, IDS/IPS          │    │   │
│  │  │  ┌─────────────────────────────────────────────┐    │    │   │
│  │  │  │            ENDPOINT SECURITY                 │    │    │   │
│  │  │  │    EDR, USB device control, app whitelisting │    │    │   │
│  │  │  │  ┌─────────────────────────────────────┐    │    │    │   │
│  │  │  │  │        APPLICATION SECURITY          │    │    │    │   │
│  │  │  │  │    Input validation, least privilege │    │    │    │   │
│  │  │  │  │  ┌─────────────────────────────┐    │    │    │    │   │
│  │  │  │  │  │      DATA SECURITY           │    │    │    │    │   │
│  │  │  │  │  │    Encryption, DLP, backup   │    │    │    │    │   │
│  │  │  │  │  └─────────────────────────────┘    │    │    │    │   │
│  │  │  │  └─────────────────────────────────────┘    │    │    │   │
│  │  │  └─────────────────────────────────────────────┘    │    │   │
│  │  └─────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Cross-Cutting: Monitoring │ Logging │ Alerting │ Response          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Attack Surface Overview

### USB/HID Attack Vectors

| Vector | Description | Primary Defense |
|--------|-------------|-----------------|
| BadUSB | Malicious keyboard emulation | USB device control |
| USB Drop | Social engineering with USB drives | User awareness |
| Charging Attacks | Compromised charging stations | Data-only cables |
| Supply Chain | Pre-compromised peripherals | Procurement vetting |

### Wireless Attack Vectors

| Vector | Description | Primary Defense |
|--------|-------------|-----------------|
| Evil Twin | Rogue access point impersonation | WIDS, 802.1X |
| Deauth | Denial of service attacks | PMF, WIDS alerting |
| KARMA | Responding to any probe | Client configuration |
| Credential Harvest | Captive portal phishing | User awareness |

---

## Detection Strategy Matrix

```
┌────────────────┬──────────┬──────────┬──────────┬──────────┐
│ Attack Type    │   SIEM   │   EDR    │  IDS/IPS │   WIDS   │
├────────────────┼──────────┼──────────┼──────────┼──────────┤
│ BadUSB         │    ●     │    ●●●   │    ○     │    ○     │
│ Keystroke Inj. │    ●     │    ●●●   │    ○     │    ○     │
│ Exfiltration   │    ●●    │    ●●    │    ●●●   │    ○     │
│ Evil Twin      │    ●     │    ○     │    ●     │    ●●●   │
│ Deauth Attack  │    ●     │    ○     │    ●     │    ●●●   │
│ Cred Harvest   │    ●●    │    ●     │    ●●    │    ●●    │
│ C2 Callback    │    ●●    │    ●●●   │    ●●●   │    ○     │
│ Persistence    │    ●●    │    ●●●   │    ○     │    ○     │
└────────────────┴──────────┴──────────┴──────────┴──────────┘

Legend: ○ = Limited  ● = Some  ●● = Good  ●●● = Excellent
```

---

## Quick Reference: Detection Sources

### USB/HID Attack Detection

```
Event Sources:
├── Windows Security Log (4624, 4688)
├── Sysmon (Event ID 1, 11, 12, 13)
├── USB Device Events (2003, 2010)
├── PowerShell Logs (4103, 4104)
└── EDR Telemetry

Key Indicators:
├── Rapid keystroke injection (>50 chars/sec)
├── PowerShell from explorer.exe
├── New USB HID with suspicious VID/PID
├── Registry Run key modifications
└── Encoded command execution
```

### Wireless Attack Detection

```
Event Sources:
├── WIDS/WIPS Alerts
├── AP Logs
├── RADIUS Logs
├── Network Traffic (pcap)
└── Client Connection Logs

Key Indicators:
├── Duplicate SSID with different BSSID
├── Deauth frame floods
├── Unknown AP in controlled space
├── Failed 802.1X authentications
└── DNS redirect to local IP
```

---

## Chapter Contents

| Section | Title | Focus Area |
|---------|-------|------------|
| 01 | [Blue Team Fundamentals](./01_Blue_Team_Fundamentals/) | Defensive mindset, visibility, detection engineering |
| 02 | [Security Monitoring & SIEM](./02_Security_Monitoring_SIEM/) | Log collection, correlation, alerting |
| 03 | [EDR](./03_EDR/) | Endpoint detection, behavioral analysis |
| 04 | [Network Monitoring IDS/IPS](./04_Network_Monitoring_IDS_IPS/) | Network-based detection and prevention |
| 05 | [Botnet Understanding](./05_Botnet_Understanding/) | Adversary infrastructure, C2 patterns |
| 06 | [Security Hardening](./06_Security_Hardening/) | Preventive controls, attack surface reduction |
| 07 | [Incident Response](./07_Incident_Response/) | Response procedures, playbooks, forensics |
| 08 | [Threat Intelligence](./08_Threat_Intelligence/) | Intel sources, IOCs, threat hunting |

---

## Recommended Learning Path

```
Week 1-2: Foundation
├── Blue Team Fundamentals
├── Security Monitoring & SIEM basics
└── Hands-on: Set up logging

Week 3-4: Detection
├── EDR configuration
├── IDS/IPS rules
└── Hands-on: Build detection rules

Week 5-6: Prevention
├── Security Hardening
├── Botnet Understanding
└── Hands-on: Harden test environment

Week 7-8: Response
├── Incident Response procedures
├── Threat Intelligence integration
└── Hands-on: Tabletop exercises
```

---

## Key Takeaways

1. **Visibility First**: You can't protect what you can't see
2. **Layer Defenses**: No single control is sufficient
3. **Assume Breach**: Design for detection, not just prevention
4. **Know the Adversary**: Understanding attacks improves defense
5. **Practice Response**: Procedures untested are procedures failed

---

[← Technical Addendum](../Chapter_03_Technical_Addendum/) | [Back to Main](../README.md) | [Next: Skill Levels →](../Chapter_05_Skill_Levels/)
