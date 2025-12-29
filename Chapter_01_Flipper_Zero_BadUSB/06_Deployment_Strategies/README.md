# Deployment Strategies

## Overview

Effective payload deployment requires understanding the physical access scenarios, social engineering vectors, and operational security considerations. This section covers tactical deployment approaches for authorized security testing.

---

## Physical Access Scenarios

### Quick Drop (< 30 seconds)

```
Scenario: Brief physical access to unlocked workstation
Requirements:
├── Pre-loaded minimal payload
├── Fast execution (< 10 commands)
├── No visible windows
└── No user interaction required

Payload Type: Basic/Intermediate
Examples:
├── WiFi password dump
├── Clipboard capture
├── Quick system info grab
└── Beacon deployment

Timing Considerations:
├── USB enumeration: 1-2 seconds
├── Payload execution: 3-5 seconds
├── Window closing: 1 second
└── Total: < 10 seconds active
```

### Maintenance Window (2-5 minutes)

```
Scenario: Extended access during IT maintenance
Requirements:
├── Multi-stage payload
├── Comprehensive reconnaissance
├── Persistence establishment
├── Cleanup operations
└── Plausible cover story

Payload Type: Advanced
Examples:
├── Full attack chain with exfiltration
├── Domain enumeration + credential harvesting
├── Service installation for persistence
└── Network mapping and share enumeration

Operational Flow:
1. Quick recon (30 sec)
2. Persistence install (60 sec)
3. Data collection (120 sec)
4. Exfiltration (30 sec)
5. Cleanup (30 sec)
```

### Unattended Access (5+ minutes)

```
Scenario: After-hours physical access
Requirements:
├── Complete reconnaissance
├── Multiple persistence mechanisms
├── Network mapping
├── Credential harvesting
├── Staged exfiltration
└── Anti-forensics measures

Payload Type: Expert
Examples:
├── Polymorphic payload with evasion
├── Full domain reconnaissance
├── Certificate/key extraction
├── Lateral movement preparation
└── Long-term access establishment
```

---

## Social Engineering Delivery

### USB Drop Attack

```
Cover Stories:
├── "Lost" USB drive in parking lot
├── Conference/event giveaway drives
├── "Firmware update" drives from IT
├── "Training materials" USB
└── "Important documents" delivery

Payload Considerations:
├── Boot delay (users plug in, wait, forget)
├── Silent execution (no visible windows)
├── Persistence for later access
├── Activity only when system idle
└── Blend with expected behavior

Success Factors:
├── Attractive labeling ("Confidential", "HR", "Payroll")
├── Professional appearance
├── Placement near target area
├── Timing with employee movement
└── Multiple drops for coverage
```

### Insider Threat Simulation

```
Scenario: Testing insider threat controls
Method: Authorized employee plants device
Purpose: Test detection and response capabilities

Payload Types:
├── Data exfiltration attempt tracking
├── Privilege escalation testing
├── Policy violation detection
└── Security awareness verification

Documentation Required:
├── Written authorization
├── Scope limitations
├── Emergency contacts
└── Time boundaries
```

---

## Network-Adjacent Deployment

### Evil Maid Attack

```
Target: Laptop left in hotel room
Window: Housekeeping access (~10 min)
Payload: Persistent backdoor, keylogger

Attack Flow:
1. Access locked laptop
2. Boot from external device (or use USB attack)
3. Install persistence mechanism
4. Deploy keylogger/backdoor
5. Configure for exfil on network connection
6. Leave no visible traces

Recovery Methods:
├── Exfil on next WiFi connection
├── Beacon to C2 server
├── DNS exfiltration
└── Scheduled upload to cloud storage

Detection Countermeasures:
├── Full disk encryption
├── Secure boot verification
├── Hardware tamper seals
├── Pre-boot authentication
└── Travel device policies
```

### Conference/Trade Show Deployment

```
Scenario: Target devices at industry events
Opportunities:
├── Charging stations (compromised)
├── Demo stations (unattended)
├── Shared workstations
├── Presentation computers
└── Network infrastructure

Payload Goals:
├── Credential harvesting
├── Corporate email access
├── VPN configuration theft
├── Contact/calendar extraction
└── Document access
```

---

## Timing Considerations

### When to Deploy

```
Optimal Windows:
├── Lunch hours (12:00-13:00)
├── Early morning (07:00-08:00)
├── Late afternoon (17:00-18:00)
├── Meeting times (conferences/reviews)
└── IT maintenance windows

Avoid:
├── Peak activity hours
├── Security audit periods
├── Immediately after incidents
├── When security is heightened
└── Major deadline periods
```

### Execution Timing

| Action | Minimum | Recommended | Max |
|--------|---------|-------------|-----|
| USB Connect | 1000ms | 2000ms | 3000ms |
| GUI r | 200ms | 500ms | 1000ms |
| App Launch | 500ms | 1000ms | 2000ms |
| PowerShell | 1000ms | 1500ms | 2500ms |
| Between cmds | 100ms | 200ms | 500ms |
| Cleanup | 500ms | 1000ms | 2000ms |

---

## Operational Security

### Pre-Deployment

```
Checklist:
□ Payload tested in lab environment
□ Target OS verified
□ Authorization documented
□ Emergency contacts confirmed
□ Extraction plan prepared
□ Evidence handling planned
```

### During Deployment

```
Best Practices:
├── Minimize time on target
├── Avoid cameras when possible
├── Natural behavior (don't rush)
├── Cover story prepared
├── Abort criteria defined
└── Communication blackout (no phones)
```

### Post-Deployment

```
Actions:
├── Document timeline
├── Verify payload execution
├── Collect exfiltrated data
├── Report any anomalies
├── Secure evidence
└── Debrief with team
```

---

## Deployment Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT DECISION TREE                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                    ┌─────────────────┐                              │
│                    │  Physical Access │                              │
│                    │    Available?    │                              │
│                    └────────┬────────┘                              │
│                             │                                        │
│              ┌──────────────┼──────────────┐                        │
│              │              │              │                         │
│              ▼              ▼              ▼                         │
│        ┌──────────┐  ┌──────────┐  ┌──────────┐                    │
│        │ < 30 sec │  │ 2-5 min  │  │ 5+ min   │                    │
│        └────┬─────┘  └────┬─────┘  └────┬─────┘                    │
│             │             │             │                            │
│             ▼             ▼             ▼                            │
│        ┌──────────┐  ┌──────────┐  ┌──────────┐                    │
│        │ Quick    │  │ Multi-   │  │ Full     │                    │
│        │ Drop     │  │ Stage    │  │ Engagement│                   │
│        │ Payload  │  │ Payload  │  │ Payload  │                    │
│        └──────────┘  └──────────┘  └──────────┘                    │
│             │             │             │                            │
│             ▼             ▼             ▼                            │
│        FZ-B/I        FZ-A          FZ-E                             │
│        Series        Series        Series                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│                DEPLOYMENT QUICK REFERENCE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  QUICK DROP (< 30s):                                                │
│  ├── Simple payloads (FZ-B/I)                                       │
│  ├── No visible windows                                             │
│  ├── Minimal commands                                               │
│  └── Pre-tested timing                                              │
│                                                                      │
│  MAINTENANCE WINDOW (2-5 min):                                      │
│  ├── Multi-stage payloads (FZ-A)                                    │
│  ├── Persistence + recon                                            │
│  ├── Cleanup operations                                             │
│  └── Cover story ready                                              │
│                                                                      │
│  UNATTENDED (5+ min):                                               │
│  ├── Full engagement (FZ-E)                                         │
│  ├── Multiple persistence                                           │
│  ├── Complete reconnaissance                                        │
│  └── Anti-forensics                                                 │
│                                                                      │
│  ALWAYS:                                                            │
│  ├── Written authorization                                          │
│  ├── Tested payloads                                                │
│  ├── Emergency contacts                                             │
│  └── Documentation                                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Expert Scripts](../05_Expert_Scripts/) | [Back to Flipper Zero](../README.md) | [Next: Development & Creation →](../07_Development_Creation/)
