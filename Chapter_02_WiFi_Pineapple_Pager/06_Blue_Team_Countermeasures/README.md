# Blue Team Countermeasures - WiFi Pineapple Pager

## Overview

This section provides defensive strategies for protecting against wireless attacks conducted via the WiFi Pineapple Pager or similar tools. Designed for security operations, network security, and security architecture teams.

---

## Detection Strategies

### Rogue AP Detection

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ROGUE AP INDICATORS                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DETECTION INDICATORS:                                               │
│  ├── Multiple BSSIDs for same SSID                                  │
│  │   Legitimate: 1 BSSID per SSID per location                      │
│  │   Rogue: Additional BSSID with same SSID                         │
│  │                                                                   │
│  ├── Unexpected APs in scan results                                 │
│  │   Compare against authorized AP inventory                        │
│  │   Alert on new/unknown BSSIDs                                    │
│  │                                                                   │
│  ├── Signal strength anomalies                                      │
│  │   Rogue AP may have unusually strong signal                      │
│  │   Location inconsistent with known AP placement                  │
│  │                                                                   │
│  └── MAC address mismatches                                         │
│       OUI doesn't match corporate AP vendor                         │
│       MAC spoofing detection                                        │
│                                                                      │
│  DETECTION TOOLS:                                                    │
│  ├── WIPS (Wireless Intrusion Prevention System)                    │
│  │   Aruba RFProtect, Cisco CleanAir, etc.                          │
│  │                                                                   │
│  ├── Periodic authorized AP audits                                  │
│  │   Compare scans against inventory                                │
│  │                                                                   │
│  └── Client-side AP verification                                    │
│       Certificate pinning for enterprise WiFi                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Deauthentication Detection

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DEAUTH ATTACK INDICATORS                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DETECTION INDICATORS:                                               │
│  ├── High volume deauthentication frames                            │
│  │   Normal: Rare, individual deauth                                │
│  │   Attack: Burst of deauth frames                                 │
│  │                                                                   │
│  ├── Targeted deauth patterns                                       │
│  │   Same source/destination repeatedly                             │
│  │   Sequential client targeting                                    │
│  │                                                                   │
│  └── Client disconnection spikes                                    │
│       Multiple clients disconnecting simultaneously                 │
│       Followed by reconnection to different BSSID                   │
│                                                                      │
│  DETECTION METHODS:                                                  │
│  ├── WIDS monitoring                                                │
│  │   Deauth flood detection rules                                   │
│  │                                                                   │
│  ├── Frame analysis                                                 │
│  │   Count deauth frames per timeframe                              │
│  │   Alert above threshold                                          │
│  │                                                                   │
│  └── Connection stability metrics                                   │
│       Track disconnection frequency                                 │
│       Correlate with potential attacks                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Evil Twin Detection

```
EVIL TWIN INDICATORS:

1. Certificate Mismatch
   - Enterprise WPA uses certificates
   - Evil twin may present different cert
   - Client should reject invalid certs

2. BSSID Changes
   - Same SSID, different BSSID
   - Unexpected AP in trusted location

3. Captive Portal Anomalies
   - Corporate network shouldn't have portal
   - Unexpected login prompts
   - SSL certificate warnings

4. DHCP Irregularities
   - Different IP range than expected
   - Different gateway/DNS
   - Unusual lease times

DETECTION QUERIES:
- Alert on new BSSID for known SSID
- Alert on captive portal redirect from corporate SSID
- Monitor for certificate validation failures
```

---

## Prevention Measures

### WPA3 Implementation

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WPA3 SECURITY BENEFITS                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SAE (Simultaneous Authentication of Equals):                        │
│  ├── Prevents offline dictionary attacks                            │
│  │   Handshake cannot be captured and cracked offline               │
│  │                                                                   │
│  ├── Forward secrecy                                                │
│  │   Past traffic cannot be decrypted                               │
│  │                                                                   │
│  └── Password security                                              │
│       Weak passwords better protected                               │
│                                                                      │
│  PMF (Protected Management Frames):                                  │
│  ├── Prevents deauthentication attacks                              │
│  │   Management frames are encrypted                                │
│  │                                                                   │
│  └── Prevents disassociation attacks                                │
│       Can't force clients to disconnect                             │
│                                                                      │
│  OWE (Opportunistic Wireless Encryption):                            │
│  ├── Encryption for open networks                                   │
│  │   No password required                                           │
│  │                                                                   │
│  └── Prevents passive eavesdropping                                 │
│       Guest networks protected                                      │
│                                                                      │
│  DEPLOYMENT:                                                         │
│  ├── WPA3-Enterprise for corporate networks                         │
│  ├── WPA3-Personal for PSK networks                                 │
│  └── WPA3-Transition mode for compatibility                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 802.1X/EAP-TLS Implementation

```
┌─────────────────────────────────────────────────────────────────────┐
│                    802.1X ENTERPRISE SECURITY                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  CERTIFICATE-BASED AUTHENTICATION:                                   │
│  ├── No PSK to capture or crack                                    │
│  │   Each user has unique certificate                               │
│  │                                                                   │
│  ├── Mutual authentication                                          │
│  │   Server authenticates to client                                 │
│  │   Client authenticates to server                                 │
│  │                                                                   │
│  └── Evil twin protection                                           │
│       Client validates server certificate                           │
│       Rogue AP can't provide valid cert                             │
│                                                                      │
│  IMPLEMENTATION COMPONENTS:                                          │
│  ├── RADIUS server (FreeRADIUS, NPS)                                │
│  ├── PKI infrastructure (CA, client certs)                          │
│  ├── Client supplicant configuration                                │
│  └── AP configuration for 802.1X                                    │
│                                                                      │
│  RECOMMENDED EAP METHODS:                                            │
│  ├── EAP-TLS (certificate on both sides)                            │
│  ├── EAP-TTLS (certificate on server)                               │
│  └── PEAP (protected EAP tunnel)                                    │
│                                                                      │
│  CLIENT CONFIGURATION:                                               │
│  ├── Install CA certificate                                         │
│  ├── Configure server certificate validation                        │
│  ├── Enable "Verify server certificate"                             │
│  └── Specify expected server CN                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Network Segmentation

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NETWORK SEGMENTATION                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SEGMENTATION STRATEGY:                                              │
│  ├── Corporate Network (WPA3-Enterprise)                            │
│  │   Full access to internal resources                              │
│  │   Certificate-based authentication                               │
│  │                                                                   │
│  ├── Guest Network (Isolated)                                       │
│  │   Internet only, no internal access                              │
│  │   Captive portal for acceptance                                  │
│  │   Bandwidth limited                                              │
│  │                                                                   │
│  ├── IoT Network (Isolated)                                         │
│  │   Specific ports/services only                                   │
│  │   No client-to-client communication                              │
│  │                                                                   │
│  └── BYOD Network (Limited)                                         │
│       Limited internal access                                       │
│       NAC for device posture                                        │
│                                                                      │
│  VLAN IMPLEMENTATION:                                                │
│  ├── Each network on separate VLAN                                  │
│  ├── Firewall between VLANs                                         │
│  ├── ACLs restrict cross-VLAN traffic                               │
│  └── Logging at VLAN boundaries                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Monitoring and Response

### Wireless IDS/IPS

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WIDS/WIPS CAPABILITIES                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DETECTION CAPABILITIES:                                             │
│  ├── Rogue AP detection                                             │
│  │   Compare against authorized inventory                           │
│  │   Alert on new/unknown APs                                       │
│  │                                                                   │
│  ├── Deauth flood detection                                         │
│  │   Count deauth frames per source                                 │
│  │   Alert above threshold                                          │
│  │                                                                   │
│  ├── Evil twin identification                                       │
│  │   Same SSID, different BSSID                                     │
│  │   MAC address analysis                                           │
│  │                                                                   │
│  └── Client impersonation detection                                 │
│       MAC spoofing detection                                        │
│       Multiple locations same MAC                                   │
│                                                                      │
│  RESPONSE CAPABILITIES:                                              │
│  ├── Automated containment                                          │
│  │   Deauth rogue AP clients                                        │
│  │   Block rogue at switch port                                     │
│  │                                                                   │
│  ├── Alert generation                                               │
│  │   SIEM integration                                               │
│  │   Email/SMS notification                                         │
│  │                                                                   │
│  └── Forensic capture                                               │
│       Packet capture on detection                                   │
│       Evidence preservation                                         │
│                                                                      │
│  COMMERCIAL SOLUTIONS:                                               │
│  ├── Aruba RFProtect                                                │
│  ├── Cisco CleanAir / Adaptive wIPS                                 │
│  ├── Juniper Sky ATP                                                │
│  └── Fortinet FortiWiFi                                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Incident Response for Wireless Attacks

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WIRELESS INCIDENT RESPONSE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. IDENTIFICATION                                                   │
│  ├── Detect rogue AP or attack in progress                         │
│  ├── Gather initial indicators                                      │
│  └── Classify incident type                                         │
│                                                                      │
│  2. CONTAINMENT                                                      │
│  ├── Locate rogue AP physically                                     │
│  │   Use signal strength triangulation                              │
│  │                                                                   │
│  ├── Block at network level                                         │
│  │   Switch port disable                                            │
│  │   Wired containment                                              │
│  │                                                                   │
│  └── Wireless containment                                           │
│       Targeted deauth of rogue AP clients                           │
│       Increase legitimate AP power                                  │
│                                                                      │
│  3. ERADICATION                                                      │
│  ├── Remove rogue device                                            │
│  ├── Document device details                                        │
│  └── Chain of custody for evidence                                  │
│                                                                      │
│  4. RECOVERY                                                         │
│  ├── Verify no remaining rogue APs                                  │
│  ├── Reset affected user credentials                                │
│  └── Resume normal monitoring                                       │
│                                                                      │
│  5. LESSONS LEARNED                                                  │
│  ├── How was attack detected?                                       │
│  ├── How long was rogue AP active?                                  │
│  ├── What data may have been compromised?                           │
│  └── What controls can prevent recurrence?                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Security Awareness

### Training Topics

```
ESSENTIAL WIRELESS SECURITY TRAINING:

1. Public WiFi Risks
   ├── Man-in-the-middle attacks
   ├── Credential interception
   └── Unencrypted traffic exposure

2. Evil Twin Attacks
   ├── How they work
   ├── How to identify (certificate warnings)
   └── What to do if suspected

3. Captive Portal Phishing
   ├── Fake login pages
   ├── Credential harvesting
   └── Verify URL before entering credentials

4. VPN Usage
   ├── Always use VPN on untrusted networks
   ├── Company VPN requirements
   └── How to verify VPN connection

5. Certificate Warnings
   ├── Never ignore certificate errors
   ├── What certificates mean
   └── Reporting procedures
```

### User Guidelines

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WIRELESS SECURITY GUIDELINES                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DO:                                                                 │
│  ├── Use corporate VPN on any public WiFi                           │
│  ├── Verify certificate when connecting to corporate WiFi           │
│  ├── Report unexpected login prompts on corporate network           │
│  ├── Disable auto-join for non-corporate networks                   │
│  └── Use mobile data instead of unknown WiFi when possible          │
│                                                                      │
│  DON'T:                                                              │
│  ├── Ignore certificate warnings                                    │
│  ├── Enter credentials on unexpected captive portals                │
│  ├── Connect to networks with suspicious names                      │
│  ├── Leave WiFi enabled when not in use                             │
│  └── Trust networks just because they're password-protected         │
│                                                                      │
│  REPORT:                                                             │
│  ├── Unexpected certificate warnings                                │
│  ├── Corporate WiFi asking for credentials via web page             │
│  ├── Sudden disconnections followed by reconnection prompts         │
│  ├── Unknown networks appearing near corporate locations            │
│  └── Any suspicious wireless behavior                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detection Rules

### Sigma Rules for Wireless Attacks

```yaml
# Rogue AP Detection
title: Multiple BSSIDs for Corporate SSID
status: experimental
description: Detects when multiple BSSIDs are observed for corporate SSID
logsource:
    product: wireless_ids
detection:
    selection:
        ssid: "CORPORATE_SSID"
    condition: selection | count(bssid) by ssid > 1
level: high

# Deauth Flood Detection
title: Deauthentication Flood Detected
status: experimental
description: High volume of deauth frames indicates attack
logsource:
    product: wireless_ids
detection:
    selection:
        frame_type: "deauth"
    condition: selection | count() > 100
    timeframe: 60s
level: high
```

### Snort/Suricata Rules

```
# Detect deauthentication flood
alert wifi any any -> any any (msg:"Wireless Deauth Flood Detected"; \
    wifi.type:0; wifi.subtype:12; threshold:type both, track by_src, \
    count 50, seconds 10; sid:1000001; rev:1;)

# Detect probe request flood
alert wifi any any -> any any (msg:"Probe Request Flood Detected"; \
    wifi.type:0; wifi.subtype:4; threshold:type both, track by_src, \
    count 100, seconds 60; sid:1000002; rev:1;)
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│             PP BLUE TEAM COUNTERMEASURES QUICK REFERENCE             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DETECTION:                                                          │
│  ├── Deploy WIDS/WIPS solution                                      │
│  ├── Monitor for rogue APs (multiple BSSID per SSID)                │
│  ├── Alert on deauth floods                                         │
│  ├── Track client connection anomalies                              │
│  └── Integrate with SIEM                                            │
│                                                                      │
│  PREVENTION:                                                         │
│  ├── Implement WPA3 (SAE + PMF)                                     │
│  ├── Deploy 802.1X/EAP-TLS                                          │
│  ├── Segment networks (corp/guest/IoT)                              │
│  ├── Configure client certificate validation                        │
│  └── Disable auto-join on clients                                   │
│                                                                      │
│  RESPONSE:                                                           │
│  ├── Locate rogue AP (triangulation)                                │
│  ├── Contain at switch/wireless level                               │
│  ├── Remove and document device                                     │
│  ├── Reset affected credentials                                     │
│  └── Conduct lessons learned                                        │
│                                                                      │
│  AWARENESS:                                                          │
│  ├── Public WiFi risks                                              │
│  ├── VPN usage requirements                                         │
│  ├── Certificate warning response                                   │
│  └── Reporting procedures                                           │
│                                                                      │
│  KEY TECHNOLOGIES:                                                   │
│  ├── WPA3-Enterprise                                                │
│  ├── 802.1X with EAP-TLS                                            │
│  ├── WIDS/WIPS                                                      │
│  └── Network segmentation                                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Red Team Tactics](../05_Red_Team_Tactics/) | [Back to Pineapple Pager](../README.md)
