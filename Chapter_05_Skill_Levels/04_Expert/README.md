# Expert Level

## Overview

Expert-level content covers sophisticated attack techniques including cryptocurrency mining deployments, advanced persistence, and complete attack chains. Each payload includes comprehensive Blue Team detection and response guidance.

---

## Important Notice

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ⚠️  LEGAL WARNING  ⚠️                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  The techniques in this section are for EDUCATIONAL PURPOSES and    │
│  AUTHORIZED SECURITY TESTING only.                                  │
│                                                                      │
│  Deploying cryptocurrency miners on systems you don't own or        │
│  have explicit authorization to test is:                            │
│                                                                      │
│  • ILLEGAL in most jurisdictions                                    │
│  • A violation of computer fraud laws (CFAA, etc.)                 │
│  • Potentially prosecutable as theft of resources                   │
│                                                                      │
│  Always obtain written authorization before testing.                │
│  See Chapter_03_Technical_Addendum/11_Legal_Compliance/            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Expert Topics

```
04_Expert/
├── Ducky/
│   ├── EXP-D01_XMRig_Miner_Deploy.md        # Monero miner deployment
│   ├── EXP-D02_Stealth_Miner.md             # Evasive mining
│   ├── EXP-D03_Multi_Coin_Miner.md          # Multiple currencies
│   ├── EXP-D04_Complete_Attack_Chain.md     # Full attack scenario
│   └── EXP-D05_C2_With_Mining.md            # C2 + mining combo
│
├── Bash/
│   ├── EXP-B01_Miner_Detection.sh           # Blue Team: Detect miners
│   ├── EXP-B02_Pool_Blocking.sh             # Block mining pools
│   ├── EXP-B03_CPU_Monitoring.sh            # Resource monitoring
│   ├── EXP-B04_Process_Hunter.sh            # Hunt for hidden miners
│   └── EXP-B05_Incident_Response.sh         # Miner IR toolkit
│
├── Challenges/
│   ├── Challenge_01_Detect_Hidden_Miner.md
│   ├── Challenge_02_Trace_Infection_Vector.md
│   └── Challenge_03_Full_IR_Scenario.md
│
└── Practice/
    ├── Lab_Setup_Mining_Detection.md
    └── Blue_Team_Exercises.md
```

---

## Cryptocurrency Mining Overview

### Why Attackers Deploy Miners

| Motivation | Description |
|------------|-------------|
| Direct Profit | Convert victim's resources to cryptocurrency |
| Passive Income | Long-term revenue from multiple infected systems |
| Lower Risk | Less attention than ransomware |
| Easy Monetization | No need to sell stolen data |

### Common Cryptocurrencies Used

| Currency | Why Popular |
|----------|-------------|
| Monero (XMR) | Privacy-focused, CPU-friendly, anonymous wallets |
| Bitcoin (BTC) | Most valuable but requires GPU/ASIC |
| Ethereum (ETH) | GPU mining, high value |
| Ravencoin (RVN) | GPU-friendly, growing value |

### Attack Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│              CRYPTOMINER ATTACK FLOW                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. INITIAL ACCESS                                                  │
│     └── BadUSB insertion / Phishing / Exploit                      │
│                                                                      │
│  2. PAYLOAD DOWNLOAD                                                │
│     └── Download miner binary from staging server                  │
│                                                                      │
│  3. CONFIGURATION                                                   │
│     ├── Wallet address                                              │
│     ├── Pool address                                                │
│     └── CPU/GPU throttling settings                                │
│                                                                      │
│  4. PERSISTENCE                                                     │
│     ├── Registry Run keys                                           │
│     ├── Scheduled tasks                                             │
│     └── Service installation                                        │
│                                                                      │
│  5. EXECUTION                                                       │
│     ├── Start mining process                                        │
│     ├── Connect to pool                                             │
│     └── Begin solving hashes                                        │
│                                                                      │
│  6. EVASION                                                         │
│     ├── Throttle when user active                                   │
│     ├── Rename process to blend in                                  │
│     └── Hide from task manager                                      │
│                                                                      │
│  7. PROFIT                                                          │
│     └── Cryptocurrency deposited to attacker's wallet              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Blue Team Focus

### Detection Indicators

```
┌─────────────────────────────────────────────────────────────────────┐
│              CRYPTOMINER DETECTION INDICATORS                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SYSTEM BEHAVIOR:                                                   │
│  ├── Sustained high CPU usage (>80%)                               │
│  ├── High GPU usage (if GPU mining)                                │
│  ├── System slowdown and heat                                       │
│  ├── Increased power consumption                                    │
│  └── Fan noise constantly high                                      │
│                                                                      │
│  NETWORK TRAFFIC:                                                   │
│  ├── Connections to known pool domains                             │
│  ├── Stratum protocol (ports 3333, 4444, etc.)                    │
│  ├── Long-lived persistent connections                             │
│  ├── JSON-RPC traffic patterns                                      │
│  └── High upstream data (hash submissions)                         │
│                                                                      │
│  PROCESS INDICATORS:                                                │
│  ├── Process names: xmrig, cpuminer, ccminer                       │
│  ├── High-CPU processes with random names                          │
│  ├── Processes without visible windows                             │
│  ├── Renamed svchost.exe or other system names                     │
│  └── Command lines with pool addresses                             │
│                                                                      │
│  FILE SYSTEM:                                                       │
│  ├── Config files with wallet addresses                            │
│  ├── Binaries in temp/hidden directories                           │
│  ├── JSON config files with pool settings                          │
│  └── Log files with mining statistics                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Detection Rules

```yaml
# Sigma Rule: Cryptocurrency Miner Execution
title: Cryptocurrency Miner Process
id: crypto-miner-001
status: stable
description: Detects common cryptocurrency miner processes
logsource:
    category: process_creation
    product: windows
detection:
    selection_names:
        Image|endswith:
            - '\xmrig.exe'
            - '\xmr-stak.exe'
            - '\cpuminer.exe'
            - '\ccminer.exe'
            - '\ethminer.exe'
            - '\minerd.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'stratum+tcp://'
            - 'stratum+ssl://'
            - 'pool.minexmr'
            - 'nanopool.org'
            - 'supportxmr.com'
            - '--donate-level'
    condition: selection_names or selection_cmdline
level: high
tags:
    - attack.execution
    - attack.t1059
```

### Response Playbook

```
CRYPTOMINER INCIDENT RESPONSE:

1. IDENTIFY (15 min)
   □ Confirm mining activity
   □ Identify affected systems
   □ Determine infection scope

2. CONTAIN (30 min)
   □ Block pool connections at firewall
   □ Isolate heavily infected systems
   □ Kill miner processes

3. ERADICATE (1-2 hours)
   □ Remove miner binaries
   □ Clean persistence mechanisms
   □ Reset compromised credentials
   □ Patch infection vector

4. RECOVER (1 hour)
   □ Verify clean state
   □ Return systems to production
   □ Enhanced monitoring

5. LESSONS (1 week)
   □ Document incident
   □ Update detection rules
   □ Improve prevention controls
```

---

## Contents

| File | Description |
|------|-------------|
| [Ducky/](./Ducky/) | DuckyScript miner deployment payloads |
| [Bash/](./Bash/) | Blue Team detection and response scripts |
| [Challenges/](./Challenges/) | Hands-on security exercises |
| [Practice/](./Practice/) | Lab environment setup |

---

## Learning Objectives

After completing this level, you will be able to:

1. **Understand** cryptocurrency mining attack techniques
2. **Recognize** mining indicators of compromise
3. **Detect** miner activity using various tools
4. **Respond** to mining infections effectively
5. **Prevent** future mining deployments
6. **Hunt** for hidden miners in enterprise environments

---

[← Advanced Level](../03_Advanced/) | [Back to Skill Levels](../README.md) | [Back to Main](../../README.md)
