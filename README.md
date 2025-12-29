# The DuckyScript & Bash Security Training Repository

```
████████▄  ▄██   ▄   ▄████████    ▄█   ▄█▄ ▄██   ▄      ▄████████  ▄████████    ▄████████  ▄█     ▄███████▄     ███
███   ▀███ ███   ██▄ ███    ███   ███ ▄███▀ ███   ██▄   ███    ███ ███    ███   ███    ███ ███    ███    ███ ▀█████████▄
███    ███ ███▄▄▄███ ███    █▀    ███▐██▀   ███▄▄▄███   ███    █▀  ███    █▀    ███    ███ ███▌   ███    ███    ▀███▀▀██
███    ███ ▀▀▀▀▀▀███ ███         ▄█████▀    ▀▀▀▀▀▀███   ███        ███         ▄███▄▄▄▄██▀ ███▌   ███    ███     ███   ▀
███    ███ ▄██   ███ ███        ▀▀█████▄    ▄██   ███ ▀███████████ ███        ▀▀███▀▀▀▀▀   ███▌ ▀█████████▀      ███
███    ███ ███   ███ ███    █▄    ███▐██▄   ███   ███          ███ ███    █▄  ▀███████████ ███    ███            ███
███   ▄███ ███   ███ ███    ███   ███ ▀███▄ ███   ███    ▄█    ███ ███    ███   ███    ███ ███    ███            ███
████████▀   ▀█████▀  ████████▀    ███   ▀█▀  ▀█████▀   ▄████████▀  ████████▀    ███    ███ █▀    ▄████▀         ▄████▀
```

## Complete Security Training: From Beginner to Expert

> **For authorized security testing and education only. Always obtain proper written authorization before testing.**

---

## Quick Navigation

| Section | Description | Skill Level |
|---------|-------------|-------------|
| [Learning Path](#learning-path) | Your journey from beginner to expert | All Levels |
| [Chapter 1: Flipper Zero](#chapter-1-flipper-zero-badusb) | BadUSB fundamentals and payloads | Beginner → Expert |
| [Chapter 2: WiFi Pineapple](#chapter-2-wifi-pineapple-pager) | Wireless attack platform | Beginner → Expert |
| [Chapter 3: Technical Reference](#chapter-3-technical-addendum) | Protocols, hardware, tools | Intermediate → Expert |
| [Chapter 4: Security Operations](#chapter-4-security-operations) | Red Team & Blue Team training | Intermediate → Expert |
| [Chapter 5: Skill Levels](#chapter-5-skill-level-training) | Hands-on practice by level | All Levels |
| [Payloads Library](#payloads-library) | Ready-to-use payload collection | All Levels |

---

## Learning Path

### How to Use This Repository

This repository is designed as a **progressive learning system**. Follow the path below based on your current skill level:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         YOUR LEARNING JOURNEY                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐    │
│   │   BASIC     │──▶│INTERMEDIATE │──▶│  ADVANCED   │──▶│   EXPERT    │    │
│   │  (Week 1-2) │   │  (Week 3-4) │   │  (Week 5-6) │   │  (Week 7+)  │    │
│   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘    │
│         │                 │                 │                 │             │
│         ▼                 ▼                 ▼                 ▼             │
│   • Hello World     • System Recon    • AMSI Bypass     • Custom C2        │
│   • Basic Keys      • Persistence     • UAC Bypass      • Full Chains      │
│   • Simple Delays   • WiFi Extract    • Reverse Shells  • Evasion Dev      │
│   • First Payload   • Network Scan    • Anti-Forensics  • Tool Creation    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Beginner Start Here

### Prerequisites
Before you begin, you should have:
- [ ] Basic understanding of command line (Windows CMD or Linux terminal)
- [ ] A Flipper Zero device OR WiFi Pineapple Pager (or virtual lab)
- [ ] Text editor for writing scripts
- [ ] Test environment (VM recommended)

### Week 1-2: Basic Level

**Goal:** Understand what DuckyScript and Bash are, write your first payloads

| Day | Topic | Link | Practice |
|-----|-------|------|----------|
| 1 | What is BadUSB? | [Chapter 1.1](Chapter_01_Flipper_Zero_BadUSB/01_Fundamentals/) | Read & understand |
| 2 | DuckyScript basics | [Basic Ducky](Chapter_05_Skill_Levels/01_Basic/Ducky/) | Hello World |
| 3 | Bash scripting intro | [Basic Bash](Chapter_05_Skill_Levels/01_Basic/Bash/) | First script |
| 4 | Your first payload | [FZ-B01](Chapter_01_Flipper_Zero_BadUSB/02_Basic_Scripts/FZ-B01_Hello_World.md) | Copy & test |
| 5 | System commands | [FZ-B04](Chapter_01_Flipper_Zero_BadUSB/02_Basic_Scripts/FZ-B04_System_Info.md) | Modify & test |
| 6-7 | Basic challenges | [Challenges](Chapter_05_Skill_Levels/01_Basic/Challenges/) | Complete all |

**Checkpoint:** Can you write a payload that opens Notepad and types your name?

---

### Week 3-4: Intermediate Level

**Goal:** Extract information, establish basic persistence, understand detection

| Day | Topic | Link | Practice |
|-----|-------|------|----------|
| 8 | WiFi extraction | [FZ-I02](Chapter_01_Flipper_Zero_BadUSB/03_Intermediate_Scripts/FZ-I02_WiFi_Password_Extractor.md) | Test in lab |
| 9 | Network recon | [FZ-I03](Chapter_01_Flipper_Zero_BadUSB/03_Intermediate_Scripts/FZ-I03_Network_Reconnaissance.md) | Document findings |
| 10 | Persistence basics | [FZ-I08](Chapter_01_Flipper_Zero_BadUSB/03_Intermediate_Scripts/FZ-I08_Scheduled_Task_Persistence.md) | Understand mechanisms |
| 11 | WiFi Pineapple intro | [PP Fundamentals](Chapter_02_WiFi_Pineapple_Pager/01_Fundamentals/) | Setup device |
| 12 | Detection basics | [Blue Team](Chapter_04_Security_Operations/01_Blue_Team_Fundamentals/) | Learn to detect |
| 13-14 | Intermediate challenges | [Challenges](Chapter_05_Skill_Levels/02_Intermediate/Challenges/) | Complete all |

**Checkpoint:** Can you extract WiFi passwords AND detect if someone did this to your system?

---

### Week 5-6: Advanced Level

**Goal:** Bypass security controls, understand evasion, implement countermeasures

| Day | Topic | Link | Practice |
|-----|-------|------|----------|
| 15 | AMSI bypass | [FZ-A03](Chapter_01_Flipper_Zero_BadUSB/04_Advanced_Scripts/FZ-A03_AMSI_Bypass.md) | Understand why |
| 16 | UAC bypass | [FZ-A04](Chapter_01_Flipper_Zero_BadUSB/04_Advanced_Scripts/FZ-A04_UAC_Bypass.md) | Test & detect |
| 17 | Reverse shells | [FZ-A02](Chapter_01_Flipper_Zero_BadUSB/04_Advanced_Scripts/FZ-A02_Reverse_Shell.md) | Lab only! |
| 18 | EDR evasion | [EDR Guide](Chapter_04_Security_Operations/03_EDR/) | Both sides |
| 19 | Evil Twin attacks | [PP-A01](Chapter_02_WiFi_Pineapple_Pager/04_Advanced_Payloads/) | Authorized only |
| 20-21 | Advanced challenges | [Challenges](Chapter_05_Skill_Levels/03_Advanced/Challenges/) | Complete all |

**Checkpoint:** Can you bypass AMSI AND write a detection rule for your bypass?

---

### Week 7+: Expert Level

**Goal:** Create complete attack chains, develop custom tools, lead security assessments

| Topic | Link | Mastery Goal |
|-------|------|--------------|
| Complete attack chains | [FZ-A09](Chapter_01_Flipper_Zero_BadUSB/04_Advanced_Scripts/FZ-A09_Complete_Attack_Chain.md) | Understand full lifecycle |
| Anti-forensics | [FZ-A10](Chapter_01_Flipper_Zero_BadUSB/04_Advanced_Scripts/FZ-A10_Anti_Forensics.md) | Know what to look for |
| Persistence framework | [FZ-E01](Chapter_01_Flipper_Zero_BadUSB/05_Expert_Scripts/) | Multiple mechanisms |
| Botnet understanding | [Botnet Guide](Chapter_04_Security_Operations/05_Botnet_Understanding/) | C2 operations |
| Incident response | [IR Guide](Chapter_04_Security_Operations/07_Incident_Response/) | Lead IR efforts |
| Expert challenges | [Challenges](Chapter_05_Skill_Levels/04_Expert/Challenges/) | Create your own |

**Checkpoint:** Can you design a full red team engagement AND the blue team response?

---

## Repository Structure

```
Ducky_Bash/
├── README.md                              # You are here - Learning guide
├── Payloads/                              # Ready-to-use payload files
│   ├── Flipper_Zero/
│   │   ├── Basic/                         # Beginner payloads
│   │   ├── Intermediate/                  # Growing complexity
│   │   ├── Advanced/                      # Security bypasses
│   │   └── Expert/                        # Full attack chains
│   └── WiFi_Pineapple/
│       ├── Basic/                         # Simple alerts & scans
│       ├── Intermediate/                  # Logging & tracking
│       ├── Advanced/                      # Evil twin, captive portal
│       └── Expert/                        # Full spectrum audits
│
├── Chapter_01_Flipper_Zero_BadUSB/        # VOLUME 1
│   ├── 01_Fundamentals/                   # Core concepts
│   ├── 02_Basic_Scripts/                  # FZ-B01 through FZ-B15
│   ├── 03_Intermediate_Scripts/           # FZ-I01 through FZ-I15
│   ├── 04_Advanced_Scripts/               # FZ-A01 through FZ-A10
│   ├── 05_Expert_Scripts/                 # FZ-E01 through FZ-E05
│   ├── 06_Deployment_Strategies/          # Physical access tactics
│   ├── 07_Development_Creation/           # Building payloads
│   ├── 08_Red_Team_Tactics/               # Offensive operations
│   └── 09_Blue_Team_Countermeasures/      # Detection & prevention
│
├── Chapter_02_WiFi_Pineapple_Pager/       # VOLUME 2
│   ├── 01_Fundamentals/                   # Device overview
│   ├── 02_Basic_Payloads/                 # PP-B01 through PP-B10
│   ├── 03_Intermediate_Payloads/          # PP-I01 through PP-I10
│   ├── 04_Advanced_Payloads/              # PP-A01 through PP-A05
│   ├── 05_Red_Team_Tactics/               # Wireless attacks
│   └── 06_Blue_Team_Countermeasures/      # Rogue AP detection
│
├── Chapter_03_Technical_Addendum/         # VOLUME 3
│   ├── 01_Hardware_Deep_Dive/             # Device specifications
│   ├── 02_Firmware_Ecosystem/             # Custom firmware
│   ├── 03_Protocol_Reference/             # 802.11, WPA, EAPOL
│   ├── 04_USB_VID_PID_Database/           # Device identification
│   ├── 05_Keyboard_Layouts/               # International support
│   ├── 06_MITRE_ATT_CK_Mapping/           # Framework alignment
│   ├── 07_Cracking_Reference/             # Hashcat, aircrack-ng
│   ├── 08_Lab_Environment/                # Setup guide
│   ├── 09_Tool_Integration/               # Metasploit, Cobalt Strike
│   ├── 10_Defensive_Signatures/           # Detection rules
│   └── 11_Legal_Compliance/               # Authorization templates
│
├── Chapter_04_Security_Operations/        # VOLUME 4
│   ├── 01_Blue_Team_Fundamentals/         # Defense in depth
│   ├── 02_Security_Monitoring_SIEM/       # Log analysis
│   ├── 03_EDR/                            # Endpoint detection
│   ├── 04_Network_Monitoring_IDS_IPS/     # Traffic analysis
│   ├── 05_Botnet_Understanding/           # C2 operations
│   ├── 06_Security_Hardening/             # System lockdown
│   ├── 07_Incident_Response/              # IR procedures
│   └── 08_Threat_Intelligence/            # IOCs and hunting
│
└── Chapter_05_Skill_Levels/               # HANDS-ON TRAINING
    ├── 01_Basic/
    │   ├── Ducky/                         # DuckyScript lessons
    │   ├── Bash/                          # Bash scripting lessons
    │   ├── Challenges/                    # Test your skills
    │   └── Practice/                      # Guided exercises
    ├── 02_Intermediate/
    │   ├── Ducky/
    │   ├── Bash/
    │   ├── Challenges/
    │   └── Practice/
    ├── 03_Advanced/
    │   ├── Ducky/
    │   ├── Bash/
    │   ├── Challenges/
    │   └── Practice/
    └── 04_Expert/
        ├── Ducky/
        ├── Bash/
        ├── Challenges/
        └── Practice/
```

---

## Chapter 1: Flipper Zero BadUSB

The Flipper Zero is a portable multi-tool for pentesters and geeks. Its BadUSB functionality allows it to emulate a USB keyboard and execute pre-written scripts.

### What You'll Learn
- DuckyScript syntax and commands
- Payload development workflow
- Evasion techniques
- Detection and prevention

### Sub-Chapters

| Section | Description | Files |
|---------|-------------|-------|
| [01_Fundamentals](Chapter_01_Flipper_Zero_BadUSB/01_Fundamentals/) | Core concepts, command reference | Introduction, Commands |
| [02_Basic_Scripts](Chapter_01_Flipper_Zero_BadUSB/02_Basic_Scripts/) | Hello World to WiFi display | FZ-B01 → FZ-B15 |
| [03_Intermediate_Scripts](Chapter_01_Flipper_Zero_BadUSB/03_Intermediate_Scripts/) | Recon, extraction, persistence | FZ-I01 → FZ-I15 |
| [04_Advanced_Scripts](Chapter_01_Flipper_Zero_BadUSB/04_Advanced_Scripts/) | Bypasses, shells, attack chains | FZ-A01 → FZ-A10 |
| [05_Expert_Scripts](Chapter_01_Flipper_Zero_BadUSB/05_Expert_Scripts/) | Full frameworks, engagement payloads | FZ-E01 → FZ-E05 |
| [08_Red_Team_Tactics](Chapter_01_Flipper_Zero_BadUSB/08_Red_Team_Tactics/) | Offensive operations guide | MITRE mapping |
| [09_Blue_Team_Countermeasures](Chapter_01_Flipper_Zero_BadUSB/09_Blue_Team_Countermeasures/) | Detection and prevention | Sigma rules, scripts |

---

## Chapter 2: WiFi Pineapple Pager

The WiFi Pineapple Pager is a compact wireless auditing platform for capturing handshakes, deploying rogue APs, and monitoring wireless networks.

### What You'll Learn
- Bash scripting for wireless attacks
- Handshake capture and cracking
- Evil twin deployments
- Wireless IDS/IPS

### Sub-Chapters

| Section | Description | Files |
|---------|-------------|-------|
| [01_Fundamentals](Chapter_02_WiFi_Pineapple_Pager/01_Fundamentals/) | Device overview, payload system | Introduction |
| [02_Basic_Payloads](Chapter_02_WiFi_Pineapple_Pager/02_Basic_Payloads/) | Alerts, scans, status checks | PP-B01 → PP-B10 |
| [03_Intermediate_Payloads](Chapter_02_WiFi_Pineapple_Pager/03_Intermediate_Payloads/) | Logging, tracking, recon | PP-I01 → PP-I10 |
| [04_Advanced_Payloads](Chapter_02_WiFi_Pineapple_Pager/04_Advanced_Payloads/) | Evil twin, PMKID, full audits | PP-A01 → PP-A05 |
| [05_Red_Team_Tactics](Chapter_02_WiFi_Pineapple_Pager/05_Red_Team_Tactics/) | Wireless attack operations | Deployment guide |
| [06_Blue_Team_Countermeasures](Chapter_02_WiFi_Pineapple_Pager/06_Blue_Team_Countermeasures/) | Rogue AP detection | WIDS setup |

---

## Chapter 3: Technical Addendum

Deep technical reference for hardware, protocols, and tool integration.

### What You'll Learn
- Hardware specifications and internals
- Protocol details (802.11, WPA, EAPOL)
- Tool integration (Metasploit, Cobalt Strike)
- Detection signatures

---

## Chapter 4: Security Operations

Complete Red Team and Blue Team training for security professionals.

### What You'll Learn
- SOC operations and SIEM
- EDR and its evasion
- Network monitoring
- Incident response
- Threat intelligence

---

## Chapter 5: Skill Level Training

Hands-on learning with side-by-side DuckyScript and Bash comparisons.

### Structure Per Level

Each skill level contains:
- **Ducky/** - DuckyScript-specific lessons
- **Bash/** - Bash scripting lessons
- **Challenges/** - Test your knowledge
- **Practice/** - Guided hands-on exercises

### Side-by-Side Learning

Every concept is taught in both languages:

```
┌──────────────────────────────┬──────────────────────────────┐
│        DUCKYSCRIPT           │            BASH              │
├──────────────────────────────┼──────────────────────────────┤
│ REM This is a comment        │ # This is a comment          │
│ DELAY 1000                   │ sleep 1                      │
│ STRING Hello World           │ echo "Hello World"           │
│ ENTER                        │ # (implicit in script)       │
│ GUI r                        │ xdotool key super+r          │
└──────────────────────────────┴──────────────────────────────┘
```

---

## Payloads Library

Ready-to-use payloads organized by device and skill level.

### Flipper Zero Payloads

| Level | Count | Description |
|-------|-------|-------------|
| Basic | 15 | Hello World, system info, pranks |
| Intermediate | 15 | Recon, extraction, persistence |
| Advanced | 10 | Bypasses, shells, attack chains |
| Expert | 5 | Full engagement frameworks |

### WiFi Pineapple Payloads

| Level | Count | Description |
|-------|-------|-------------|
| Basic | 10 | Alerts, scans, status |
| Intermediate | 10 | Logging, tracking, probes |
| Advanced | 5 | Evil twin, PMKID, audits |
| Expert | 5 | Full spectrum operations |

---

## How Each Lesson is Structured

Every payload/technique lesson follows this format:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ LESSON STRUCTURE                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ 1. OVERVIEW                                                                  │
│    • What this payload/technique does                                        │
│    • Difficulty level and prerequisites                                      │
│    • MITRE ATT&CK mapping                                                    │
│                                                                              │
│ 2. THE CODE                                                                  │
│    • Complete, commented payload                                             │
│    • Line-by-line explanation                                                │
│                                                                              │
│ 3. HOW IT WORKS                                                              │
│    • Technical deep-dive                                                     │
│    • Why each component is necessary                                         │
│    • Common variations                                                       │
│                                                                              │
│ 4. RED TEAM PERSPECTIVE                                                      │
│    • How attackers use this                                                  │
│    • Evasion techniques                                                      │
│    • Real-world scenarios                                                    │
│                                                                              │
│ 5. BLUE TEAM PERSPECTIVE                                                     │
│    • How to detect this                                                      │
│    • Prevention measures                                                     │
│    • Detection scripts/rules                                                 │
│                                                                              │
│ 6. PRACTICE EXERCISES                                                        │
│    • Modify the payload                                                      │
│    • Write detection rules                                                   │
│    • Challenge questions                                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Contributing

Want to add payloads or improve documentation?

1. Fork the repository
2. Create a feature branch
3. Follow the lesson structure above
4. Include both Red Team and Blue Team perspectives
5. Submit a pull request

---

## Legal Disclaimer

This repository is for **authorized security testing and educational purposes only**.

- Always obtain written authorization before testing
- Never use these techniques against systems you don't own or have permission to test
- Understand and comply with local laws and regulations
- The authors are not responsible for misuse

---

## Resources

- [Flipper Zero Documentation](https://docs.flipper.net/)
- [Hak5 Documentation](https://docs.hak5.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | December 2025 | Initial release with complete training structure |

---

**Happy Learning! Start with [Basic Level](Chapter_05_Skill_Levels/01_Basic/) if you're new.**
