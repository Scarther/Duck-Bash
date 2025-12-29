# Expert Level Challenges

## Overview

Expert-level challenges require combining multiple skills, creative problem-solving, and comprehensive understanding of both offensive and defensive techniques.

---

## Challenge E-01: Full Red Team Operation

### Scenario
You have been contracted for a Red Team engagement. Your objective is to:
1. Gain initial access via BadUSB
2. Establish persistent access
3. Escalate privileges
4. Move laterally to one other system
5. Exfiltrate a specific "crown jewel" file
6. Avoid detection for 48 hours

### Constraints
- No internet-connected C2 (air-gapped simulation)
- Must use only built-in Windows tools (LOLBAS)
- Payload must execute in under 30 seconds
- Must not trigger Windows Defender

### Deliverables
1. Complete DuckyScript payload
2. Documentation of each phase
3. MITRE ATT&CK mapping
4. Recommended detection rules

### Evaluation Criteria
- Stealth (20%)
- Reliability (20%)
- Completeness (20%)
- Documentation (20%)
- OPSEC (20%)

---

## Challenge E-02: Full Blue Team Response

### Scenario
Your organization has detected suspicious USB activity. Initial IOCs:
- USB device connected at 14:32:15
- PowerShell execution detected at 14:32:18
- Outbound connection to 192.168.1.100:8080 at 14:32:25

### Tasks
1. **Contain** - Isolate affected systems
2. **Investigate** - Determine full scope
3. **Eradicate** - Remove all malware/persistence
4. **Recover** - Restore normal operations
5. **Report** - Document findings and lessons learned

### Required Artifacts
1. Timeline of events
2. Complete IOC list
3. Forensic evidence package
4. Root cause analysis
5. Recommendations for prevention

### Lab Setup
```bash
#!/bin/bash
# Expert Blue Team Challenge Setup
# Run on lab VM to create incident scenario

# Create simulated infection artifacts
mkdir -p /tmp/.hidden_cache
echo "FLAG{expert_blue_challenge}" > /tmp/.hidden_cache/.secret

# Add persistence
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://192.168.1.100/beacon") | crontab -

# Create network activity
while true; do
    curl -s http://192.168.1.100:8080/heartbeat &>/dev/null
    sleep 300
done &

# Leave breadcrumbs in logs
logger "USB device connected: VID=0483 PID=5740"
logger "PowerShell execution: -w hidden -ep bypass"

echo "[+] Scenario deployed. Blue Team: Find everything!"
```

---

## Challenge E-03: Detection Engineering Marathon

### Objective
Create a comprehensive detection suite for BadUSB attacks.

### Requirements

#### Part 1: Sigma Rules (10 rules)
Create detection rules for:
1. USB device with known BadUSB VID/PID
2. Rapid keystroke injection pattern
3. PowerShell with suspicious flags
4. Registry Run key persistence
5. Scheduled task with hidden execution
6. WMI event subscription creation
7. AMSI bypass attempt
8. ETW tampering
9. LSASS access
10. DNS exfiltration

#### Part 2: YARA Rules (5 rules)
Create file/memory signatures for:
1. DuckyScript payload files
2. PowerShell download cradle
3. Encoded commands
4. Credential harvesting scripts
5. C2 beacon behavior

#### Part 3: Network Rules (5 rules)
Create Snort/Suricata rules for:
1. HTTP POST exfiltration
2. DNS tunneling
3. Reverse shell connection
4. Beaconing behavior
5. Large file transfer

#### Part 4: Integration
- Deploy rules to test environment
- Generate test traffic
- Validate detection
- Calculate false positive rate

### Scoring
- Correct detection: 5 points
- False positive avoidance: 3 points
- Documentation: 2 points
- Total: 200 points possible

---

## Challenge E-04: Custom Tool Development

### Objective
Develop a custom BadUSB detection tool.

### Requirements

#### Core Features
1. Real-time USB device monitoring
2. Keystroke timing analysis
3. Process behavior correlation
4. Network activity monitoring
5. Alert generation

#### Technical Specifications
```
Language: Bash/Python (your choice)
Platform: Linux
Dependencies: Minimal (standard tools)
Output: JSON-formatted alerts
Performance: < 5% CPU usage
```

#### Evaluation Script
```bash
#!/bin/bash
# Test harness for custom detection tool

echo "[*] Testing detection tool..."

# Test 1: USB device detection
echo "[Test 1] USB device monitoring"
# Simulate USB event
echo "add@/devices/usb/0483:5740" | tee /dev/null
sleep 2
# Check if tool detected it

# Test 2: Keystroke timing
echo "[Test 2] Rapid keystroke detection"
# Simulate rapid keystrokes
for i in {1..100}; do
    echo "KEY_A" | tee /dev/null
done
sleep 2

# Test 3: Process correlation
echo "[Test 3] Process behavior"
# Simulate suspicious process chain
bash -c 'powershell -c "echo test"' &
sleep 2

# Test 4: Network activity
echo "[Test 4] Network monitoring"
# Simulate C2 connection
curl -s http://localhost:4444 &>/dev/null &
sleep 2

# Check alerts
echo ""
echo "[*] Checking generated alerts..."
cat /var/log/badusb_detector/alerts.json 2>/dev/null
```

---

## Challenge E-05: Purple Team Exercise

### Scenario
Conduct a purple team exercise with both attacking and defending simultaneously.

### Phase 1: Planning (Day 1)
- Red Team: Develop attack plan
- Blue Team: Review current detection capabilities
- Both: Define rules of engagement

### Phase 2: Execution (Day 2-3)
- Red Team: Execute attack in stages
- Blue Team: Detect and respond in real-time
- Coordinator: Document timeline and observations

### Phase 3: Analysis (Day 4)
- Compare Red Team actions vs Blue Team detections
- Identify gaps in detection
- Develop improvements

### Documentation Requirements

#### Red Team Report
```markdown
# Red Team Report

## Executive Summary
[Brief overview of attack success/failure]

## Attack Timeline
| Time | Action | Detected? |
|------|--------|-----------|
| 09:00 | Initial access | No |
| 09:05 | Persistence | Yes |
| ... | ... | ... |

## Techniques Used
[List with MITRE IDs]

## Recommendations
[Detection improvements]
```

#### Blue Team Report
```markdown
# Blue Team Report

## Executive Summary
[Overview of detection success]

## Detection Timeline
| Time | Alert | Action Taken |
|------|-------|--------------|
| 09:05 | Registry modification | Investigated |
| ... | ... | ... |

## Gaps Identified
[What was missed]

## Improvements Made
[Real-time adjustments]

## Recommendations
[Future enhancements]
```

---

## Challenge E-06: Research and Development

### Objective
Research and document a novel BadUSB attack technique or defense mechanism.

### Requirements
1. Literature review of existing techniques
2. Novel contribution or improvement
3. Proof of concept implementation
4. Detection/defense strategy
5. Responsible disclosure considerations

### Deliverables
1. Research paper (5-10 pages)
2. Working proof of concept
3. Detection signatures
4. Presentation slides

### Evaluation Criteria
- Novelty (25%)
- Technical depth (25%)
- Practical applicability (25%)
- Documentation quality (25%)

---

## Scoring and Certification

### Expert Level Completion Requirements

| Challenge | Points | Required |
|-----------|--------|----------|
| E-01 Red Team Op | 100 | Yes |
| E-02 Blue Team Response | 100 | Yes |
| E-03 Detection Engineering | 200 | Yes |
| E-04 Tool Development | 150 | Choose 1 |
| E-05 Purple Team | 150 | Choose 1 |
| E-06 Research | 100 | Choose 1 |

**Minimum for Expert Certification: 550 points**

### Skill Verification
- Peer review of deliverables
- Live demonstration capability
- Written examination (optional)

---

## Resources for Expert Level

### Recommended Reading
- The Art of Intrusion (Mitnick)
- Red Team Field Manual
- Blue Team Field Manual
- MITRE ATT&CK Framework
- SANS Incident Handler's Handbook

### Practice Labs
- Build isolated test network
- Deploy multiple OS targets
- Install logging/SIEM infrastructure
- Practice with various BadUSB devices

### Community Resources
- Security conferences (DEF CON, Black Hat)
- CTF competitions
- Bug bounty programs (for real-world practice)
- Open source security tools

---

[← Back to Skill Levels](../README.md)
