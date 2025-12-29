# Expert Level Challenges

## Overview

These challenges test your ability to detect, investigate, and respond to cryptocurrency mining infections.

---

## Challenge 01: Detect the Hidden Miner

### Scenario
Your SOC received reports of slow systems from multiple users. Initial antivirus scans came back clean. Your task is to investigate and determine if cryptocurrency mining is occurring.

### Objectives
1. Identify any mining processes
2. Locate miner configuration files
3. Document the mining pool being used
4. Identify persistence mechanisms
5. Determine the infection vector

### Hints
- Miners often rename themselves to blend in
- Check CPU usage patterns over time
- Look for network connections on unusual ports
- Check WMI, scheduled tasks, and registry

### Success Criteria
- [ ] Mining process identified with PID
- [ ] Pool address extracted from config
- [ ] Persistence mechanism documented
- [ ] Infection vector hypothesis formed

---

## Challenge 02: Trace the Infection Vector

### Scenario
A confirmed miner infection was found on a workstation. Your task is to determine how the miner got onto the system.

### Evidence Provided
- Windows Security Event Logs (4624, 4688)
- Sysmon logs
- USB device connection history
- PowerShell transcription logs

### Objectives
1. Build a timeline of events
2. Identify the initial access method
3. Document the attack chain
4. Identify any IOCs for detection rules

### Success Criteria
- [ ] Timeline created with all significant events
- [ ] Initial access method confirmed
- [ ] Attack chain fully documented
- [ ] IOCs extracted for future detection

---

## Challenge 03: Full Incident Response

### Scenario
Multiple systems are infected with cryptocurrency miners. You are the incident responder. Conduct a full IR process.

### Phase 1: Detection & Identification
- Identify all affected systems
- Document all IOCs
- Assess scope of infection

### Phase 2: Containment
- Isolate affected systems
- Block mining pool connections
- Prevent lateral movement

### Phase 3: Eradication
- Remove all miner components
- Clean persistence mechanisms
- Verify removal

### Phase 4: Recovery
- Return systems to production
- Implement enhanced monitoring
- Update detection rules

### Phase 5: Lessons Learned
- Document incident
- Identify prevention improvements
- Update procedures

### Success Criteria
- [ ] All affected systems identified
- [ ] Complete IOC list created
- [ ] All miners removed
- [ ] Incident report completed
- [ ] Detection rule improvements proposed

---

## Lab Setup

For these challenges, set up a controlled lab environment:

1. Create VM(s) for testing
2. Deploy sample miners (in isolated network only)
3. Configure logging (Sysmon, PowerShell)
4. Disconnect from internet/isolate network

See [Practice/Lab_Setup_Mining_Detection.md](../Practice/Lab_Setup_Mining_Detection.md) for detailed setup instructions.

---

[← Expert Level](../README.md)
