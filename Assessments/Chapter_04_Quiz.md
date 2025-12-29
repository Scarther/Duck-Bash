# Chapter 04: Security Operations - Assessment Quiz

## Instructions
- Choose the best answer for each question
- Answers are provided at the end
- Passing score: 70% (14/20 correct)

---

## Section A: Blue Team Fundamentals (5 questions)

### Q1. What is the primary purpose of a SIEM?
- A) Block malware automatically
- B) Collect, correlate, and analyze security logs
- C) Encrypt network traffic
- D) Manage user passwords

### Q2. Which Windows feature allows advanced process monitoring including command lines?
- A) Event Viewer
- B) Sysmon (System Monitor)
- C) Task Manager
- D) Performance Monitor

### Q3. What is "defense in depth"?
- A) Using the most expensive security tool
- B) Multiple layers of security controls
- C) Deep packet inspection only
- D) Annual security audits

### Q4. Which log source is MOST valuable for detecting PowerShell attacks?
- A) Application logs
- B) PowerShell Script Block Logging
- C) System logs
- D) Setup logs

### Q5. What does EDR stand for?
- A) Event Detection and Response
- B) Endpoint Detection and Response
- C) Enterprise Data Recovery
- D) External Device Restriction

---

## Section B: Detection Engineering (5 questions)

### Q6. What is a Sigma rule?
- A) A firewall configuration format
- B) A generic signature format for SIEM detection rules
- C) An encryption standard
- D) A penetration testing framework

### Q7. Which Sysmon Event ID indicates a network connection?
- A) Event ID 1
- B) Event ID 3
- C) Event ID 7
- D) Event ID 11

### Q8. What type of detection identifies anomalies from baseline behavior?
- A) Signature-based detection
- B) Behavioral/anomaly detection
- C) Heuristic detection
- D) Rule-based detection

### Q9. What is a YARA rule used for?
- A) Network traffic analysis
- B) Pattern matching in files and memory
- C) User authentication
- D) Log aggregation

### Q10. Which Windows Event ID indicates a new process was created?
- A) 4624
- B) 4688
- C) 4720
- D) 7045

---

## Section C: Incident Response (5 questions)

### Q11. What is the first phase of the NIST Incident Response lifecycle?
- A) Detection and Analysis
- B) Preparation
- C) Containment
- D) Recovery

### Q12. What is "volatile evidence" in digital forensics?
- A) Evidence that can be easily modified
- B) Evidence that is lost when power is removed (RAM, running processes)
- C) Encrypted evidence
- D) Cloud-based evidence

### Q13. What is the primary goal of the "Containment" phase?
- A) Identify the attacker
- B) Prevent further damage while maintaining evidence
- C) Restore normal operations
- D) Document the incident

### Q14. What tool is used for memory forensics?
- A) Wireshark
- B) Volatility
- C) Nmap
- D) Burp Suite

### Q15. What is an IOC (Indicator of Compromise)?
- A) A security policy
- B) Forensic artifacts that indicate a security breach
- C) A compliance requirement
- D) A firewall rule

---

## Section D: Threat Intelligence (5 questions)

### Q16. What is STIX in threat intelligence?
- A) A malware family
- B) A structured format for sharing threat information
- C) A SIEM product
- D) A penetration testing tool

### Q17. What is a TTP in the context of threat intelligence?
- A) Threat Transfer Protocol
- B) Tactics, Techniques, and Procedures
- C) Trusted Third Party
- D) Time To Patch

### Q18. What does the MITRE ATT&CK framework provide?
- A) Antivirus signatures
- B) A knowledge base of adversary tactics and techniques
- C) Firewall configurations
- D) Password policies

### Q19. What is threat hunting?
- A) Waiting for alerts to fire
- B) Proactively searching for threats that evade existing controls
- C) Penetration testing
- D) Vulnerability scanning

### Q20. What is the purpose of a threat intelligence feed?
- A) To provide real-time stock prices
- B) To share known IOCs and threat data
- C) To encrypt network traffic
- D) To manage user access

---

## Answer Key

<details>
<summary>Click to reveal answers</summary>

| Question | Answer | Explanation |
|----------|--------|-------------|
| Q1 | B | SIEM aggregates and analyzes security logs |
| Q2 | B | Sysmon provides detailed process monitoring |
| Q3 | B | Defense in depth uses multiple security layers |
| Q4 | B | Script Block Logging captures PowerShell script content |
| Q5 | B | EDR = Endpoint Detection and Response |
| Q6 | B | Sigma is a generic SIEM detection rule format |
| Q7 | B | Sysmon Event ID 3 is Network Connection |
| Q8 | B | Behavioral detection finds anomalies from normal |
| Q9 | B | YARA matches patterns in files/memory |
| Q10 | B | Event ID 4688 is Process Creation |
| Q11 | B | Preparation is the first NIST IR phase |
| Q12 | B | Volatile evidence is lost when power is removed |
| Q13 | B | Containment prevents further damage |
| Q14 | B | Volatility is used for memory forensics |
| Q15 | B | IOCs are artifacts indicating a breach |
| Q16 | B | STIX is a threat sharing format |
| Q17 | B | TTP = Tactics, Techniques, and Procedures |
| Q18 | B | ATT&CK catalogs adversary behaviors |
| Q19 | B | Threat hunting is proactive threat searching |
| Q20 | B | Threat feeds share IOCs and threat data |

**Passing Score: 14/20 (70%)**

</details>

---

## Scoring

- **18-20 correct**: Expert level - Ready for SOC/IR roles
- **14-17 correct**: Proficient - Good defensive security knowledge
- **10-13 correct**: Developing - Review security operations material
- **Below 10**: Needs improvement - Re-study Chapter 04 material

---

[← Chapter 03 Quiz](./Chapter_03_Quiz.md) | [Back to Assessments](./README.md)
