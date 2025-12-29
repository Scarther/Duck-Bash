# BadUSB Case Studies

## Overview

Real-world inspired case studies demonstrating BadUSB attacks, detection, and response. All scenarios are fictional and designed for educational purposes.

## Available Case Studies

| Case Study | Scenario | Key Lessons |
|------------|----------|-------------|
| [Case Study 01](./Case_Study_01_Corporate_Breach.md) | Corporate Network Breach | Detection gaps, incident response |
| [Case Study 02](./Case_Study_02_Red_Team_Engagement.md) | Red Team Physical Engagement | Physical security, user awareness |

## Case Study Structure

Each case study follows a consistent format:

1. **Scenario Overview** - Context and background
2. **Timeline of Events** - Chronological attack progression
3. **Technical Analysis** - Payloads, IOCs, techniques used
4. **Detection Analysis** - What worked, what didn't
5. **Impact Assessment** - Business and technical impact
6. **Lessons Learned** - Recommendations and improvements
7. **Discussion Questions** - For team exercises

## How to Use These Case Studies

### For Training

1. Present the scenario without revealing the outcome
2. Have participants discuss detection strategies
3. Walk through the timeline
4. Discuss lessons learned as a group

### For Tabletop Exercises

1. Use as basis for IR tabletop exercises
2. Modify details for your environment
3. Test response procedures
4. Document improvement opportunities

### For Detection Engineering

1. Extract IOCs and TTPs
2. Create detection rules based on techniques
3. Validate rules in lab environment
4. Deploy to production SIEM

## MITRE ATT&CK Mapping

### Case Study 01: Corporate Breach

| Technique | ID | Phase |
|-----------|-----|-------|
| Replication Through Removable Media | T1091 | Initial Access |
| PowerShell | T1059.001 | Execution |
| Registry Run Keys | T1547.001 | Persistence |
| Credentials from Web Browsers | T1555.003 | Credential Access |
| Exfiltration Over C2 | T1041 | Exfiltration |

### Case Study 02: Red Team Engagement

| Technique | ID | Phase |
|-----------|-----|-------|
| Hardware Additions | T1200 | Initial Access |
| Replication Through Removable Media | T1091 | Initial Access |
| PowerShell | T1059.001 | Execution |
| System Information Discovery | T1082 | Discovery |
| Application Layer Protocol | T1071.001 | C2 |

## Creating Your Own Case Studies

### Template

```markdown
# Case Study XX: [Title]

## Scenario Overview
- Organization type
- Attack type
- Outcome

## Timeline of Events
- Chronological progression
- Key timestamps

## Technical Analysis
- Payloads used
- IOCs identified
- Techniques (MITRE ATT&CK)

## Detection Analysis
- What was detected
- What was missed
- Time to detection

## Impact Assessment
- Data compromised
- Business impact

## Lessons Learned
- Immediate improvements
- Long-term recommendations

## Discussion Questions
- For team exercises
```

## Additional Resources

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [NIST Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/incident-handlers-handbook/)

---

[← Back to Main](../README.md)
