# Legal Compliance & Authorization

## Overview

Understanding the legal framework surrounding penetration testing, wireless auditing, and security research is essential. This chapter covers authorization requirements, relevant laws, and compliance considerations.

---

## Authorization Requirements

### Written Authorization Template

```
PENETRATION TESTING AUTHORIZATION

Date: _______________

AUTHORIZING PARTY:
Company Name: _______________________________
Authorized Representative: _______________________________
Title: _______________________________
Contact: _______________________________

TESTING PARTY:
Company/Individual: _______________________________
Lead Tester: _______________________________
Contact: _______________________________

SCOPE OF TESTING:

1. AUTHORIZED ACTIVITIES:
   □ USB/HID device testing (BadUSB)
   □ Wireless network assessment
   □ Social engineering
   □ Physical security testing
   □ Other: _______________________________

2. TARGET SYSTEMS:
   IP Ranges: _______________________________
   Wireless SSIDs: _______________________________
   Physical Locations: _______________________________
   Excluded Systems: _______________________________

3. TESTING PERIOD:
   Start Date/Time: _______________________________
   End Date/Time: _______________________________
   Testing Hours: _______________________________

4. RULES OF ENGAGEMENT:
   □ No denial of service
   □ No data destruction
   □ No exfiltration of real data
   □ Notify before critical system testing
   □ Other restrictions: _______________________________

5. EMERGENCY CONTACTS:
   Primary: _______________________________
   Secondary: _______________________________
   Escalation: _______________________________

SIGNATURES:

_______________________________     _______________
Authorizing Representative          Date

_______________________________     _______________
Testing Lead                        Date
```

### Scope Limitations

```
ALWAYS GET EXPLICIT AUTHORIZATION FOR:
├── Each network/system to be tested
├── Testing methodologies (active vs passive)
├── Credential harvesting activities
├── Physical access attempts
├── Social engineering campaigns
├── Data handling procedures
└── Third-party systems (cloud, vendors)

NEVER ASSUME AUTHORIZATION EXTENDS TO:
├── Systems not explicitly listed
├── Third-party networks
├── Production systems (unless specified)
├── Customer/user data
├── Extended time periods
└── Additional attack vectors
```

---

## Relevant Laws

### United States

#### Computer Fraud and Abuse Act (CFAA)
```
18 U.S.C. § 1030

Key Provisions:
├── Unauthorized access to computers
├── Exceeding authorized access
├── Trafficking in passwords
├── Causing damage through access
├── Accessing to obtain information

Penalties:
├── First offense: Up to 5 years
├── Repeat offense: Up to 10 years
├── Aggravated cases: Up to 20 years
└── Civil liability possible

Relevance to Payloads:
├── BadUSB on unauthorized systems = violation
├── Wireless attacks on non-owned networks = violation
├── Even "harmless" testing without permission = violation
```

#### Wiretap Act (18 U.S.C. § 2511)
```
Prohibits:
├── Interception of communications
├── Use of intercepted communications
├── Disclosure of intercepted communications

Exceptions:
├── Consent of one party
├── Law enforcement with warrant
├── Provider protection

Relevance:
├── WiFi traffic capture = potential violation
├── Captive portal credential capture = potential violation
├── Even on "open" networks without consent
```

#### CAN-SPAM and Related
```
For social engineering tests involving email:
├── CAN-SPAM Act compliance
├── State anti-spam laws
├── Phishing simulation requirements
└── Employee notification requirements
```

### European Union

#### General Data Protection Regulation (GDPR)
```
Key Requirements:
├── Lawful basis for processing
├── Data minimization
├── Purpose limitation
├── Storage limitation
├── Individual rights

Penetration Testing Implications:
├── Document lawful basis (legitimate interest/consent)
├── Minimize personal data collection
├── Secure any collected data
├── Delete data after assessment
├── Report data breaches within 72 hours
```

#### Computer Misuse Laws (by country)
```
UK: Computer Misuse Act 1990
Germany: StGB § 202a-c (Computer Crime)
France: Articles 323-1 to 323-7 Code pénal
Netherlands: Wetboek van Strafrecht Art. 138ab

Common Elements:
├── Unauthorized access prohibited
├── Authorization must be explicit
├── Intent may not be relevant
└── Cross-border issues complex
```

### Other Jurisdictions

```
Australia: Criminal Code Act 1995
Canada: Criminal Code Section 342.1
Japan: Unauthorized Computer Access Law
Singapore: Computer Misuse Act

Key Consideration:
├── Laws vary significantly by jurisdiction
├── Testing across borders complicates legality
├── Consult local legal counsel
└── Document authorization thoroughly
```

---

## Ethical Guidelines

### Professional Standards

#### PTES (Penetration Testing Execution Standard)
```
Core Ethics:
├── Only test with explicit authorization
├── Stay within defined scope
├── Protect client confidentiality
├── Report all findings honestly
├── Do no harm to systems or data
└── Maintain professional competence
```

#### EC-Council Code of Ethics
```
Principles:
├── Protect society and infrastructure
├── Act honorably, honestly, legally
├── Provide diligent and competent service
├── Advance and protect the profession
└── Avoid practices that could harm others
```

### Personal Ethics Checklist

```
Before ANY testing, ask yourself:

□ Do I have explicit written authorization?
□ Am I operating within the defined scope?
□ Could this action cause unintended harm?
□ Am I protecting collected data appropriately?
□ Would I be comfortable explaining this in court?
□ Am I respecting privacy and confidentiality?
□ Is my testing proportionate to the objective?
```

---

## Compliance Frameworks

### PCI DSS
```
Requirement 11.3: Penetration Testing

Requirements:
├── Annual external penetration test
├── Internal testing after significant changes
├── Methodology based on industry standards
├── Testing must include network and application
├── Remediate and retest critical findings

Relevance:
├── Wireless testing for cardholder environments
├── BadUSB testing for physical security
├── Social engineering for security awareness
└── Must document all testing activities
```

### HIPAA
```
Healthcare environments require:
├── Business Associate Agreement (BAA)
├── Protection of PHI during testing
├── Breach notification procedures
├── Additional documentation requirements
└── Potential OCR oversight
```

### SOC 2
```
Security testing considerations:
├── Document testing in control evidence
├── Include in risk assessment
├── Report findings appropriately
├── Remediate per control requirements
└── May require attestation evidence
```

---

## Documentation Requirements

### Testing Records

```
MAINTAIN DOCUMENTATION OF:

1. Authorization:
   ├── Signed authorization letter
   ├── Scope of work document
   ├── Rules of engagement
   └── Contact information

2. Testing Activities:
   ├── Detailed logs with timestamps
   ├── Tools and commands used
   ├── Evidence collected
   └── Findings discovered

3. Data Handling:
   ├── Inventory of collected data
   ├── Encryption methods used
   ├── Access controls implemented
   └── Destruction documentation

4. Communication:
   ├── Status reports
   ├── Incident notifications
   ├── Final report delivery
   └── Remediation follow-up
```

### Evidence Preservation

```bash
# Chain of custody for captured data
CAPTURE_DIR="/secure/evidence/engagement_$(date +%Y%m%d)"
mkdir -p "$CAPTURE_DIR"

# Generate hash before and after
sha256sum capture.pcap > "$CAPTURE_DIR/hashes.txt"

# Document collection
cat > "$CAPTURE_DIR/evidence_log.txt" << EOF
Evidence Collection Log
=======================
Collected By: [Your Name]
Date/Time: $(date)
Source: [Description]
Hash: $(sha256sum capture.pcap | cut -d' ' -f1)
Purpose: [Testing objective]
EOF
```

---

## Quick Legal Reference

```
┌─────────────────────────────────────────────────────────────┐
│                    LEGAL QUICK REFERENCE                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ALWAYS DO:                                                  │
│  ├── Get written authorization                              │
│  ├── Define scope explicitly                                │
│  ├── Document everything                                    │
│  ├── Protect collected data                                 │
│  ├── Stay within boundaries                                 │
│  └── Report findings responsibly                            │
│                                                              │
│  NEVER DO:                                                   │
│  ├── Test without authorization                             │
│  ├── Exceed defined scope                                   │
│  ├── Cause unnecessary damage                               │
│  ├── Retain data beyond necessity                           │
│  ├── Share confidential findings                            │
│  └── Assume "good intentions" protect you                   │
│                                                              │
│  WHEN IN DOUBT:                                              │
│  ├── Ask for clarification                                  │
│  ├── Consult legal counsel                                  │
│  ├── Document your concerns                                 │
│  └── Err on the side of caution                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Resources

### Legal References
- [CFAA Full Text](https://www.law.cornell.edu/uscode/text/18/1030)
- [GDPR Official Text](https://gdpr-info.eu/)
- [PTES Standard](http://www.pentest-standard.org/)

### Professional Organizations
- (ISC)² - International Information System Security Certification Consortium
- ISACA - Information Systems Audit and Control Association
- EC-Council - International Council of E-Commerce Consultants

### Consulting Resources
- Work with qualified legal counsel for specific situations
- Engage with professional liability insurance providers
- Consider industry-specific regulatory requirements

---

[← Defensive Signatures](../10_Defensive_Signatures/) | [Back to Technical Addendum](../README.md) | [Back to Main](../../README.md)
