# Contributing to BadUSB Training Repository

Thank you for your interest in contributing! This document provides guidelines for contributions.

## Code of Conduct

- Be respectful and professional
- Focus on educational and defensive uses
- Never share payloads designed for malicious use
- Ensure all contributions support authorized testing only

## Types of Contributions

### Accepted Contributions

- New educational payloads with clear documentation
- Detection rules and defensive scripts
- Documentation improvements
- Bug fixes
- Lab environment enhancements
- Case studies (fictional/anonymized)
- Assessment questions
- Translations

### Not Accepted

- Payloads targeting specific organizations
- Zero-day exploits
- Malware or ransomware
- Detection evasion techniques for malicious use
- Content promoting unauthorized access

## How to Contribute

### 1. Fork the Repository

```bash
git clone https://github.com/yourusername/badusb-training.git
cd badusb-training
```

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 3. Make Changes

Follow the style guidelines below.

### 4. Test Your Changes

- Verify payloads work as expected
- Test in isolated lab environment
- Ensure documentation is accurate

### 5. Submit Pull Request

- Provide clear description
- Reference any related issues
- Include testing notes

## Style Guidelines

### Payload Files

```
REM ========================================
REM Payload Name: [Descriptive Name]
REM Author: [Your Name/Handle]
REM Target OS: [Windows/Linux/macOS]
REM Description: [Brief description]
REM MITRE ATT&CK: [T1xxx, T1yyy]
REM ========================================
REM For authorized security testing only
REM ========================================

[Payload content]
```

### Documentation

- Use Markdown format
- Include table of contents for long documents
- Add code examples where applicable
- Include links back to main README

### Code (Python/Bash)

- Include docstrings/comments
- Follow PEP8 for Python
- Use shellcheck for Bash
- Add usage examples

## Directory Structure

```
Ducky_Bash/
├── Chapter_XX_Name/
│   ├── Section_Name/
│   │   ├── payload.txt
│   │   └── README.md
│   └── README.md
├── Tools/
│   └── Tool_Name/
│       ├── tool.py
│       └── README.md
└── Documentation/
```

## Payload Contribution Checklist

- [ ] Payload is educational/defensive in nature
- [ ] Clear documentation provided
- [ ] Target OS specified
- [ ] MITRE ATT&CK mapping included
- [ ] Tested in isolated environment
- [ ] No hardcoded malicious IPs/domains
- [ ] Detection guidance included (for attack payloads)

## Documentation Contribution Checklist

- [ ] Markdown formatting correct
- [ ] Links tested and working
- [ ] Code examples syntax-highlighted
- [ ] Images/diagrams included where helpful
- [ ] Proofread for typos

## Detection Rule Contributions

### Sigma Rules

```yaml
title: Rule Title
status: experimental|test|stable
description: What this rule detects
author: Your Name
date: YYYY/MM/DD
references:
    - https://reference.url
logsource:
    product: windows|linux
    service: sysmon|security|powershell
detection:
    selection:
        # Selection criteria
    condition: selection
falsepositives:
    - Known false positive
level: low|medium|high|critical
tags:
    - attack.txxxx
```

### YARA Rules

```yara
rule Rule_Name {
    meta:
        author = "Your Name"
        description = "What this detects"
        reference = "URL"
        date = "YYYY-MM-DD"

    strings:
        $string1 = "pattern"
        $string2 = { hex pattern }

    condition:
        all of them
}
```

## Issue Reporting

### Bug Reports

Include:
- Description of the issue
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternatives considered
- Willingness to contribute

## Questions?

Open an issue with the "question" label for any clarification needed.

---

Thank you for contributing to security education!
