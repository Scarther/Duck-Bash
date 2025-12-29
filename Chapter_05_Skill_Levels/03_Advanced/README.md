# Advanced Level - Security Training

## Overview

This section contains sophisticated payloads and exercises covering persistence, defense evasion, and comprehensive attack chains used in authorized penetration testing.

---

## Contents

| Directory | Description |
|-----------|-------------|
| [Ducky](Ducky/) | Advanced DuckyScript payloads |
| [Bash](Bash/) | Advanced Bash scripts |
| [Challenges](Challenges/) | Complex security challenges |
| [Practice](Practice/) | Enterprise-like lab environments |

---

## Learning Objectives

After completing the Advanced level, you will be able to:

- Implement persistence mechanisms
- Use defense evasion techniques
- Create multi-stage attack chains
- Perform credential harvesting
- Understand anti-forensics basics
- Map techniques to MITRE ATT&CK framework

---

## Prerequisites

- Completion of Intermediate level
- Strong PowerShell and scripting skills
- Understanding of Windows internals
- Familiarity with MITRE ATT&CK framework
- Enterprise lab environment access

---

## Key Concepts

### Persistence Mechanisms

```powershell
# Registry Run Key
Set-ItemProperty -Path "HKCU:\...\Run" -Name "Update" -Value "payload.exe"

# Scheduled Task
Register-ScheduledTask -TaskName "Update" -Action $action -Trigger $trigger

# WMI Event Subscription
Set-WmiInstance -Class __EventFilter -Arguments @{...}
```

### Defense Evasion

```powershell
# Obfuscation techniques
$a = "po"; $b = "wershell"; & "$a$b" -c "code"

# AMSI considerations (for understanding detection)
# Base64 encoding
# Process hollowing concepts
```

### Credential Access

```powershell
# WiFi passwords
netsh wlan show profile name="SSID" key=clear

# Saved credentials
cmdkey /list

# Browser credential locations (not decryption)
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
```

### Anti-Forensics

```powershell
# Clear history
Remove-Item (Get-PSReadLineOption).HistorySavePath

# Clear MRU
Remove-ItemProperty -Path "HKCU:\...\RunMRU" -Name "*"
```

---

## Attack Chain Examples

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ADVANCED ATTACK CHAINS                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PERSISTENCE CHAIN:                                                  │
│  Initial Access → Execution → Persistence → Cleanup                 │
│                                                                      │
│  CREDENTIAL CHAIN:                                                   │
│  Access → Privilege Check → Credential Dump → Exfiltration          │
│                                                                      │
│  FULL ENGAGEMENT:                                                    │
│  Recon → Access → Persist → Credential → Lateral → Exfil → Clean   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Registry Run Keys | T1547.001 | Persistence via registry |
| Scheduled Task | T1053.005 | Persistence via task scheduler |
| PowerShell | T1059.001 | Execution via PowerShell |
| Obfuscation | T1027 | Defense evasion |
| Credential Dumping | T1003 | Credential access |
| Indicator Removal | T1070 | Anti-forensics |

---

## Safety Reminder

Advanced payloads can cause significant impact. **ALWAYS**:

1. Obtain explicit written authorization
2. Test thoroughly in isolated environments
3. Document all activities
4. Understand legal implications
5. Have rollback procedures ready

---

[← Intermediate Level](../02_Intermediate/) | [Back to Skill Levels](../README.md) | [Next: Expert →](../04_Expert/)
