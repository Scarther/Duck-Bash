# FZ-A10: Ransomware Simulation (Educational)

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A10 |
| **Name** | Ransomware Simulation |
| **Difficulty** | Advanced |
| **Target OS** | Windows 10/11 |
| **Purpose** | DEFENSIVE EDUCATION ONLY |
| **MITRE ATT&CK** | T1486 (Data Encrypted for Impact) |

## ⚠️ CRITICAL WARNING

**This payload is for EDUCATIONAL and DEFENSIVE purposes ONLY.**

This simulation demonstrates ransomware mechanics to:
- Train security teams on detection
- Test backup recovery procedures
- Validate incident response plans
- Educate users on ransomware threats

**NEVER deploy actual ransomware. It is illegal and destructive.**

---

## Educational Objectives

Understanding ransomware helps defenders:
1. Recognize early indicators of compromise
2. Implement effective detection rules
3. Design resilient backup strategies
4. Develop incident response procedures

---

## Simulation Payload (Non-Destructive)

```ducky
REM =============================================
REM ADVANCED: Ransomware Simulation (EDUCATIONAL)
REM Target: Windows 10/11 - ISOLATED LAB ONLY
REM Action: Simulates ransomware behavior
REM Purpose: Detection testing and education
REM WARNING: USE IN LAB ENVIRONMENT ONLY
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open PowerShell
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500

REM SIMULATION - Creates markers, does NOT encrypt
STRINGLN # RANSOMWARE SIMULATION - NON-DESTRUCTIVE
STRINGLN # Creates indicator files to test detection

STRINGLN # Create "encrypted" marker files (empty, just for detection)
STRINGLN $testPath = "$env:USERPROFILE\Desktop\RANSOMWARE_TEST"
STRINGLN New-Item -Path $testPath -ItemType Directory -Force

STRINGLN # Create fake encrypted file markers
STRINGLN 1..5 | ForEach-Object { New-Item "$testPath\file$_.txt.encrypted" -ItemType File }

STRINGLN # Create ransom note
STRINGLN @"
STRINGLN ===== RANSOMWARE SIMULATION =====
STRINGLN
STRINGLN This is a SIMULATION for security training.
STRINGLN No files have been encrypted.
STRINGLN
STRINGLN In a real attack, you would see:
STRINGLN - Encrypted files with changed extensions
STRINGLN - Ransom note with payment instructions
STRINGLN - Disabled shadow copies
STRINGLN - Terminated security processes
STRINGLN
STRINGLN This test helps verify:
STRINGLN - Detection capabilities
STRINGLN - Backup restoration
STRINGLN - Incident response procedures
STRINGLN
STRINGLN Delete this folder when testing complete.
STRINGLN "@ | Out-File "$testPath\README_SIMULATION.txt"

STRINGLN Write-Host "Simulation complete. Check: $testPath"
STRINGLN exit
```

---

## How Real Ransomware Works

### Attack Phases

```
┌─────────────────────────────────────────────────────────────┐
│                   Ransomware Attack Chain                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   1. INITIAL ACCESS                                          │
│      • Phishing email with malicious attachment              │
│      • Exploit kit via malicious website                     │
│      • RDP brute force                                       │
│      • Supply chain compromise                               │
│                                                               │
│   2. EXECUTION & PERSISTENCE                                 │
│      • Establish foothold                                    │
│      • Deploy RAT/backdoor                                   │
│      • Create persistence                                    │
│                                                               │
│   3. DISCOVERY & LATERAL MOVEMENT                            │
│      • Network enumeration                                   │
│      • Find valuable data                                    │
│      • Spread to other systems                               │
│      • Compromise backup servers                             │
│                                                               │
│   4. ENCRYPTION                                              │
│      • Delete shadow copies                                  │
│      • Encrypt files (AES/RSA hybrid)                        │
│      • Rename files with new extension                       │
│      • Drop ransom note                                      │
│                                                               │
│   5. EXTORTION                                               │
│      • Display ransom demand                                 │
│      • Threaten data leak                                    │
│      • Set payment deadline                                  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Encryption Mechanics (Educational)

```powershell
# EDUCATIONAL ONLY - How encryption works conceptually

# Generate AES key
$aesKey = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)

# AES encryption function (conceptual)
function Encrypt-File {
    param($Path, $Key)
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.GenerateIV()
    # In ransomware: file would be encrypted and renamed
    # We're NOT doing this - just showing the concept
}

# RSA encrypts the AES key
# Attacker holds private key
# Victim can only decrypt if they pay for private key
```

### Common Ransomware Behaviors

| Behavior | Purpose |
|----------|---------|
| Delete shadow copies | Prevent recovery |
| Kill security processes | Avoid detection |
| Terminate backup software | Prevent restoration |
| Network share enumeration | Find more targets |
| Exclude system files | Keep OS bootable |
| Add persistence | Survive reboots |

---

## Detection Indicators

### File System Activity

| Indicator | Detection Method |
|-----------|------------------|
| Mass file modification | Sysmon Event ID 11 |
| New file extensions | File integrity monitoring |
| Ransom note creation | File creation alerts |
| Shadow copy deletion | Event ID 524 |

### Process Activity

| Indicator | Detection Method |
|-----------|------------------|
| vssadmin delete shadows | Process monitoring |
| wmic shadowcopy delete | Command line logging |
| bcdedit /set recoveryenabled no | Boot config changes |
| Encryption APIs | API monitoring |

### Network Activity

| Indicator | Detection Method |
|-----------|------------------|
| C2 communication | Network monitoring |
| SMB enumeration | Traffic analysis |
| Mass file reads | NetFlow analysis |

---

## Blue Team Perspective

### Early Warning Signs

1. **Pre-Encryption**
   - Unusual recon activity
   - Disabled AV/EDR
   - Lateral movement
   - Backup tampering

2. **During Encryption**
   - High CPU usage
   - Mass file changes
   - Extension changes
   - Ransom note creation

3. **Post-Encryption**
   - Cannot open files
   - Ransom message displayed
   - Shadow copies missing

### Detection Script

```powershell
# Monitor for ransomware indicators
function Watch-RansomwareIndicators {
    # Check for shadow copy deletion
    Get-WinEvent -FilterHashtable @{LogName='Application';Id=524} -MaxEvents 10 -ErrorAction SilentlyContinue

    # Check for mass file modifications
    $recentFiles = Get-ChildItem $env:USERPROFILE -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) }

    if ($recentFiles.Count -gt 100) {
        Write-Warning "High file modification rate detected!"
    }

    # Check for suspicious extensions
    $suspiciousExt = @('.encrypted', '.locked', '.crypted', '.crypto')
    $encrypted = Get-ChildItem $env:USERPROFILE -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $suspiciousExt -contains $_.Extension }

    if ($encrypted) {
        Write-Warning "Files with suspicious extensions found!"
        $encrypted | Select FullName
    }
}

Watch-RansomwareIndicators
```

### Sigma Rule

```yaml
title: Ransomware Activity Indicators
status: experimental
description: Detects common ransomware behaviors
logsource:
    product: windows
    category: process_creation
detection:
    selection_shadow:
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'wmic shadowcopy delete'
    selection_recovery:
        CommandLine|contains:
            - 'bcdedit /set'
            - 'recoveryenabled'
    selection_backup:
        CommandLine|contains:
            - 'wbadmin delete'
            - 'delete catalog'
    condition: selection_shadow or selection_recovery or selection_backup
level: critical
tags:
    - attack.impact
    - attack.t1486
    - attack.t1490
```

---

## Prevention & Mitigation

### Prevention

| Control | Implementation |
|---------|---------------|
| Backups | 3-2-1 rule, offline/immutable |
| Patching | Regular updates |
| Email Security | Block malicious attachments |
| Endpoint Protection | EDR with behavioral analysis |
| Network Segmentation | Limit lateral movement |
| Least Privilege | Reduce attack surface |

### Response Checklist

1. **Contain**
   - Isolate affected systems
   - Disable network shares
   - Block C2 traffic

2. **Assess**
   - Identify scope
   - Determine ransomware variant
   - Check backup integrity

3. **Recover**
   - Restore from backups
   - Rebuild if necessary
   - Validate systems

4. **Learn**
   - Root cause analysis
   - Improve defenses
   - Update procedures

---

## Lab Setup for Testing

### Safe Testing Environment

```powershell
# Create isolated test environment
# Use virtual machine snapshot before testing
# Disconnect from production network

# Create test files
$testPath = "C:\RansomwareTest"
New-Item -Path $testPath -ItemType Directory -Force
1..100 | ForEach-Object {
    "Test content for file $_" | Out-File "$testPath\testfile_$_.txt"
}

# Run simulation (non-destructive)
# Creates .encrypted marker files alongside originals
# Does NOT actually encrypt anything
```

---

## Practice Exercises

### Exercise 1: Shadow Copy Check
```powershell
vssadmin list shadows
```

### Exercise 2: Backup Verification
```powershell
# Check Windows Backup status
Get-WBSummary
```

### Exercise 3: Detection Rule Testing
Run the simulation payload and verify your detection tools alert.

---

## Payload File

Save as `FZ-A10_Ransomware_Simulation.txt`:

```ducky
REM FZ-A10: Ransomware Simulation (EDUCATIONAL)
REM FOR LAB USE ONLY - DOES NOT ENCRYPT
DELAY 2500
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500
STRINGLN $p="$env:USERPROFILE\Desktop\RANSOM_SIM";New-Item $p -ItemType Directory -Force;1..5|%{New-Item "$p\file$_.txt.encrypted" -ItemType File};"SIMULATION - No real encryption" > "$p\README.txt";Write-Host "Simulation at: $p"
```

---

## Advanced Scripts Complete!

You've completed all Advanced level payloads. Key skills learned:

| Skill | Payloads |
|-------|----------|
| Security Bypass | FZ-A01, FZ-A02 |
| Credential Access | FZ-A03 |
| Remote Access | FZ-A04 |
| Data Exfiltration | FZ-A05 |
| Input Capture | FZ-A06 |
| Screen Capture | FZ-A07 |
| Domain Recon | FZ-A08 |
| Attack Chains | FZ-A09 |
| Ransomware Defense | FZ-A10 |

**Next:** [Expert Level Scripts →](../05_Expert_Scripts/)

---

[← FZ-A09 Complete Attack Chain](FZ-A09_Complete_Attack_Chain.md) | [Back to Advanced](README.md) | [Next: Expert Scripts →](../05_Expert_Scripts/)
