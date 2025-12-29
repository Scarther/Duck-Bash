# BadUSB Detection Quick Reference

## USB Event Monitoring

### Windows Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 2003 | Microsoft-Windows-DriverFrameworks-UserMode/Operational | USB device connected |
| 2004 | Microsoft-Windows-DriverFrameworks-UserMode/Operational | USB device disconnected |
| 2010 | Microsoft-Windows-DriverFrameworks-UserMode/Operational | USB device configuration |
| 2100-2102 | Microsoft-Windows-DriverFrameworks-UserMode/Operational | Driver installation |
| 6416 | Security | New external device recognized |
| 4663 | Security | Attempt to access removable storage |

### Quick PowerShell Detection Queries

```powershell
# Recent USB device connections
Get-WinEvent -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" |
  Where-Object { $_.Id -eq 2003 } |
  Select-Object TimeCreated, Message -First 10

# USB storage device events
Get-WinEvent -LogName Security |
  Where-Object { $_.Id -eq 6416 } |
  Select-Object TimeCreated, Message -First 10
```

### Linux USB Monitoring

```bash
# Monitor dmesg for USB events
dmesg -w | grep -i usb

# Check recent USB connections
journalctl -k | grep -i usb

# List connected USB devices
lsusb -v

# USB event monitoring
udevadm monitor --udev
```

---

## PowerShell Detection

### Event Log Locations

| Log | Contains |
|-----|----------|
| PowerShell/Operational | Script execution |
| PowerShell/Script Block Logging | Full script content |
| PowerShell/Module Logging | Loaded modules |
| PowerShell/Transcription | Complete transcripts |

### Suspicious Patterns

```powershell
# Encoded commands
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object { $_.Message -match "-enc|-encodedcommand" } |
  Select-Object TimeCreated, Message

# Download cradles
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object { $_.Message -match "DownloadString|DownloadFile|IWR|Invoke-WebRequest|WebClient" }

# Execution policy bypass
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object { $_.Message -match "-ep bypass|-ExecutionPolicy Bypass" }
```

### Sigma Rule - PowerShell Download Cradle
```yaml
title: PowerShell Download Cradle
status: stable
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'Invoke-WebRequest'
      - 'IWR'
      - 'WebClient'
      - 'Net.WebClient'
  condition: selection
level: high
```

---

## Sysmon Detection

### Critical Sysmon Events for BadUSB

| Event ID | Description |
|----------|-------------|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image loaded |
| 10 | Process access |
| 11 | File creation |
| 12-14 | Registry events |
| 22 | DNS query |

### Quick Sysmon Queries

```powershell
# Suspicious process creation
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 1 -and $_.Message -match "powershell|cmd|wscript|mshta" }

# Network connections to external IPs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 3 -and $_.Message -notmatch "DestinationIp: (127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)" }

# Registry Run key modifications
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 13 -and $_.Message -match "CurrentVersion\\Run" }
```

---

## Network Indicators

### Suspicious Outbound Traffic

| Protocol | Indicator | Severity |
|----------|-----------|----------|
| HTTP | POST to IP address (not domain) | High |
| HTTP | User-Agent: PowerShell, curl, wget | Medium |
| DNS | Long subdomain queries (exfil) | High |
| DNS | Queries to rare/new domains | Medium |
| ICMP | Large or unusual ICMP traffic | Medium |
| Any | Traffic to known bad IPs | Critical |

### Zeek/Bro Detection Script
```zeek
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    if (method == "POST" && c$http$user_agent == /PowerShell|curl|wget/) {
        print fmt("Suspicious POST: %s -> %s", c$id$orig_h, c$id$resp_h);
    }
}
```

### Suricata Rules
```
# PowerShell User-Agent
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious PowerShell User-Agent";
  content:"User-Agent|3a 20|PowerShell"; http_header; sid:100001; rev:1;)

# Possible DNS exfil (long subdomain)
alert dns any any -> any any (msg:"Possible DNS exfiltration - long subdomain";
  dns.query; pcre:"/^[a-zA-Z0-9]{30,}\./"; sid:100002; rev:1;)
```

---

## File System Indicators

### Suspicious Locations (Windows)

```
%TEMP%\*.exe
%TEMP%\*.ps1
%TEMP%\*.bat
%TEMP%\*.vbs
%APPDATA%\*.exe
%USERPROFILE%\AppData\Local\Temp\*
C:\Windows\Temp\*
```

### Suspicious Locations (Linux)

```
/tmp/.*
/dev/shm/*
/var/tmp/*
/home/*/.cache/*
```

### Quick File Hunting

```powershell
# Recent suspicious files (Windows)
Get-ChildItem -Path $env:TEMP -Include *.exe,*.ps1,*.bat,*.vbs -Recurse -File |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) }

# Hidden script files
Get-ChildItem -Path C:\Users -Include *.ps1,*.bat,*.vbs -Recurse -Hidden -File -ErrorAction SilentlyContinue
```

```bash
# Recent suspicious files (Linux)
find /tmp /dev/shm /var/tmp -type f -mmin -60 2>/dev/null

# Hidden executable files
find /home -type f -perm -u+x -name ".*" 2>/dev/null
```

---

## Registry Indicators (Windows)

### Key Locations to Monitor

| Key | Purpose |
|-----|---------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | User autostart |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | System autostart |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | One-time execution |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` | Shell replacement |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` | Login script |

### Registry Monitoring Query
```powershell
# Check Run keys
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue

# Recent registry changes (via Sysmon)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -in (12,13,14) -and $_.TimeCreated -gt (Get-Date).AddHours(-1) }
```

---

## Process Indicators

### Suspicious Process Trees

```
winword.exe → powershell.exe
excel.exe → cmd.exe → powershell.exe
explorer.exe → powershell.exe (hidden window)
svchost.exe → cmd.exe
```

### Suspicious Command Lines

```
powershell -enc
powershell -w hidden
powershell -ep bypass
cmd /c powershell
mshta vbscript:
certutil -urlcache
bitsadmin /transfer
regsvr32 /s /u /i:
rundll32 javascript:
```

### Process Hunting Query
```powershell
# Current suspicious processes
Get-Process | Where-Object {
    $_.ProcessName -match "powershell|cmd|wscript|cscript|mshta"
} | Select-Object ProcessName, Id, Path, StartTime

# Process command lines (requires admin)
Get-WmiObject Win32_Process |
  Where-Object { $_.CommandLine -match "-enc|-hidden|bypass|DownloadString" } |
  Select-Object Name, ProcessId, CommandLine
```

---

## YARA Rules

### Quick BadUSB Detection Rules
```yara
rule Suspicious_PowerShell_Script {
    meta:
        description = "Detects suspicious PowerShell script patterns"
    strings:
        $a = "DownloadString" nocase
        $b = "-enc" nocase
        $c = "Invoke-Expression" nocase
        $d = "IEX" nocase
        $e = "WebClient" nocase
        $f = "-windowstyle hidden" nocase
    condition:
        2 of them
}

rule Reverse_Shell_Indicator {
    meta:
        description = "Detects reverse shell patterns"
    strings:
        $a = "/dev/tcp/" nocase
        $b = "TCPClient" nocase
        $c = "bash -i" nocase
        $d = "nc -e" nocase
        $e = "socket.socket" nocase
    condition:
        any of them
}
```

---

## Quick Detection Checklist

### Immediate Response (< 5 min)

- [ ] Check recent USB device connections
- [ ] Review PowerShell event logs (last hour)
- [ ] Check scheduled tasks
- [ ] Review Run registry keys
- [ ] Check for suspicious processes
- [ ] Review recent file creations in TEMP

### Extended Analysis (< 30 min)

- [ ] Full Sysmon log review
- [ ] Network connection analysis
- [ ] DNS query log review
- [ ] Browser history/downloads check
- [ ] Full registry autorun scan
- [ ] Memory analysis if needed

---

## Tool Quick Reference

| Tool | Use Case | Command |
|------|----------|---------|
| Autoruns | Registry persistence | `autorunsc -a *` |
| Process Explorer | Process analysis | GUI |
| TCPView | Network connections | GUI |
| WinPmem | Memory acquisition | `winpmem.exe memdump.raw` |
| Volatility | Memory analysis | `vol.py -f memdump.raw pslist` |
| USBDeview | USB history | GUI |
| Sigma | Log detection | `sigmac -t splunk rule.yml` |

---

[← Back to Main](../README.md)
