# Intermediate WiFi Pineapple Payloads (PP-I01 to PP-I10)

## Overview

Intermediate payloads build on fundamentals to perform active attacks: Evil Twin setup, credential capture, client manipulation, and network exploitation.

### Skill Level Characteristics
- **Code Length**: 50-150 lines Bash
- **Purpose**: Active network attacks
- **Risk**: Medium - active manipulation
- **Complexity**: Multiple components, error handling

---

## Payload Index

| ID | Name | Type | Description |
|----|------|------|-------------|
| [PP-I01](PP-I01_Evil_Twin.md) | Evil Twin | Attack | Create rogue access point |
| [PP-I02](PP-I02_Captive_Portal.md) | Captive Portal | Attack | Credential harvesting portal |
| [PP-I03](PP-I03_KARMA_Attack.md) | KARMA Attack | Attack | Respond to all probe requests |
| [PP-I04](PP-I04_SSL_Strip.md) | SSL Strip | Attack | Downgrade HTTPS connections |
| [PP-I05](PP-I05_DNS_Spoof.md) | DNS Spoof | Attack | Redirect DNS queries |
| [PP-I06](PP-I06_WEP_Crack.md) | WEP Crack | Attack | Crack WEP encryption |
| [PP-I07](PP-I07_WPA_Handshake.md) | WPA Handshake | Attack | Capture WPA handshakes |
| [PP-I08](PP-I08_Client_Deauth.md) | Client Deauth | Attack | Targeted disconnection |
| [PP-I09](PP-I09_Traffic_Capture.md) | Traffic Capture | Recon | Log all network traffic |
| [PP-I10](PP-I10_Automated_Recon.md) | Automated Recon | Recon | Scheduled reconnaissance |

---

## Key Concepts

### Evil Twin Attack Flow
```
┌─────────────────────────────────────────────────────────────┐
│                EVIL TWIN ATTACK FLOW                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. RECONNAISSANCE                                          │
│      └── Identify target network (SSID, channel)            │
│                                                              │
│   2. SETUP EVIL TWIN                                        │
│      └── Create AP with same SSID                           │
│      └── Configure DHCP/DNS                                 │
│                                                              │
│   3. DEAUTH LEGITIMATE AP                                   │
│      └── Disconnect clients from real AP                    │
│                                                              │
│   4. CLIENT CONNECTS                                        │
│      └── Victim connects to our stronger signal             │
│                                                              │
│   5. TRAFFIC INTERCEPTION                                   │
│      └── Capture credentials, inject content                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Attack Components

| Component | Tool | Purpose |
|-----------|------|---------|
| Access Point | hostapd | Create rogue AP |
| DHCP Server | dnsmasq | Assign IPs to clients |
| DNS Server | dnsmasq | Redirect DNS queries |
| Web Server | nginx/python | Serve captive portal |
| Traffic Capture | tcpdump | Log all traffic |
| SSL Strip | bettercap | Downgrade HTTPS |

---

## Common Setup Commands

### Enable IP Forwarding
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### Configure NAT
```bash
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
```

### Start Access Point
```bash
# hostapd.conf
interface=wlan0
ssid=TargetNetwork
channel=6
hw_mode=g

hostapd /tmp/hostapd.conf
```

### Start DHCP/DNS
```bash
# dnsmasq.conf
interface=wlan0
dhcp-range=192.168.1.100,192.168.1.200,12h
address=/#/192.168.1.1

dnsmasq -C /tmp/dnsmasq.conf
```

---

## Learning Objectives

After completing Intermediate payloads:
- [ ] Set up Evil Twin attacks
- [ ] Create captive portals
- [ ] Capture network credentials
- [ ] Perform MITM attacks
- [ ] Crack WEP/WPA encryption

---

## Prerequisites

Before starting Intermediate payloads:
1. Complete all Basic payloads
2. Understand wireless fundamentals
3. Know Bash scripting basics
4. Have monitor-capable adapter

---

[← Back to Chapter 02](../README.md) | [Next: PP-I01 Evil Twin →](PP-I01_Evil_Twin.md)
