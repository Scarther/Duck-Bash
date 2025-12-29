# Network Monitoring: IDS/IPS

## Overview

Network-based Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) provide visibility into network traffic and can detect attacks that endpoint solutions might miss. This section covers network monitoring for detecting USB payload communications, wireless attacks, and cryptomining activity.

---

## IDS vs IPS

```
┌─────────────────────────────────────────────────────────────────────┐
│                    IDS vs IPS                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   IDS (Intrusion Detection System)                                  │
│   ────────────────────────────────                                  │
│                                                                      │
│   ┌──────────┐                   ┌──────────┐                      │
│   │  Traffic │───────────────────│   IDS    │──────▶ Alert         │
│   └──────────┘     Mirror/TAP    └──────────┘                      │
│        │                                                             │
│        ▼                                                             │
│   ┌──────────┐                                                      │
│   │ Network  │    (Traffic flows normally)                          │
│   └──────────┘                                                      │
│                                                                      │
│   IPS (Intrusion Prevention System)                                 │
│   ─────────────────────────────────                                 │
│                                                                      │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐                      │
│   │  Traffic │───│   IPS    │───│ Network  │                       │
│   └──────────┘   └──────────┘   └──────────┘                       │
│                       │                                              │
│                       ▼                                              │
│                    Block/Alert (Traffic passes through IPS)         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Network Architecture for Detection

```
┌─────────────────────────────────────────────────────────────────────┐
│               NETWORK MONITORING ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   INTERNET                                                          │
│       │                                                              │
│       ▼                                                              │
│   ┌──────────────────────────────┐                                  │
│   │         FIREWALL             │──────▶ Logs to SIEM             │
│   └──────────────────────────────┘                                  │
│       │                                                              │
│       ▼                                                              │
│   ┌──────────────────────────────┐                                  │
│   │          IPS/IDS             │──────▶ Alerts to SIEM           │
│   │    (Inline or Passive)       │                                  │
│   └──────────────────────────────┘                                  │
│       │                                                              │
│       ├───────────────────────────────┐                             │
│       │                               │                              │
│       ▼                               ▼                              │
│   ┌──────────────┐           ┌──────────────┐                      │
│   │  DMZ / Web   │           │  Internal    │                       │
│   │   Servers    │           │  Network     │                       │
│   └──────────────┘           └──────────────┘                       │
│                                      │                               │
│                                      ▼                               │
│                          ┌──────────────────┐                       │
│                          │   Internal IDS   │──────▶ SIEM          │
│                          │   (East-West)    │                       │
│                          └──────────────────┘                       │
│                                      │                               │
│                                      ▼                               │
│                              ┌──────────────┐                       │
│                              │  Endpoints   │                       │
│                              │  & Servers   │                       │
│                              └──────────────┘                       │
│                                                                      │
│   Additionally:                                                      │
│   ├── Network TAPs for traffic mirroring                           │
│   ├── DNS monitoring for malicious domains                         │
│   ├── NetFlow collection for traffic analysis                      │
│   └── Full packet capture for forensics                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## IDS/IPS Platforms

### Open Source

| Platform | Type | Strengths |
|----------|------|-----------|
| Suricata | IDS/IPS | Fast, multi-threaded, excellent rule support |
| Snort | IDS/IPS | Industry standard, huge rule community |
| Zeek (Bro) | NSM | Protocol analysis, scripting capabilities |
| OSSEC | HIDS | Log analysis, file integrity |

### Commercial

| Platform | Type | Strengths |
|----------|------|-----------|
| Palo Alto | NGFW/IPS | App awareness, SSL inspection |
| Cisco Firepower | IPS | Deep integration, threat intel |
| FortiGate | NGFW/IPS | Performance, UTM features |
| Carbon Black | NTA | Behavioral analysis |

---

## Detection Rules for BadUSB C2 Traffic

### Snort/Suricata Rules

```
# Reverse Shell Detection
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"BADUSB Potential Reverse Shell";
    flow:to_server,established;
    content:"/bin/sh"; depth:10;
    classtype:trojan-activity;
    sid:1000001; rev:1;
)

# PowerShell Download Cradle (HTTP)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"BADUSB PowerShell Download Cradle";
    flow:to_server,established;
    content:"powershell"; nocase; http_user_agent;
    content:"GET"; http_method;
    classtype:trojan-activity;
    sid:1000002; rev:1;
)

# Encoded PowerShell over HTTP
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"BADUSB Encoded PowerShell Beacon";
    flow:to_server,established;
    content:"User-Agent|3a| Mozilla"; http_header;
    pcre:"/[A-Za-z0-9+\/=]{100,}/";
    classtype:trojan-activity;
    sid:1000003; rev:1;
)

# DNS Exfiltration (Long Subdomain)
alert dns $HOME_NET any -> any 53 (
    msg:"BADUSB Potential DNS Exfiltration";
    dns.query;
    pcre:"/[a-zA-Z0-9]{32,}\./";
    classtype:trojan-activity;
    sid:1000004; rev:1;
)

# Common C2 Beacon Patterns
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"BADUSB Cobalt Strike Beacon Pattern";
    flow:to_server,established;
    content:"Cookie|3a|"; http_header;
    pcre:"/SESSIONID=[a-zA-Z0-9+\/]{48,}/H";
    classtype:trojan-activity;
    sid:1000005; rev:1;
)
```

### Cryptocurrency Mining Detection

```
# Stratum Mining Protocol Detection
alert tcp $HOME_NET any -> any any (
    msg:"CRYPTOMINER Stratum Protocol Detected";
    flow:to_server,established;
    content:"mining.subscribe"; nocase;
    classtype:trojan-activity;
    sid:1000010; rev:1;
)

# XMRig Miner Detection
alert tcp $HOME_NET any -> any any (
    msg:"CRYPTOMINER XMRig Miner Detected";
    flow:to_server,established;
    content:"xmrig"; nocase;
    classtype:trojan-activity;
    sid:1000011; rev:1;
)

# Mining Pool Connection
alert tcp $HOME_NET any -> any 3333:3334 (
    msg:"CRYPTOMINER Mining Pool Connection (Common Port)";
    flow:to_server,established;
    content:"mining"; nocase;
    classtype:trojan-activity;
    sid:1000012; rev:1;
)

# Monero Pool Domains
alert dns $HOME_NET any -> any 53 (
    msg:"CRYPTOMINER Monero Pool DNS Query";
    dns.query;
    content:"pool"; nocase;
    content:"monero"; nocase; distance:0;
    classtype:trojan-activity;
    sid:1000013; rev:1;
)

# Bitcoin Pool Detection
alert dns $HOME_NET any -> any 53 (
    msg:"CRYPTOMINER Bitcoin Pool DNS Query";
    dns.query;
    pcre:"/(btc|bitcoin).*pool|pool.*(btc|bitcoin)/i";
    classtype:trojan-activity;
    sid:1000014; rev:1;
)

# High CPU Usage Traffic Pattern (Keepalive)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"CRYPTOMINER Persistent Connection Pattern";
    flow:to_server,established;
    content:"job"; depth:50;
    content:"id"; within:10;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:trojan-activity;
    sid:1000015; rev:1;
)
```

---

## Wireless Attack Detection (WIDS)

### Kismet Configuration

```conf
# /etc/kismet/kismet.conf

# Log alerts
log_alerts=true
log_types=alert

# Alert thresholds
alert=APSPOOF,5/min,1/sec
alert=DEAUTHFLOOD,10/min,2/sec
alert=DISASSOCIATEFLOOD,10/min,2/sec
alert=PROBERESPFLOOD,50/min,5/sec

# Known AP whitelist
filter_tracker=BSSID(AA:BB:CC:DD:EE:FF)
```

### Snort Wireless Rules

```
# Deauthentication Flood
alert wifi any any -> any any (
    msg:"WIRELESS Deauthentication Flood";
    wifi.type:0; wifi.subtype:12;
    threshold:type both, track by_src, count 20, seconds 10;
    classtype:attempted-dos;
    sid:2000001; rev:1;
)

# Beacon Flood
alert wifi any any -> any any (
    msg:"WIRELESS Beacon Flood Detected";
    wifi.type:0; wifi.subtype:8;
    threshold:type both, track by_src, count 100, seconds 10;
    classtype:attempted-dos;
    sid:2000002; rev:1;
)

# Probe Response Flood (KARMA Attack)
alert wifi any any -> any any (
    msg:"WIRELESS Probe Response Flood";
    wifi.type:0; wifi.subtype:5;
    threshold:type both, track by_src, count 50, seconds 10;
    classtype:attempted-recon;
    sid:2000003; rev:1;
)
```

---

## Network Traffic Analysis

### Zeek Scripts for Detection

```zeek
# badusb_c2_detection.zeek
# Detect potential BadUSB C2 communications

module BadUSB;

export {
    redef enum Notice::Type += {
        Rapid_HTTP_Requests,
        Encoded_PowerShell_Traffic,
        DNS_Exfiltration,
        Mining_Pool_Connection,
    };
}

# Detect rapid HTTP requests (beaconing)
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    local src = c$id$orig_h;
    
    # Track requests per source
    if (src !in http_request_count)
        http_request_count[src] = 0;
    
    http_request_count[src] += 1;
    
    if (http_request_count[src] > 100) {
        NOTICE([
            $note=Rapid_HTTP_Requests,
            $msg=fmt("Rapid HTTP requests from %s", src),
            $src=src,
            $identifier=cat(src)
        ]);
    }
}

# Detect mining pool connections
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (/pool\.(monero|xmr|btc|bitcoin|eth|ethereum)/ in query ||
        /(stratum|mining).*pool/ in query) {
        NOTICE([
            $note=Mining_Pool_Connection,
            $msg=fmt("Mining pool DNS query: %s", query),
            $src=c$id$orig_h,
            $identifier=cat(c$id$orig_h, query)
        ]);
    }
}
```

### NetFlow Analysis

```bash
#!/bin/bash
# Analyze NetFlow for suspicious patterns

# Common cryptominer ports
MINING_PORTS="3333 3334 3335 4444 5555 7777 8888 9999 14444 14433"

# Check for connections to mining ports
nfdump -r /var/netflow/current \
    -o "fmt:%ts %sa %da %dp %bps" \
    "dst port in [$MINING_PORTS]" | \
while read ts src dst port bps; do
    echo "[ALERT] Potential mining: $src -> $dst:$port ($bps bps)"
done

# High outbound data (exfiltration)
nfdump -r /var/netflow/current \
    -o "fmt:%ts %sa %da %byt" \
    -s srcip/bytes \
    "src net 10.0.0.0/8 and dst net not 10.0.0.0/8" | \
    awk '$4 > 100000000 {print "[ALERT] High outbound: " $0}'
```

---

## Integration with SIEM

### Log Forwarding Configuration

```yaml
# Suricata eve.json to SIEM
outputs:
  - eve-log:
      enabled: yes
      filetype: syslog
      facility: local5
      level: info
      types:
        - alert:
            payload: yes
            payload-printable: yes
            http: yes
            http-body: yes
            http-body-printable: yes
        - dns
        - tls
        - files
        - netflow
```

### Splunk Integration

```
# inputs.conf for Suricata
[monitor:///var/log/suricata/eve.json]
sourcetype = suricata
index = security

# Search for C2 indicators
index=security sourcetype=suricata event_type=alert
| stats count by alert.signature, src_ip, dest_ip
| where count > 10
| table src_ip, dest_ip, alert.signature, count
```

---

## Common Attack Patterns

### BadUSB Network Indicators

```
┌─────────────────────────────────────────────────────────────────────┐
│              BADUSB NETWORK INDICATORS                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PHASE 1: DOWNLOAD STAGE                                            │
│  ├── HTTP GET to raw.githubusercontent.com                         │
│  ├── HTTP GET to pastebin.com                                       │
│  ├── PowerShell user-agent                                          │
│  └── Download of .ps1, .exe, .dll files                            │
│                                                                      │
│  PHASE 2: C2 ESTABLISHMENT                                          │
│  ├── Consistent beacon intervals                                    │
│  ├── Long-lived connections                                         │
│  ├── Base64 in URI or POST body                                     │
│  └── Non-standard ports (4444, 8080, etc.)                         │
│                                                                      │
│  PHASE 3: DATA EXFILTRATION                                         │
│  ├── Large POST requests                                            │
│  ├── DNS TXT queries with encoded data                             │
│  ├── HTTPS to unusual domains                                       │
│  └── Upload to cloud storage (Drive, Dropbox)                      │
│                                                                      │
│  CRYPTOMINER INDICATORS:                                            │
│  ├── Stratum protocol traffic                                       │
│  ├── Connections to pool domains                                    │
│  ├── Ports 3333, 4444, 14444                                        │
│  ├── JSON-RPC with "job" and "submit"                              │
│  └── Persistent long-lived connections                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Mining Pool Domains to Monitor

```
Common Mining Pool Domains:
├── Monero (XMR)
│   ├── pool.minexmr.com
│   ├── xmr.nanopool.org
│   ├── monerohash.com
│   └── supportxmr.com
│
├── Bitcoin (BTC)
│   ├── btc.viabtc.com
│   ├── stratum.slushpool.com
│   └── ss.antpool.com
│
├── Ethereum (ETH)
│   ├── eth.2miners.com
│   ├── eth.nanopool.org
│   └── eu1.ethermine.org
│
└── Multi-coin Pools
    ├── stratum+tcp://pool.supportxmr.com
    ├── stratum+ssl://pool.hashvault.pro
    └── nicehash.com
```

---

## Implementation Checklist

```
□ Network Architecture
  □ Network TAPs or SPAN ports configured
  □ IDS/IPS positioned at network boundaries
  □ Internal network monitoring deployed
  □ NetFlow collection enabled
  □ DNS logging configured

□ Detection Rules
  □ C2 communication patterns
  □ Data exfiltration indicators
  □ Cryptocurrency mining traffic
  □ Wireless attack signatures
  □ Custom rules for environment

□ Alert Configuration
  □ Critical alerts routed immediately
  □ Alert thresholds tuned
  □ False positives minimized
  □ SIEM integration verified

□ Response Procedures
  □ Blocking procedures documented
  □ Investigation playbooks created
  □ Forensic capture capability
  □ Escalation paths defined
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│                 IDS/IPS QUICK REFERENCE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  KEY DETECTION SIGNATURES:                                          │
│  ├── Reverse shell patterns                                         │
│  ├── PowerShell download cradles                                    │
│  ├── Encoded command traffic                                        │
│  ├── Stratum mining protocol                                        │
│  └── DNS exfiltration patterns                                      │
│                                                                      │
│  MINING INDICATORS:                                                 │
│  ├── Ports: 3333, 3334, 4444, 14444                                │
│  ├── Protocol: Stratum (JSON-RPC over TCP)                         │
│  ├── Keywords: mining.subscribe, job, submit                       │
│  └── Pool domains: *pool*, *mine*, *hash*                          │
│                                                                      │
│  C2 INDICATORS:                                                     │
│  ├── Regular beacon intervals                                       │
│  ├── Base64 in requests                                             │
│  ├── Long cookie values                                             │
│  └── Unusual user agents                                            │
│                                                                      │
│  RESPONSE ACTIONS:                                                  │
│  ├── Block at firewall                                              │
│  ├── Sinkhole malicious domains                                     │
│  ├── Capture traffic for analysis                                   │
│  └── Isolate affected endpoints                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← EDR](../03_EDR/) | [Back to Security Operations](../README.md) | [Next: Botnet Understanding →](../05_Botnet_Understanding/)
