# Cracking Reference Guide

## WPA/WPA2 Cracking

### Hash Formats

#### Hashcat Modes
| Mode | Format | Description |
|------|--------|-------------|
| 2500 | hccapx | WPA/WPA2 (legacy) |
| 22000 | hash line | WPA-PBKDF2-PMKID+EAPOL |
| 22001 | hash line | WPA-PMK-PMKID+EAPOL |

#### Hash Line Format (Mode 22000)
```
WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID_HEX*NONCE_AP*EAPOL*MESSAGE_PAIR
WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID_HEX***
```

### Conversion Tools
```bash
# Cap to hashcat format
hcxpcapngtool -o hash.22000 capture.cap

# Old method (deprecated)
cap2hccapx capture.cap hash.hccapx

# View hash info
hcxhashtool -i hash.22000 --info
```

---

## Hashcat Commands

### Basic Dictionary Attack
```bash
# WPA/WPA2 with wordlist
hashcat -m 22000 -a 0 hash.22000 wordlist.txt

# With rules
hashcat -m 22000 -a 0 hash.22000 wordlist.txt -r rules/best64.rule

# Show cracked
hashcat -m 22000 hash.22000 --show
```

### Attack Modes
| Mode | Flag | Description |
|------|------|-------------|
| 0 | -a 0 | Dictionary |
| 1 | -a 1 | Combination |
| 3 | -a 3 | Brute-force |
| 6 | -a 6 | Hybrid dict + mask |
| 7 | -a 7 | Hybrid mask + dict |

### Mask Attack (Brute Force)
```bash
# 8 character lowercase
hashcat -m 22000 -a 3 hash.22000 ?l?l?l?l?l?l?l?l

# 8-10 characters
hashcat -m 22000 -a 3 hash.22000 ?a?a?a?a?a?a?a?a --increment --increment-min 8 --increment-max 10

# Custom charset
hashcat -m 22000 -a 3 hash.22000 -1 ?l?d ?1?1?1?1?1?1?1?1
```

### Mask Charsets
| Charset | Description | Characters |
|---------|-------------|------------|
| ?l | Lowercase | a-z |
| ?u | Uppercase | A-Z |
| ?d | Digits | 0-9 |
| ?s | Special | !@#$%... |
| ?a | All printable | ?l?u?d?s |
| ?b | Binary | 0x00-0xFF |

---

## Common WiFi Password Patterns

### Pattern-Based Wordlist Generation
```bash
# Using hashcat mask processor
mp64 ?u?l?l?l?l?l?d?d > pattern_wordlist.txt

# Common patterns
Company2024!        # Company + Year + Symbol
Wireless123         # Generic + Numbers
Password1!          # Default + Complexity
Summer2024          # Season + Year
[City]WiFi          # Location-based
[Name]123           # Personal name
```

### Rule-Based Attacks
```bash
# Popular rules
hashcat -m 22000 hash.22000 wordlist.txt -r rules/best64.rule
hashcat -m 22000 hash.22000 wordlist.txt -r rules/d3ad0ne.rule
hashcat -m 22000 hash.22000 wordlist.txt -r rules/dive.rule

# Multiple rules
hashcat -m 22000 hash.22000 wordlist.txt -r rules/best64.rule -r rules/toggles1.rule
```

### Custom Rule Examples
```
# Append numbers
$0
$1
$0$1
$1$2$3

# Append years
$2$0$2$4
$2$0$2$5

# Capitalize first, append
c$1
c$1$2$3
c$!

# Leetspeak
sa@
se3
si1
so0

# Toggle case
T0
T1
T0T1
```

---

## Aircrack-ng Cracking

### Basic Commands
```bash
# Dictionary attack
aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF capture.cap

# Multiple wordlists
aircrack-ng -w list1.txt,list2.txt,list3.txt capture.cap

# With BSSID filter
aircrack-ng -b TARGET_BSSID -w wordlist.txt capture.cap
```

### Speed Comparison
| Tool | Speed (approx) | GPU Acceleration |
|------|----------------|------------------|
| aircrack-ng | 2,000 p/s (CPU) | No |
| hashcat | 500,000+ p/s | Yes |
| john | 3,000 p/s (CPU) | Limited |

---

## MSCHAPv2/NTLM Cracking

### Hash Formats
```
# NetNTLMv1 (hashcat mode 5500)
username::domain:challenge:response:challenge

# NetNTLMv2 (hashcat mode 5600)
username::domain:challenge:response:challenge

# MSCHAPv2 from hostapd-wpe
user::::challenge:response
```

### Cracking Commands
```bash
# NetNTLMv1
hashcat -m 5500 hashes.txt wordlist.txt

# NetNTLMv2
hashcat -m 5600 hashes.txt wordlist.txt

# NTLM (if you have just the hash)
hashcat -m 1000 hash.txt wordlist.txt
```

---

## Wordlist Resources

### Popular Wordlists
| Name | Size | Description |
|------|------|-------------|
| rockyou.txt | 14M passwords | Leaked passwords (classic) |
| SecLists | Various | Multiple specialized lists |
| CrackStation | 1.5B entries | Human passwords only |
| Kaonashi | 100M+ | Merged cleaned lists |

### WiFi-Specific Lists
```
Common WiFi passwords:
├── 12345678
├── password
├── password1
├── password123
├── 1234567890
├── 0987654321
├── qwertyuiop
├── abcdefgh
├── 11111111
├── 00000000
└── [SSID]123
```

### Generate Custom Lists
```bash
# Based on company name
echo "CompanyName" > base.txt
hashcat --stdout -r rules/best64.rule base.txt > company_list.txt

# From SSID
echo "NetworkSSID" | hashcat --stdout -a 0 -r rules/dive.rule - > ssid_based.txt

# Crunch (pattern generator)
crunch 8 8 -t Company@@ -o company_dates.txt
```

---

## Performance Optimization

### Hashcat Tuning
```bash
# Set workload profile (1-4)
hashcat -w 3 ...

# Set device
hashcat -d 1 ...

# Benchmark
hashcat -b -m 22000
```

### Hardware Requirements
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU | GTX 1060 | RTX 3080+ |
| VRAM | 4 GB | 8+ GB |
| RAM | 8 GB | 16+ GB |
| Storage | SSD 256GB | NVMe 512GB+ |

### Expected Speeds (RTX 3080)
| Hash Type | Speed |
|-----------|-------|
| WPA/WPA2 | ~500,000 H/s |
| NTLM | ~60,000,000,000 H/s |
| MD5 | ~60,000,000,000 H/s |
| SHA256 | ~4,000,000,000 H/s |

---

## John the Ripper

### Basic Usage
```bash
# Crack WPA
john --wordlist=rockyou.txt --format=wpapsk hash.john

# Show cracked
john --show hash.john

# Incremental mode
john --incremental hash.john
```

### Conversion
```bash
# Convert cap to john format
wpapcap2john capture.cap > hash.john

# PCAP to john
pcap2john.py capture.pcap > hashes.john
```

---

## Distributed Cracking

### Hashcat Distributed
```bash
# Node 1 (skip 0, work on half)
hashcat -m 22000 hash.22000 wordlist.txt --skip 0 --limit 50000000

# Node 2 (skip first half)
hashcat -m 22000 hash.22000 wordlist.txt --skip 50000000

# Using hashtopolis for management
# https://github.com/hashtopolis/server
```

### Cloud Cracking Services
```
AWS p3.8xlarge: 4x V100 GPUs
Google Cloud: Various GPU options
Vast.ai: Rental GPUs
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────┐
│                 CRACKING QUICK REFERENCE                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  WPA/WPA2:                                                  │
│    hashcat -m 22000 -a 0 hash.22000 wordlist.txt           │
│    hashcat -m 22000 -a 0 hash.22000 list.txt -r best64.rule│
│    aircrack-ng -w wordlist.txt capture.cap                 │
│                                                              │
│  NTLM/MSCHAPv2:                                             │
│    hashcat -m 5500 hashes.txt wordlist.txt  (NetNTLMv1)    │
│    hashcat -m 5600 hashes.txt wordlist.txt  (NetNTLMv2)    │
│                                                              │
│  MASKS:                                                      │
│    ?l = lowercase    ?u = uppercase                         │
│    ?d = digits       ?s = special                           │
│    ?a = all printable                                       │
│                                                              │
│  COMMON PATTERNS:                                           │
│    ?u?l?l?l?l?l?d?d    (Word2024)                          │
│    ?u?l?l?l?l?l?d?d?s  (Word2024!)                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

[← MITRE ATT&CK Mapping](../06_MITRE_ATT_CK_Mapping/) | [Back to Technical Addendum](../README.md) | [Next: Lab Environment →](../08_Lab_Environment/)
