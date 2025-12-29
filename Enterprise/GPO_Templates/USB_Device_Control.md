# Windows Group Policy Templates for USB Device Control

## Overview

This document provides Group Policy Object (GPO) configurations for preventing and detecting BadUSB attacks in enterprise Windows environments.

---

## GPO: Block All Removable Storage

### Policy Path
```
Computer Configuration > Administrative Templates > System > Removable Storage Access
```

### Settings

| Policy | Setting | Value |
|--------|---------|-------|
| All Removable Storage classes: Deny all access | Enabled | Yes |
| All Removable Storage: Allow direct access in remote sessions | Disabled | - |
| CD and DVD: Deny execute access | Enabled | Yes |
| CD and DVD: Deny read access | Enabled | Yes |
| CD and DVD: Deny write access | Enabled | Yes |
| Removable Disks: Deny execute access | Enabled | Yes |
| Removable Disks: Deny read access | Enabled | Yes |
| Removable Disks: Deny write access | Enabled | Yes |
| WPD Devices: Deny read access | Enabled | Yes |
| WPD Devices: Deny write access | Enabled | Yes |

### Registry Equivalent
```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices]
"Deny_All"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}]
"Deny_Read"=dword:00000001
"Deny_Write"=dword:00000001
"Deny_Execute"=dword:00000001
```

---

## GPO: USB Device Whitelist

### Prerequisites
- Windows 10/11 Enterprise or Education
- Device installation restrictions require specific hardware IDs

### Policy Path
```
Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions
```

### Settings

| Policy | Setting |
|--------|---------|
| Prevent installation of devices not described by other policy settings | Enabled |
| Allow installation of devices that match any of these device IDs | Enabled + List |
| Allow installation of devices that match any of these device setup classes | Enabled + List |

### Allowed Device Classes (Examples)

```
# Keyboards (HID)
{4d36e96b-e325-11ce-bfc1-08002be10318}

# Mice (HID)
{4d36e96f-e325-11ce-bfc1-08002be10318}

# USB Hubs
{36fc9e60-c465-11cf-8056-444553540000}

# Approved storage devices (add specific hardware IDs)
USB\VID_0781&PID_5583  # SanDisk example
USB\VID_0951&PID_1666  # Kingston example
```

### PowerShell Script to Get Device Hardware IDs

```powershell
# Get all USB device hardware IDs
Get-WmiObject Win32_PnPEntity |
    Where-Object { $_.DeviceID -like 'USB*' } |
    Select-Object Name, DeviceID, @{N='HardwareID';E={$_.HardwareID[0]}} |
    Format-Table -AutoSize

# Get specific device info
Get-PnpDevice -Class USB |
    Get-PnpDeviceProperty -KeyName 'DEVPKEY_Device_HardwareIds' |
    Format-Table InstanceId, Data
```

---

## GPO: Prevent Installation of Removable Devices

### Policy Path
```
Computer Configuration > Administrative Templates > System > Device Installation > Device Installation Restrictions
```

### Settings

```
Policy: Prevent installation of removable devices
Setting: Enabled
```

### Registry Equivalent
```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions]
"DenyRemovableDevices"=dword:00000001
```

---

## GPO: Enable Device Installation Logging

### Policy Path
```
Computer Configuration > Administrative Templates > System > Device Installation
```

### Settings

| Policy | Setting |
|--------|---------|
| Configure device installation time-out | Enabled - 300 seconds |
| Allow remote access to the PnP interface | Disabled |

### Enable Detailed Logging

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup]
"LogLevel"=dword:0000ffff

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"SetupType"=dword:00000000
```

---

## GPO: PowerShell Execution and Logging

### Policy Path
```
Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell
```

### Settings

| Policy | Setting |
|--------|---------|
| Turn on Script Execution | Enabled - Allow only signed scripts |
| Turn on Module Logging | Enabled |
| Turn on PowerShell Script Block Logging | Enabled |
| Turn on PowerShell Transcription | Enabled |

### Transcript Output Path
```
C:\Windows\Logs\PowerShell\
```

### Registry Settings
```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging]
"EnableScriptBlockLogging"=dword:00000001
"EnableScriptBlockInvocationLogging"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging]
"EnableModuleLogging"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription]
"EnableTranscripting"=dword:00000001
"OutputDirectory"="C:\\Windows\\Logs\\PowerShell"
"EnableInvocationHeader"=dword:00000001
```

---

## GPO: Command Prompt Restrictions

### Policy Path
```
User Configuration > Administrative Templates > System
```

### Settings

| Policy | Setting |
|--------|---------|
| Prevent access to the command prompt | Enabled - Disable script processing also |

**Note:** This is aggressive and may break legitimate scripts. Consider scope carefully.

---

## GPO: Windows Defender Hardening

### Policy Path
```
Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus
```

### Settings

| Policy | Setting |
|--------|---------|
| Turn off Microsoft Defender Antivirus | Disabled (keeps Defender ON) |
| Configure local setting override for reporting to MAPS | Disabled |
| Turn on behavior monitoring | Enabled |
| Scan removable drives | Enabled |
| Turn on script scanning | Enabled |

### Real-time Protection
```
Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection
```

| Policy | Setting |
|--------|---------|
| Turn off real-time protection | Disabled |
| Turn on process scanning when possible | Enabled |
| Monitor file and program activity on your computer | Enabled |

---

## GPO: Audit USB Device Events

### Policy Path
```
Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Object Access
```

### Settings

| Policy | Success | Failure |
|--------|---------|---------|
| Audit Removable Storage | Enable | Enable |
| Audit Handle Manipulation | Enable | Enable |
| Audit PNP Activity | Enable | Enable |

### Enable via auditpol
```cmd
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
```

---

## Complete GPO Template Export

### PowerShell Export Script

```powershell
# Export USB Security GPO Settings
# Run on a domain controller with the GPO applied

$GPOName = "USB-Security-Policy"
$ExportPath = "C:\GPO_Backups"

# Create backup directory
New-Item -ItemType Directory -Path $ExportPath -Force

# Backup GPO
Backup-GPO -Name $GPOName -Path $ExportPath

# Export to HTML report
Get-GPOReport -Name $GPOName -ReportType HTML -Path "$ExportPath\$GPOName.html"

Write-Host "GPO exported to $ExportPath"
```

### Import GPO

```powershell
# Import USB Security GPO
$ImportPath = "C:\GPO_Backups"
$GPOName = "USB-Security-Policy"

# Get backup ID
$BackupID = (Get-ChildItem $ImportPath -Directory).Name

# Import GPO
Import-GPO -BackupId $BackupID -TargetName $GPOName -Path $ImportPath -CreateIfNeeded
```

---

## Testing GPO Application

### Verify GPO Application

```powershell
# Check applied GPOs
gpresult /r

# Detailed GPO report
gpresult /h C:\GPO_Report.html

# Force GPO update
gpupdate /force

# Check specific policy settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
```

### Test USB Blocking

```powershell
# Check if USB storage is blocked
$USBDrive = Get-WmiObject Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' }
if ($USBDrive) {
    Write-Host "USB storage detected - policy may not be applied"
} else {
    Write-Host "No USB storage detected - policy is working"
}
```

---

## Deployment Checklist

- [ ] Create GPO in Group Policy Management Console
- [ ] Configure USB device restrictions
- [ ] Configure PowerShell logging
- [ ] Enable audit policies
- [ ] Link GPO to target OUs
- [ ] Test on pilot group
- [ ] Document exceptions
- [ ] Monitor for issues
- [ ] Create exception process
- [ ] Train IT staff

---

[← Back to Main](../../README.md)
