# Microsoft Intune MDM Templates for USB Security

## Overview

This document provides Microsoft Intune (Endpoint Manager) configurations for managing USB device security across Windows, macOS, and iOS/Android devices.

---

## Windows Device Restrictions

### Create Device Restriction Profile

1. Navigate to: **Endpoint Manager > Devices > Configuration profiles > Create profile**
2. Platform: **Windows 10 and later**
3. Profile type: **Templates > Device restrictions**

### Removable Storage Settings

```json
{
    "deviceConfiguration": {
        "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
        "displayName": "USB Device Control",
        "description": "Block unauthorized USB storage devices",
        "storageBlockRemovableStorage": true,
        "storageRequireMobileDeviceEncryption": true,
        "storageBlockRemovableStorageWrite": true
    }
}
```

### Settings Reference

| Setting | OMA-URI | Value |
|---------|---------|-------|
| Block Removable Storage | `./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyWriteAccess` | `1` |
| Deny Execute on Removable | `./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyExecuteAccess` | `1` |
| All Removable Storage Deny | `./Device/Vendor/MSFT/Policy/Config/Storage/AllRemovableStorageClasses_DenyAll_Access_2` | `1` |

---

## Custom OMA-URI Policies

### Create Custom Profile

1. Navigate to: **Endpoint Manager > Devices > Configuration profiles > Create profile**
2. Platform: **Windows 10 and later**
3. Profile type: **Templates > Custom**

### USB Storage Blocking OMA-URI Settings

```xml
<!-- Block all removable storage -->
Name: Block Removable Storage
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyWriteAccess
Data type: Integer
Value: 1

<!-- Block CD/DVD -->
Name: Block CD ROM
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/Storage/CDRomDenyRead
Data type: Integer
Value: 1

<!-- Deny execute on removable -->
Name: Deny Execute Removable
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyExecuteAccess
Data type: Integer
Value: 1
```

### Device Installation Restrictions

```xml
<!-- Prevent installation of removable devices -->
Name: Prevent Removable Device Installation
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/DeviceInstallation/PreventInstallationOfMatchingDeviceIDs
Data type: String
Value: <enabled/><data id="DeviceInstall_IDs_Deny_List" value="1&#xF000;USB\Class_08"/>

<!-- Prevent device installation by class -->
Name: Prevent Device Class Installation
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/DeviceInstallation/PreventInstallationOfMatchingDeviceSetupClasses
Data type: String
Value: <enabled/><data id="DeviceInstall_Classes_Deny_List" value="1&#xF000;{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"/>
```

---

## Microsoft Defender for Endpoint - Device Control

### Device Control Policy JSON

```json
{
    "PolicyName": "USB Device Control Policy",
    "PolicyDescription": "Block unauthorized USB storage, allow approved devices",
    "Groups": [
        {
            "GroupId": "{group-guid-approved}",
            "Name": "Approved USB Storage",
            "Type": "Device",
            "DescriptorIdList": [
                {
                    "DescriptorType": "VID_PID",
                    "Value": "VID_0781&PID_5583"
                },
                {
                    "DescriptorType": "VID_PID",
                    "Value": "VID_0951&PID_1666"
                }
            ]
        },
        {
            "GroupId": "{group-guid-all-storage}",
            "Name": "All Removable Storage",
            "Type": "Device",
            "DescriptorIdList": [
                {
                    "DescriptorType": "PrimaryId",
                    "Value": "RemovableMediaDevices"
                }
            ]
        }
    ],
    "Rules": [
        {
            "RuleId": "{rule-guid-allow-approved}",
            "Name": "Allow Approved USB Storage",
            "IncludedIdList": ["{group-guid-approved}"],
            "Entry": [
                {
                    "Type": "Allow",
                    "AccessMask": 63,
                    "Options": 0
                }
            ]
        },
        {
            "RuleId": "{rule-guid-block-all}",
            "Name": "Block All Other USB Storage",
            "IncludedIdList": ["{group-guid-all-storage}"],
            "ExcludedIdList": ["{group-guid-approved}"],
            "Entry": [
                {
                    "Type": "Deny",
                    "AccessMask": 63,
                    "Options": 0
                },
                {
                    "Type": "AuditDenied",
                    "AccessMask": 63,
                    "Options": 1
                }
            ]
        }
    ]
}
```

### Deploy via Intune

1. Navigate to: **Endpoint Manager > Endpoint Security > Attack surface reduction**
2. Create policy: **Device control**
3. Import JSON configuration

---

## macOS USB Restrictions

### Create macOS Configuration Profile

1. Navigate to: **Endpoint Manager > Devices > Configuration profiles > Create profile**
2. Platform: **macOS**
3. Profile type: **Settings catalog**

### Configuration Settings

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systemuiserver</string>
            <key>PayloadIdentifier</key>
            <string>com.company.usb.restrictions</string>
            <key>PayloadUUID</key>
            <string>GENERATE-UUID-HERE</string>
            <key>mount-controls</key>
            <dict>
                <key>harddisk-external</key>
                <array>
                    <string>deny</string>
                </array>
                <key>disk-image</key>
                <array>
                    <string>deny</string>
                </array>
            </dict>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>USB Storage Restrictions</string>
    <key>PayloadIdentifier</key>
    <string>com.company.macos.usb</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>GENERATE-UUID-HERE</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

### Settings Catalog Options

| Category | Setting | Value |
|----------|---------|-------|
| System Policy Control | Allow USB Restricted Mode | No |
| Privacy | Access USB Device | Deny |

---

## iOS/iPadOS Restrictions

### Create iOS Configuration Profile

1. Navigate to: **Endpoint Manager > Devices > Configuration profiles > Create profile**
2. Platform: **iOS/iPadOS**
3. Profile type: **Device restrictions**

### USB Restrictions

| Setting | Value |
|---------|-------|
| Allow USB Restricted Mode | Block |
| Allow USB drive access in Files app | Block |
| Allow USB accessories while device is locked | Block |

### Configuration Profile XML

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>allowUSBRestrictedMode</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>iOS USB Restrictions</string>
    <key>PayloadIdentifier</key>
    <string>com.company.ios.usb</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

---

## Android Enterprise Restrictions

### Create Android Configuration

1. Navigate to: **Endpoint Manager > Devices > Configuration profiles > Create profile**
2. Platform: **Android Enterprise**
3. Profile type: **Device restrictions (Fully Managed)**

### USB Settings

| Setting | Value |
|---------|-------|
| USB file transfer | Block |
| USB debugging | Block |
| USB storage | Block |
| MTP (Media Transfer Protocol) | Block |

---

## Compliance Policies

### Windows Compliance Policy

```json
{
    "displayName": "USB Security Compliance",
    "description": "Ensure USB security policies are applied",
    "scheduledActionsForRule": [
        {
            "ruleName": "DeviceNonCompliance",
            "scheduledActionConfigurations": [
                {
                    "gracePeriodHours": 0,
                    "actionType": "block"
                },
                {
                    "gracePeriodHours": 24,
                    "actionType": "notification"
                }
            ]
        }
    ],
    "deviceComplianceRules": [
        {
            "settingName": "DefenderEnabled",
            "operator": "equals",
            "value": "true"
        },
        {
            "settingName": "BitLockerEnabled",
            "operator": "equals",
            "value": "true"
        }
    ]
}
```

---

## Monitoring and Reporting

### Intune Reports to Monitor

1. **Device compliance** - Check policy application status
2. **Configuration profiles** - Verify deployment success
3. **Audit logs** - Track policy changes
4. **Defender alerts** - Monitor device control events

### PowerShell Graph API Queries

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"

# Get device configuration profiles
$profiles = Get-MgDeviceManagementDeviceConfiguration
$profiles | Where-Object { $_.DisplayName -like "*USB*" }

# Get compliance status
$compliance = Get-MgDeviceManagementDeviceCompliancePolicyDeviceStatus
$compliance | Where-Object { $_.Status -ne "compliant" }

# Get audit events
$auditEvents = Get-MgDeviceManagementAuditEvent -Filter "category eq 'deviceConfiguration'"
$auditEvents | Select-Object ActivityDateTime, ActivityOperationType, Actor
```

---

## Deployment Checklist

### Pre-Deployment
- [ ] Identify approved USB devices
- [ ] Document hardware IDs for whitelisting
- [ ] Create test device group
- [ ] Define exception process

### Deployment
- [ ] Create configuration profiles
- [ ] Create compliance policies
- [ ] Assign to test group
- [ ] Monitor for issues
- [ ] Adjust settings as needed
- [ ] Deploy to production

### Post-Deployment
- [ ] Monitor compliance reports
- [ ] Review audit logs weekly
- [ ] Update whitelist as needed
- [ ] Train helpdesk on exceptions
- [ ] Document procedures

---

## Exception Request Template

```markdown
## USB Device Exception Request

**Requestor:** [Name]
**Department:** [Department]
**Date:** [Date]

### Device Information
- Device Type: [e.g., USB Flash Drive]
- Manufacturer: [e.g., SanDisk]
- Model: [e.g., Ultra Flair]
- VID_PID: [e.g., VID_0781&PID_5583]
- Serial Number: [If available]

### Business Justification
[Explain why this device is needed]

### Duration
- [ ] Permanent
- [ ] Temporary: [End Date]

### Risk Acknowledgment
- [ ] I understand the security risks associated with USB devices
- [ ] I will only use this device for approved business purposes
- [ ] I will report any security concerns immediately

**Signature:** _______________
**Manager Approval:** _______________
**IT Security Approval:** _______________
```

---

[← Back to Main](../../README.md)
