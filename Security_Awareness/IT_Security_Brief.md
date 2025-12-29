# BadUSB Security Brief for IT Teams

## Technical Overview for IT Staff and Administrators

---

## Understanding the Threat

### How BadUSB Works

```
USB Device Inserted
        ↓
System Recognizes HID (Keyboard)
        ↓
Device Sends Keystroke Commands
        ↓
Commands Execute as User
        ↓
Payload Delivered (seconds)
```

### Why Traditional AV Fails

1. **No malware files** - Commands are typed, not dropped
2. **Trusted device type** - Keyboards are implicitly trusted
3. **User-level execution** - No exploit required
4. **Speed** - Faster than real-time scanning

### Attack Timeline

| Phase | Time | Activity |
|-------|------|----------|
| Enumeration | <1 sec | USB recognized as keyboard |
| Payload Start | 1-2 sec | Opens terminal/PowerShell |
| Execution | 3-10 sec | Commands typed and run |
| Persistence | 10-15 sec | Establishes foothold |
| Cleanup | 15-20 sec | Closes windows, hides tracks |

**Total compromise time: Under 30 seconds**

---

## Detection Strategies

### Log Sources to Monitor

| Source | Event IDs | What to Look For |
|--------|-----------|------------------|
| Security | 4688 | Process creation with suspicious commands |
| PowerShell | 4103, 4104 | Script block logging |
| Sysmon | 1, 3, 7, 11, 13 | Process, network, file, registry |
| USB Events | 2003, 6416 | Device connection |

### Key Detection Indicators

```
# Suspicious PowerShell patterns
- powershell.*-enc
- powershell.*-w hidden
- powershell.*IEX.*IWR
- powershell.*DownloadString
- powershell.*Invoke-Expression

# Suspicious process trees
- explorer.exe → powershell.exe (hidden)
- cmd.exe → powershell.exe
- Any process → powershell.exe (within seconds of USB insert)
```

### Sysmon Configuration (Critical Rules)

```xml
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- USB Device Connection -->
    <PnPDeviceEvent onmatch="include">
      <DeviceClass condition="is">HIDClass</DeviceClass>
    </PnPDeviceEvent>

    <!-- Suspicious PowerShell -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">-enc</CommandLine>
      <CommandLine condition="contains">-w hidden</CommandLine>
      <CommandLine condition="contains">IEX</CommandLine>
      <CommandLine condition="contains">DownloadString</CommandLine>
    </ProcessCreate>

    <!-- Registry Persistence -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
    </RegistryEvent>
  </EventFiltering>
</Sysmon>
```

---

## Prevention Controls

### Tier 1: Device Control (Most Effective)

**GPO Settings:**
```
Computer Configuration > Administrative Templates > System > Device Installation

- Prevent installation of removable devices: Enabled
- Allow installation of devices matching these IDs: [Approved list]
```

**Registry Implementation:**
```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions]
"DenyRemovableDevices"=dword:00000001
```

### Tier 2: USB Class Filtering

Block USB HID class for non-standard keyboards:
```
Device Class: {745a17a0-74d3-11d0-b6fe-00a0c90f57da}
```

### Tier 3: Endpoint Detection

Configure EDR to alert on:
- New HID device + PowerShell within 30 seconds
- USB device + network connection within 60 seconds
- Multiple rapid keystrokes from new device

---

## Response Playbook

### Immediate Response (0-5 minutes)

1. **Isolate** - Network disconnect affected system
2. **Preserve** - Don't power off (memory evidence)
3. **Document** - Note USB device appearance/location
4. **Contain** - Block network IOCs if identified

### Investigation (5-60 minutes)

1. Capture memory if possible
2. Review recent process execution
3. Check for persistence mechanisms
4. Identify C2 communications
5. Determine scope of access

### Investigation Commands

```powershell
# Recent PowerShell execution
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-30) }

# Recent USB devices
Get-WinEvent -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" |
    Where-Object { $_.Id -eq 2003 -and $_.TimeCreated -gt (Get-Date).AddHours(-1) }

# Check Run keys
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

# Recent network connections
Get-NetTCPConnection | Where-Object {
    $_.State -eq 'Established' -and
    $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2|3[01])\.|192\.168\.)'
}

# Scheduled tasks
Get-ScheduledTask | Where-Object { $_.Date -gt (Get-Date).AddDays(-1) }
```

---

## Implementation Checklist

### Phase 1: Visibility (Week 1)

- [ ] Enable PowerShell Script Block Logging
- [ ] Deploy Sysmon with custom config
- [ ] Configure USB event forwarding to SIEM
- [ ] Create baseline alerts

### Phase 2: Detection (Week 2-3)

- [ ] Implement detection rules (Sigma/SIEM)
- [ ] Create correlation rules for USB + execution
- [ ] Test detection with lab exercises
- [ ] Document false positive handling

### Phase 3: Prevention (Week 3-4)

- [ ] Pilot USB device restrictions (IT first)
- [ ] Create device whitelist
- [ ] Deploy GPO to broader groups
- [ ] Establish exception process

### Phase 4: Response (Ongoing)

- [ ] Update IR playbook
- [ ] Conduct tabletop exercise
- [ ] Train helpdesk on triage
- [ ] Create user reporting process

---

## Vendor Tools Reference

### USB Device Control Solutions

| Vendor | Product | Notes |
|--------|---------|-------|
| Microsoft | Defender for Endpoint | Device control rules |
| CrowdStrike | Falcon | USB device control |
| Carbon Black | EDR | Device control policies |
| Symantec | Endpoint Protection | Device control |
| McAfee | DLP | Removable media control |

### Physical Controls

| Product | Use Case |
|---------|----------|
| USB Port Blockers | Physical prevention |
| USB Data Blockers | Power-only charging |
| Kensington Locks | Physical USB locks |

---

## Testing & Validation

### Lab Testing Procedure

1. Set up isolated test environment
2. Deploy detection controls
3. Execute test payloads (safe versions)
4. Validate alert generation
5. Test response procedures
6. Document gaps and improvements

### Safe Testing Tools

- Flipper Zero (no actual malicious payload)
- Rubber Ducky with beacon-only payload
- USB Armory for advanced testing

### Test Payload (Safe)

```
REM Safe test payload - opens notepad only
DELAY 2000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING === BADUSB TEST - DO NOT BE ALARMED ===
ENTER
STRING This is a security test.
ENTER
STRING Please report to IT Security.
ENTER
STRING Test time: %TIME%
ENTER
```

---

## Metrics to Track

| Metric | Target | Frequency |
|--------|--------|-----------|
| Time to detect test payload | <5 minutes | Monthly |
| USB device policy compliance | >95% | Weekly |
| User reports of suspicious USB | Track all | Continuous |
| False positive rate | <5% | Weekly |
| Mean time to respond | <30 minutes | Per incident |

---

## Resources

- [Microsoft Device Installation Restrictions](https://docs.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK T1091](https://attack.mitre.org/techniques/T1091/)
- [SANS USB Security](https://www.sans.org/white-papers/)

---

*Document Classification: Internal IT Use Only*
*Last Updated: [Date]*
