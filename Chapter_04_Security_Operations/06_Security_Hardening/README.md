# Security Hardening

## Overview

Security hardening reduces the attack surface and limits the impact of successful attacks. This section covers hardening Windows and Linux systems against USB/HID attacks, wireless threats, and common payload execution techniques.

---

## USB/HID Hardening

### Windows USB Device Control

#### Group Policy Configuration

```
┌─────────────────────────────────────────────────────────────────────┐
│            WINDOWS USB DEVICE CONTROL GPO                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Computer Configuration → Administrative Templates →                │
│  System → Device Installation → Device Installation Restrictions    │
│                                                                      │
│  RECOMMENDED SETTINGS:                                              │
│                                                                      │
│  ☑ Prevent installation of devices not described by other policy   │
│     → Blocks unknown devices by default                             │
│                                                                      │
│  ☑ Prevent installation of devices using drivers matching these    │
│    device setup classes:                                            │
│    → {4d36e96b-e325-11ce-bfc1-08002be10318} (Keyboard)             │
│    → Note: Only if using approved keyboard whitelist                │
│                                                                      │
│  ☑ Allow installation of devices matching any of these device IDs: │
│    → USB\VID_045E&PID_* (Microsoft devices)                        │
│    → USB\VID_046D&PID_* (Logitech devices)                         │
│    → Add your approved device IDs here                             │
│                                                                      │
│  ☑ Display custom message when installation prevented              │
│    → "Unauthorized device blocked. Contact IT security."           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

#### PowerShell Implementation

```powershell
# Block all new USB storage devices
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "DenyUnspecified" -Value 1 -Type DWord

# Whitelist specific device IDs
$allowPath = "$regPath\AllowDeviceIDs"
New-Item -Path $allowPath -Force
Set-ItemProperty -Path $allowPath -Name "1" -Value "USB\VID_045E&PID_0745" -Type String
Set-ItemProperty -Path $allowPath -Name "2" -Value "USB\VID_046D&PID_C52B" -Type String

# Block specific known BadUSB device IDs
$denyPath = "$regPath\DenyDeviceIDs"  
New-Item -Path $denyPath -Force
Set-ItemProperty -Path $denyPath -Name "1" -Value "USB\VID_0483&PID_5740" -Type String  # Flipper
Set-ItemProperty -Path $denyPath -Name "2" -Value "USB\VID_FEED*" -Type String          # Common BadUSB

# Require admin for device installation
Set-ItemProperty -Path $regPath -Name "DenyRemotelyInstalled" -Value 1 -Type DWord
```

### Linux USB Guard

#### USBGuard Installation

```bash
# Install USBGuard
apt install usbguard  # Debian/Ubuntu
dnf install usbguard  # Fedora/RHEL

# Generate initial policy (allow currently connected devices)
usbguard generate-policy > /etc/usbguard/rules.conf

# Enable and start service
systemctl enable usbguard
systemctl start usbguard
```

#### USBGuard Policy

```
# /etc/usbguard/rules.conf

# Allow known keyboards
allow id 045e:* with-interface one-of { 03:01:01 } label "Microsoft Keyboards"
allow id 046d:* with-interface one-of { 03:01:01 } label "Logitech Keyboards"

# Allow known mice
allow id 045e:* with-interface one-of { 03:01:02 } label "Microsoft Mice"
allow id 046d:* with-interface one-of { 03:01:02 } label "Logitech Mice"

# Block known BadUSB devices
reject id 0483:5740 label "Block Flipper Zero"
reject id feed:* label "Block BadUSB Generic"
reject id 1337:* label "Block Hak5 Devices"

# Default: Block all other HID devices
reject with-interface one-of { 03:* } if !allowed

# Allow USB storage (optional - can be removed for high security)
# allow with-interface one-of { 08:* }

# Block everything else by default
reject
```

---

## PowerShell Hardening

### Constrained Language Mode

```powershell
# Enable Constrained Language Mode via GPO or registry
# Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell

# Turn on PowerShell Script Block Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# Turn on Module Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1

# Log all modules
$modPath = "$regPath\ModuleNames"
New-Item -Path $modPath -Force
Set-ItemProperty -Path $modPath -Name "*" -Value "*"

# Enable Transcription
$transPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $transPath -Force
Set-ItemProperty -Path $transPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $transPath -Name "OutputDirectory" -Value "C:\PSTranscripts"
```

### Execution Policy

```powershell
# Set restrictive execution policy
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force

# Or for high-security environments
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force

# Note: This can be bypassed, so combine with other controls
```

### AMSI Configuration

```powershell
# Ensure AMSI is enabled (default on Windows 10+)
# Check AMSI status
(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI").AmsiEnable

# Monitor for AMSI bypass attempts via Sysmon/EDR
# Common bypass indicators:
# - amsiInitFailed
# - AmsiScanBuffer
# - [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

---

## Application Whitelisting

### Windows Defender Application Control (WDAC)

```xml
<?xml version="1.0" encoding="utf-8"?>
<!-- WDAC Base Policy -->
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>10.0.0.0</VersionEx>
  <PolicyTypeID>{A244370E-44C9-4C06-B551-F6016E563076}</PolicyTypeID>
  
  <Rules>
    <!-- Block unsigned scripts -->
    <Rule>
      <Option>Enabled:Unsigned System Integrity Policy</Option>
    </Rule>
    
    <!-- Audit mode first, then enforce -->
    <Rule>
      <Option>Enabled:Audit Mode</Option>
    </Rule>
  </Rules>
  
  <FileRules>
    <!-- Allow Windows signed files -->
    <Allow ID="ID_ALLOW_WINDOWS" FriendlyName="Windows" 
           CertRoot="Microsoft Windows Production" />
           
    <!-- Block known BadUSB tools -->
    <Deny ID="ID_DENY_DUCKY" FriendlyName="DuckyScript Tools"
          FileName="ducky*.exe" />
  </FileRules>
</SiPolicy>
```

### AppLocker Configuration

```xml
<!-- AppLocker Policy - Block unsigned scripts -->
<AppLockerPolicy Version="1">
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    
    <!-- Allow signed scripts from trusted publishers -->
    <FilePublisherRule Id="rule-id" Name="Signed Scripts" 
                       UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT*" 
                                ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    
    <!-- Block all unsigned scripts -->
    <FilePathRule Id="rule-id2" Name="Block Unsigned" 
                  UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
    
  </RuleCollection>
</AppLockerPolicy>
```

---

## Network Hardening

### Firewall Configuration

```powershell
# Windows Firewall - Block outbound to mining pools
$miningPorts = 3333, 3334, 4444, 14444, 14433
foreach ($port in $miningPorts) {
    New-NetFirewallRule -DisplayName "Block Mining Port $port" `
        -Direction Outbound -LocalPort $port -Protocol TCP -Action Block
}

# Block known malicious domains at DNS level
# Add to hosts file or use DNS filtering
$blockedDomains = @(
    "pool.minexmr.com",
    "xmr.nanopool.org",
    "raw.githubusercontent.com"  # Often used for payload staging
)
foreach ($domain in $blockedDomains) {
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "0.0.0.0 $domain"
}
```

### Linux iptables

```bash
#!/bin/bash
# Network hardening for Linux

# Block common mining ports
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -p tcp --dport 14444 -j DROP

# Block outbound to known bad IPs (example)
iptables -A OUTPUT -d 185.165.171.0/24 -j DROP

# Allow only necessary outbound traffic
# Whitelist approach (more restrictive)
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT   # HTTP
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT   # DNS
```

---

## Wireless Network Hardening

### Access Point Configuration

```
┌─────────────────────────────────────────────────────────────────────┐
│            WIRELESS SECURITY BEST PRACTICES                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ENCRYPTION:                                                        │
│  ├── Use WPA3 if available                                         │
│  ├── WPA2-Enterprise with 802.1X for corporate                     │
│  ├── Strong PSK if using WPA2-Personal (20+ chars)                 │
│  └── Disable WEP and TKIP completely                               │
│                                                                      │
│  MANAGEMENT:                                                        │
│  ├── Enable Management Frame Protection (802.11w/PMF)              │
│  ├── Disable WPS (WiFi Protected Setup)                            │
│  ├── Use non-default admin credentials                             │
│  └── Restrict management access to wired network                   │
│                                                                      │
│  CLIENT ISOLATION:                                                  │
│  ├── Enable client isolation on guest networks                     │
│  ├── Separate VLANs for different security levels                  │
│  └── Implement network segmentation                                │
│                                                                      │
│  MONITORING:                                                        │
│  ├── Deploy WIDS/WIPS                                              │
│  ├── Enable AP logging to SIEM                                     │
│  ├── Regular rogue AP scans                                        │
│  └── Monitor for deauth attacks                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Client Configuration

```powershell
# Windows - Disable auto-connect to open networks
netsh wlan set autoconfig enabled=no interface="Wi-Fi"

# Remove saved networks
netsh wlan delete profile name="*" interface="*"

# Configure preferred networks only
netsh wlan add profile filename="corporate-wifi.xml"

# Disable WiFi when using Ethernet (GPO or script)
$wifi = Get-NetAdapter | Where-Object {$_.Name -like "*Wi-Fi*"}
$ethernet = Get-NetAdapter | Where-Object {$_.Name -like "*Ethernet*"}
if ($ethernet.Status -eq "Up") {
    Disable-NetAdapter -Name $wifi.Name -Confirm:$false
}
```

---

## Registry Hardening

### Disable Common Attack Vectors

```powershell
# Disable Windows Script Host
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" `
    -Name "Enabled" -Value 0 -Type DWord

# Disable Office macros from internet
$officePath = "HKCU:\Software\Microsoft\Office\16.0\Word\Security"
Set-ItemProperty -Path $officePath -Name "VBAWarnings" -Value 4 -Type DWord
Set-ItemProperty -Path $officePath -Name "BlockContentExecutionFromInternet" -Value 1 -Type DWord

# Disable AutoRun/AutoPlay
$autorunPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

# Block remote registry access
Stop-Service -Name "RemoteRegistry" -Force
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# Disable LLMNR (prevent responder attacks)
$llmnrPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
New-Item -Path $llmnrPath -Force
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord

# Disable NetBIOS over TCP/IP
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable
}
```

---

## Audit and Logging

### Enhanced Audit Policy

```powershell
# Enable advanced audit policy
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable

# Enable command line in process creation events
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
```

### Sysmon Configuration

```xml
<!-- Sysmon config for BadUSB detection -->
<Sysmon schemaversion="4.50">
  <HashAlgorithms>SHA256</HashAlgorithms>
  
  <EventFiltering>
    <!-- Log process creation with command line -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="end with">explorer.exe</ParentImage>
    </ProcessCreate>
    
    <!-- Log all PowerShell -->
    <ProcessCreate onmatch="include">
      <Image condition="end with">powershell.exe</Image>
      <Image condition="end with">pwsh.exe</Image>
    </ProcessCreate>
    
    <!-- Log registry persistence locations -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
    </RegistryEvent>
    
    <!-- Log file creation in startup folders -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">Start Menu\Programs\Startup</TargetFilename>
    </FileCreate>
    
    <!-- Log scheduled task creation -->
    <ProcessCreate onmatch="include">
      <Image condition="end with">schtasks.exe</Image>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## Hardening Checklist

```
┌─────────────────────────────────────────────────────────────────────┐
│              SECURITY HARDENING CHECKLIST                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  USB CONTROLS:                                                      │
│  □ USB device whitelist configured                                 │
│  □ Known BadUSB device IDs blocked                                 │
│  □ USB storage disabled (if not needed)                            │
│  □ Physical port locks installed (high-security)                   │
│                                                                      │
│  POWERSHELL:                                                        │
│  □ Constrained Language Mode enabled                               │
│  □ Script Block Logging enabled                                    │
│  □ Module Logging enabled                                          │
│  □ Transcription enabled                                           │
│  □ Execution policy set                                            │
│                                                                      │
│  APPLICATION CONTROL:                                               │
│  □ WDAC or AppLocker configured                                    │
│  □ Script execution restricted                                     │
│  □ Only signed code allowed                                        │
│                                                                      │
│  NETWORK:                                                           │
│  □ Mining ports blocked                                             │
│  □ Outbound filtering configured                                   │
│  □ DNS filtering enabled                                           │
│  □ LLMNR/NetBIOS disabled                                          │
│                                                                      │
│  WIRELESS:                                                          │
│  □ WPA3 or WPA2-Enterprise enabled                                 │
│  □ WPS disabled                                                     │
│  □ Management Frame Protection enabled                             │
│  □ WIDS deployed                                                    │
│                                                                      │
│  LOGGING:                                                           │
│  □ Process creation logging enabled                                │
│  □ Command line logging enabled                                    │
│  □ PowerShell logging enabled                                      │
│  □ Sysmon deployed                                                 │
│  □ Logs forwarded to SIEM                                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────┐
│            HARDENING QUICK REFERENCE                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  TOP PRIORITY CONTROLS:                                             │
│  1. USB device whitelisting                                         │
│  2. PowerShell logging and constraints                              │
│  3. Application whitelisting                                        │
│  4. Enhanced audit logging                                          │
│  5. Network egress filtering                                        │
│                                                                      │
│  BADUSB-SPECIFIC:                                                   │
│  ├── Block VID 0483 (Flipper)                                       │
│  ├── Block VID FEED (Common BadUSB)                                 │
│  ├── Block VID 1337 (Hak5)                                          │
│  └── Only allow whitelisted keyboards                              │
│                                                                      │
│  MINING PREVENTION:                                                 │
│  ├── Block ports 3333, 4444, 14444                                 │
│  ├── Block pool domains via DNS                                     │
│  ├── Monitor CPU usage alerts                                       │
│  └── Application whitelisting                                       │
│                                                                      │
│  WIRELESS:                                                          │
│  ├── Use WPA3 or WPA2-Enterprise                                   │
│  ├── Enable 802.11w (PMF)                                          │
│  ├── Deploy WIDS                                                    │
│  └── Disable auto-connect                                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

[← Botnet Understanding](../05_Botnet_Understanding/) | [Back to Security Operations](../README.md) | [Next: Incident Response →](../07_Incident_Response/)
