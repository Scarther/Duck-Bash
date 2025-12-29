# Security Hardening Guide

## Overview

This guide covers hardening techniques to prevent BadUSB attacks and reduce the overall attack surface of systems.

---

## USB Security Hardening

### Disable USB Storage (Linux)

```bash
#!/bin/bash
#######################################
# Disable USB Storage Devices
#######################################

echo "[*] Disabling USB storage..."

# Method 1: Blacklist USB storage module
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
echo "blacklist uas" >> /etc/modprobe.d/blacklist.conf

# Method 2: Remove if currently loaded
rmmod usb-storage 2>/dev/null
rmmod uas 2>/dev/null

# Method 3: Prevent loading
echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-usb-storage.conf

# Rebuild initramfs
update-initramfs -u

echo "[+] USB storage disabled"
echo "[*] Reboot required for full effect"
```

### Disable USB Storage (Windows)

```powershell
#######################################
# Disable USB Storage (Windows)
# Run as Administrator
#######################################

# Method 1: Registry
$path = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
Set-ItemProperty -Path $path -Name "Start" -Value 4

# Method 2: Group Policy (Domain environments)
# Computer Configuration > Administrative Templates >
# System > Removable Storage Access > All Removable Storage classes: Deny all access

# Method 3: Device Installation Restrictions
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "DenyDeviceClasses" -Value 1
Set-ItemProperty -Path $path -Name "DenyDeviceClassesRetroactive" -Value 1

# USB Storage device class GUID
$classPath = "$path\DenyDeviceClasses"
New-Item -Path $classPath -Force | Out-Null
Set-ItemProperty -Path $classPath -Name "1" -Value "{36fc9e60-c465-11cf-8056-444553540000}"

Write-Host "[+] USB storage access restricted"
```

### USB Device Whitelist

```bash
#!/bin/bash
#######################################
# USB Device Whitelist (Linux)
# Only allow authorized USB devices
#######################################

WHITELIST_FILE="/etc/udev/rules.d/99-usb-whitelist.rules"

cat > "$WHITELIST_FILE" << 'EOF'
# USB Device Whitelist
# Default: Deny all USB devices

# Allow specific keyboards (example)
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="046d", ATTR{idProduct}=="c52b", GOTO="usb_allowed"

# Allow specific mice (example)
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="046d", ATTR{idProduct}=="c534", GOTO="usb_allowed"

# Allow USB hubs
ACTION=="add", SUBSYSTEM=="usb", ATTR{bDeviceClass}=="09", GOTO="usb_allowed"

# Deny everything else
ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c 'echo 0 > /sys/$devpath/authorized'"
GOTO="usb_end"

LABEL="usb_allowed"
# Device is allowed, do nothing special

LABEL="usb_end"
EOF

udevadm control --reload-rules
echo "[+] USB whitelist applied"
```

---

## PowerShell Hardening

### Constrained Language Mode

```powershell
#######################################
# Enable PowerShell Constrained Mode
#######################################

# Set system-wide via Group Policy or registry
$path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
Set-ItemProperty -Path $path -Name "__PSLockdownPolicy" -Value 4

# Verify mode
$ExecutionContext.SessionState.LanguageMode
# Should return: ConstrainedLanguage
```

### PowerShell Logging Configuration

```powershell
#######################################
# Enable Comprehensive PowerShell Logging
#######################################

# Script Block Logging
$logPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $logPath -Force | Out-Null
Set-ItemProperty -Path $logPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $logPath -Name "EnableScriptBlockInvocationLogging" -Value 1

# Module Logging
$modPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $modPath -Force | Out-Null
Set-ItemProperty -Path $modPath -Name "EnableModuleLogging" -Value 1
New-Item -Path "$modPath\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$modPath\ModuleNames" -Name "*" -Value "*"

# Transcription
$transPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $transPath -Force | Out-Null
Set-ItemProperty -Path $transPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $transPath -Name "EnableInvocationHeader" -Value 1
Set-ItemProperty -Path $transPath -Name "OutputDirectory" -Value "C:\PSLogs"

# Create log directory
New-Item -Path "C:\PSLogs" -ItemType Directory -Force | Out-Null

Write-Host "[+] PowerShell logging configured"
```

### Execution Policy Hardening

```powershell
#######################################
# Set Strict Execution Policy
#######################################

# Require all scripts to be signed
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force

# Or more restrictive
Set-ExecutionPolicy Restricted -Scope LocalMachine -Force

# Note: These can be bypassed, so combine with AppLocker/WDAC
```

---

## Application Whitelisting

### AppLocker Configuration

```powershell
#######################################
# AppLocker Basic Configuration
#######################################

# Create default rules
$rules = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="Allow Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="Allow Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <!-- Deny scripts from user-writable locations -->
    <FilePathRule Id="a9e18c21-ff8f-43cf-b9fc-db64dbd89bb4" Name="Deny Temp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%TEMP%\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="Allow Windows Scripts" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

# Apply policy
Set-AppLockerPolicy -XmlPolicy $rules -Merge

# Start AppLocker service
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc
```

### Linux Application Control (fapolicyd)

```bash
#!/bin/bash
#######################################
# fapolicyd Setup (RHEL/CentOS/Fedora)
#######################################

# Install
dnf install -y fapolicyd

# Configure rules
cat > /etc/fapolicyd/rules.d/90-badusb-protection.rules << 'EOF'
# Deny execution from temp directories
deny perm=any all : dir=/tmp/
deny perm=any all : dir=/var/tmp/
deny perm=any all : dir=/dev/shm/

# Deny execution from user home (customize as needed)
deny perm=execute all : dir=/home/

# Allow system binaries
allow perm=any all : dir=/usr/
allow perm=any all : dir=/lib/
allow perm=any all : dir=/lib64/
EOF

# Enable and start
systemctl enable fapolicyd
systemctl start fapolicyd

echo "[+] Application whitelisting enabled"
```

---

## System Hardening Script

### Comprehensive Linux Hardening

```bash
#!/bin/bash
#######################################
# Linux System Hardening Script
# Focus on BadUSB attack prevention
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_ok() { echo -e "${GREEN}[+]${NC} $1"; }
log_info() { echo -e "[*] $1"; }

echo "════════════════════════════════════════════════════"
echo "         Linux Security Hardening"
echo "════════════════════════════════════════════════════"
echo ""

# 1. Disable USB storage
log_info "Disabling USB storage..."
echo "blacklist usb-storage" > /etc/modprobe.d/disable-usb-storage.conf
echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-usb-storage.conf
log_ok "USB storage disabled"

# 2. Set secure permissions on /tmp
log_info "Securing /tmp..."
if ! grep -q "/tmp.*noexec" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi
mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null
log_ok "/tmp mounted with noexec"

# 3. Enable audit logging
log_info "Configuring audit rules..."
cat >> /etc/audit/rules.d/badusb.rules << 'EOF'
# Monitor USB device connections
-w /dev/bus/usb -p wa -k usb_device

# Monitor execution from temp
-w /tmp -p x -k temp_exec
-w /var/tmp -p x -k temp_exec

# Monitor cron changes
-w /etc/crontab -p wa -k cron_mod
-w /etc/cron.d -p wa -k cron_mod
-w /var/spool/cron -p wa -k cron_mod

# Monitor user/group changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
EOF
augenrules --load 2>/dev/null
log_ok "Audit rules configured"

# 4. Disable unnecessary services
log_info "Disabling unnecessary services..."
DISABLE_SERVICES="cups bluetooth avahi-daemon"
for svc in $DISABLE_SERVICES; do
    systemctl disable "$svc" 2>/dev/null
    systemctl stop "$svc" 2>/dev/null
done
log_ok "Unnecessary services disabled"

# 5. Configure password policies
log_info "Configuring password policies..."
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
fi
log_ok "Password policies configured"

# 6. Secure SSH
log_info "Hardening SSH..."
if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    systemctl reload sshd 2>/dev/null
fi
log_ok "SSH hardened"

# 7. Set up fail2ban
log_info "Configuring fail2ban..."
if command -v fail2ban-client &>/dev/null; then
    systemctl enable fail2ban
    systemctl start fail2ban
    log_ok "fail2ban enabled"
else
    log_info "fail2ban not installed"
fi

# 8. Kernel hardening
log_info "Applying kernel hardening..."
cat >> /etc/sysctl.d/99-security.conf << 'EOF'
# Disable IP forwarding
net.ipv4.ip_forward = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0

# Enable SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable core dumps
fs.suid_dumpable = 0

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict ptrace
kernel.yama.ptrace_scope = 2
EOF
sysctl -p /etc/sysctl.d/99-security.conf 2>/dev/null
log_ok "Kernel parameters hardened"

echo ""
echo "════════════════════════════════════════════════════"
echo "         Hardening Complete"
echo "════════════════════════════════════════════════════"
echo ""
echo "Recommendations:"
echo "  - Reboot to apply all changes"
echo "  - Review and test USB whitelist"
echo "  - Configure centralized logging"
echo "  - Enable SELinux/AppArmor"
```

---

## Windows Hardening

### Windows Hardening Script

```powershell
#######################################
# Windows Security Hardening
# Run as Administrator
#######################################

Write-Host "═══════════════════════════════════════════════════"
Write-Host "         Windows Security Hardening"
Write-Host "═══════════════════════════════════════════════════"
Write-Host ""

# 1. Disable USB storage
Write-Host "[*] Disabling USB storage..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
Write-Host "[+] USB storage disabled"

# 2. Enable Windows Defender Attack Surface Reduction
Write-Host "[*] Enabling ASR rules..."
$asrRules = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1  # Block executable content from email
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1  # Block Office applications from creating child processes
    "3B576869-A4EC-4529-8536-B80A7769E899" = 1  # Block Office from creating executable content
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1  # Block Office from injecting code
    "D3E037E1-3EB8-44C8-A917-57927947596D" = 1  # Block JavaScript or VBScript from launching
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1  # Block execution of obfuscated scripts
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1  # Block Win32 API calls from Office macro
}

foreach ($rule in $asrRules.GetEnumerator()) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value
}
Write-Host "[+] ASR rules enabled"

# 3. Enable Credential Guard
Write-Host "[*] Enabling Credential Guard..."
$cgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-ItemProperty -Path $cgPath -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path $cgPath -Name "RequirePlatformSecurityFeatures" -Value 3
Write-Host "[+] Credential Guard enabled (reboot required)"

# 4. Disable PowerShell v2
Write-Host "[*] Disabling PowerShell v2..."
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Write-Host "[+] PowerShell v2 disabled"

# 5. Enable audit policies
Write-Host "[*] Configuring audit policies..."
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Process Tracking" /success:enable /failure:enable
Write-Host "[+] Audit policies configured"

# 6. Enable process command line auditing
Write-Host "[*] Enabling command line auditing..."
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
Write-Host "[+] Command line auditing enabled"

# 7. Disable AutoRun
Write-Host "[*] Disabling AutoRun..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
Write-Host "[+] AutoRun disabled"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════"
Write-Host "         Hardening Complete"
Write-Host "═══════════════════════════════════════════════════"
Write-Host ""
Write-Host "Please reboot to apply all changes."
```

---

## Hardening Verification

### Verify Hardening Script

```bash
#!/bin/bash
#######################################
# Hardening Verification
#######################################

PASS=0
FAIL=0

check() {
    if eval "$2" &>/dev/null; then
        echo "[PASS] $1"
        ((PASS++))
    else
        echo "[FAIL] $1"
        ((FAIL++))
    fi
}

echo "═══════════════════════════════════════════════════"
echo "         Hardening Verification"
echo "═══════════════════════════════════════════════════"
echo ""

# USB checks
check "USB storage module blocked" "! lsmod | grep -q usb_storage"
check "/tmp mounted noexec" "mount | grep '/tmp' | grep -q noexec"

# Audit checks
check "Audit daemon running" "systemctl is-active auditd"

# SSH checks
check "SSH root login disabled" "grep -q 'PermitRootLogin no' /etc/ssh/sshd_config"

# Kernel checks
check "IP forwarding disabled" "[ $(sysctl -n net.ipv4.ip_forward) -eq 0 ]"
check "SYN cookies enabled" "[ $(sysctl -n net.ipv4.tcp_syncookies) -eq 1 ]"

echo ""
echo "═══════════════════════════════════════════════════"
echo "         Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════"
```

---

[← Back to Security Operations](../README.md)
