# FZ-B10: Create Desktop File - Windows

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B10 |
| **Name** | Create Desktop File |
| **Difficulty** | Basic |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~3 seconds |

## What This Payload Does

Creates a text file on the user's Desktop using a single command-line command. Demonstrates file creation without PowerShell.

---

## The Payload

```ducky
REM =============================================
REM BASIC: Create Text File on Desktop
REM Target: Windows
REM Action: Creates readme.txt on desktop
REM Skill: Basic
REM =============================================

DELAY 2000
GUI r
DELAY 500
STRING cmd /c echo Security Awareness Test > %USERPROFILE%\Desktop\readme.txt
ENTER
```

---

## How It Works

```
cmd /c echo Security Awareness Test > %USERPROFILE%\Desktop\readme.txt

cmd /c         = Run command and close CMD window
echo           = Output text
>              = Redirect output to file (overwrites)
%USERPROFILE%  = Current user's home folder (e.g., C:\Users\John)
\Desktop\      = Desktop folder
readme.txt     = Filename to create
```

---

## Variations

### Append to File (>>)
```ducky
STRING cmd /c echo Line 1 >> %USERPROFILE%\Desktop\log.txt
```
Using `>>` appends instead of overwriting.

### Multiple Lines
```ducky
STRING cmd /c echo Line 1 > %USERPROFILE%\Desktop\message.txt && echo Line 2 >> %USERPROFILE%\Desktop\message.txt
```

### With Date/Time
```ducky
STRING cmd /c echo Test at %DATE% %TIME% > %USERPROFILE%\Desktop\timestamp.txt
```

### Different Locations
```ducky
REM Documents folder
STRING cmd /c echo Test > %USERPROFILE%\Documents\test.txt

REM Temp folder
STRING cmd /c echo Test > %TEMP%\test.txt

REM Current directory
STRING cmd /c echo Test > test.txt
```

---

## Using PowerShell Instead

### Simple File Creation
```ducky
STRING powershell -c "'Your message' | Out-File $env:USERPROFILE\Desktop\message.txt"
```

### Multiple Lines
```ducky
STRING powershell -c "@'
Line 1
Line 2
Line 3
'@ | Out-File $env:USERPROFILE\Desktop\message.txt"
```

### With Formatting
```ducky
STRING powershell -c "'Timestamp: ' + (Get-Date) | Out-File $env:USERPROFILE\Desktop\log.txt"
```

---

## Cross-Platform Versions

### macOS
```ducky
DELAY 2000
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
STRINGLN echo "Security Awareness Test" > ~/Desktop/readme.txt
```

### Linux
```ducky
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN echo "Security Awareness Test" > ~/Desktop/readme.txt
```

---

## Red Team Perspective

### Use Cases
- Proof of access (leave a marker file)
- Drop configuration for later payloads
- Create decoy files
- Security awareness testing

### Marker File Technique
```ducky
REM Create timestamped marker
STRING cmd /c echo Access at %DATE% %TIME% by BadUSB > %USERPROFILE%\Desktop\ACCESSED.txt
```

This proves:
- Physical access was achieved
- Code execution was possible
- User's Desktop was accessible

### Dropping Payloads
```ducky
REM Create a script file for later
STRING powershell -c "'IEX(command)' | Out-File $env:TEMP\update.ps1"
```

---

## Blue Team Perspective

### Detection Opportunities
- New files appearing on Desktop
- Files created by cmd.exe from Run dialog
- Unusual file creation patterns

### Monitoring
```powershell
# Watch for new Desktop files
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "$env:USERPROFILE\Desktop"
$watcher.EnableRaisingEvents = $true

Register-ObjectEvent $watcher "Created" -Action {
    Write-Warning "New file on Desktop: $($Event.SourceEventArgs.FullPath)"
}
```

### File Creation Events
- Enable File System auditing
- Monitor Event ID 4663 (file access)
- Use Sysmon for detailed file creation logging

---

## Practice Exercises

### Exercise 1: Custom Message
Create a file with your name:
```ducky
STRING cmd /c echo Created by [Your Name] > %USERPROFILE%\Desktop\whoami.txt
```

### Exercise 2: Timestamped
Add date and time to the file:
```ducky
STRING cmd /c echo Access Time: %DATE% %TIME% > %USERPROFILE%\Desktop\access_log.txt
```

### Exercise 3: Hidden File
Create a hidden file:
```ducky
STRING cmd /c echo Hidden data > %USERPROFILE%\Desktop\.hidden.txt && attrib +h %USERPROFILE%\Desktop\.hidden.txt
```

### Exercise 4: Multiple Files
Create several files:
```ducky
DELAY 2000
GUI r
DELAY 500
STRING cmd /c echo File 1 > %USERPROFILE%\Desktop\file1.txt && echo File 2 > %USERPROFILE%\Desktop\file2.txt && echo File 3 > %USERPROFILE%\Desktop\file3.txt
ENTER
```

---

## Payload File

Save as `FZ-B10_Create_Desktop_File.txt`:

```ducky
REM FZ-B10: Create Desktop File
DELAY 2000
GUI r
DELAY 500
STRING cmd /c echo Security Awareness Test > %USERPROFILE%\Desktop\readme.txt
ENTER
```

---

## Summary: Basic Level Complete!

Congratulations! You've completed all 10 Basic level payloads:

| ID | Skill Learned |
|----|---------------|
| FZ-B01 | Notepad + STRING basics |
| FZ-B02 | macOS Spotlight |
| FZ-B03 | Linux terminal |
| FZ-B04 | Command filtering |
| FZ-B05 | URL handling |
| FZ-B06 | System shortcuts |
| FZ-B07 | Screenshot + clipboard |
| FZ-B08 | PowerShell + .NET |
| FZ-B09 | Media keys |
| FZ-B10 | File creation |

**Next:** [Intermediate Level Scripts](../03_Intermediate_Scripts/)

---

[← FZ-B09 Volume Control](FZ-B09_Volume_Control.md) | [Back to Basic Scripts](README.md) | [Next: Intermediate →](../03_Intermediate_Scripts/)
