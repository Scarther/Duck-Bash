# FZ-B05: Open Website - Windows

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B05 |
| **Name** | Open Website |
| **Difficulty** | Basic |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~3 seconds |

## What This Payload Does

Opens the default web browser to a specified URL using the Windows Run dialog.

---

## The Payload

```ducky
REM =============================================
REM BASIC: Open Website
REM Target: Windows
REM Action: Opens default browser to URL
REM Skill: Basic
REM =============================================

DELAY 2000
GUI r
DELAY 500
STRING https://example.com
ENTER
```

---

## Why This Works

Windows Run dialog recognizes:
- URLs (http://, https://)
- File paths (C:\...)
- Applications (notepad, calc)
- UNC paths (\\server\share)

When you type a URL, Windows automatically launches the default browser.

---

## Variations

### Open Specific Sites
```ducky
REM Open Google
STRING https://www.google.com

REM Open internal resource
STRING http://192.168.1.1

REM Open with specific browser (if installed)
STRING chrome https://example.com
STRING firefox https://example.com
STRING msedge https://example.com
```

### Rick Roll (Classic Prank)
```ducky
DELAY 2000
GUI r
DELAY 500
STRING https://www.youtube.com/watch?v=dQw4w9WgXcQ
ENTER
```

### Open Phishing Page (Red Team Testing)
```ducky
REM FOR AUTHORIZED TESTING ONLY
DELAY 2000
GUI r
DELAY 500
STRING https://your-phishing-server.com/login
ENTER
```

---

## Cross-Platform Versions

### macOS
```ducky
DELAY 2000
GUI SPACE
DELAY 700
STRING https://example.com
ENTER
```
Note: Spotlight recognizes URLs and opens Safari.

### Linux (GNOME)
```ducky
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN xdg-open https://example.com
```

---

## Red Team Perspective

### Use Cases
| Purpose | Example |
|---------|---------|
| Phishing | Redirect to credential harvester |
| Drive-by Download | Open page with exploit |
| Distraction | Create noise while other payload runs |
| Social Engineering | "IT needs you to visit this page" |

### Credential Harvesting Flow
```
1. Create fake login page (looks like O365, Google, etc.)
2. Payload opens browser to fake page
3. User enters credentials
4. Credentials captured to your server
5. User redirected to real site
```

---

## Blue Team Perspective

### Detection
- Browser launch from Run dialog
- Unusual URLs accessed
- Navigation to non-business sites

### Prevention
- Web content filtering
- DNS sinkholing
- Proxy with URL categorization

### Monitoring
```powershell
# Check browser history (example for Chrome)
$History = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
# Note: History is SQLite database
```

---

## Practice Exercises

### Exercise 1: Open Multiple Sites
Create a payload that opens 3 websites:
```ducky
DELAY 2000
GUI r
DELAY 500
STRING https://site1.com
ENTER
DELAY 1000
GUI r
DELAY 500
STRING https://site2.com
ENTER
```

### Exercise 2: Search Query
Open a Google search:
```ducky
STRING https://www.google.com/search?q=flipper+zero
```

### Exercise 3: Download File
Trigger a file download:
```ducky
STRING https://example.com/file.pdf
```

---

## Payload File

Save as `FZ-B05_Open_Website.txt`:

```ducky
REM FZ-B05: Open Website
DELAY 2000
GUI r
DELAY 500
STRING https://example.com
ENTER
```

---

[← FZ-B04 Display IP](FZ-B04_Display_IP.md) | [Next: FZ-B06 Lock Workstation →](FZ-B06_Lock_Workstation.md)
