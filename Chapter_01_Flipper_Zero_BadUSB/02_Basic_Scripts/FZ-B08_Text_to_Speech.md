# FZ-B08: Text-to-Speech - Windows

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B08 |
| **Name** | Text-to-Speech |
| **Difficulty** | Basic |
| **Target OS** | Windows 10/11 |
| **Execution Time** | ~5 seconds + speech |

## What This Payload Does

Makes the computer speak a message aloud using Windows' built-in Speech Synthesizer API.

---

## The Payload

```ducky
REM =============================================
REM BASIC: Text-to-Speech
REM Target: Windows
REM Action: Computer speaks message aloud
REM Skill: Basic
REM =============================================

DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('I am your computer. I have become sentient.')"
ENTER
```

---

## How It Works

```
PowerShell Command Breakdown:

Add-Type -AssemblyName System.Speech
  └── Loads the .NET Speech library

New-Object System.Speech.Synthesis.SpeechSynthesizer
  └── Creates a new speech synthesizer object

.Speak('message')
  └── Speaks the message aloud

-w hidden
  └── Hides the PowerShell window
```

---

## Variations

### Change the Message
```ducky
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('Your custom message here')"
```

### Speak Multiple Sentences
```ducky
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.Speak('First sentence.'); Start-Sleep 1; $s.Speak('Second sentence.')"
```

### Change Voice Rate (Speed)
```ducky
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.Rate = 3; $s.Speak('This is spoken very fast')"
```
Rate: -10 (slowest) to 10 (fastest), 0 is default.

### Change Volume
```ducky
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.Volume = 100; $s.Speak('Maximum volume!')"
```
Volume: 0 (silent) to 100 (loudest).

---

## Fun/Prank Messages

```ducky
REM Matrix style
STRING "I know what you did last summer."

REM IT Department
STRING "Please contact your IT department. Your computer has been compromised."

REM Friendly
STRING "Hello! I am Flipper Zero. Nice to meet you!"

REM Countdown
STRING "Self destruct sequence initiated. 10. 9. 8. Just kidding."
```

---

## Cross-Platform Versions

### macOS (say command)
```ducky
DELAY 2000
GUI SPACE
DELAY 700
STRING terminal
ENTER
DELAY 1500
STRINGLN say "Hello from Flipper Zero"
```

macOS has the `say` command built-in - much simpler!

### Linux (espeak)
```ducky
DELAY 2000
CTRL ALT t
DELAY 1000
STRINGLN espeak "Hello from Flipper Zero" 2>/dev/null || spd-say "Hello from Flipper Zero"
```

Note: Requires `espeak` or `speech-dispatcher` to be installed.

---

## Red Team Perspective

### Use Cases
- Distraction while other payload runs
- Social engineering (fake IT messages)
- Proof of concept for physical access
- Awareness training demonstrations

### Example: Distraction Technique
```ducky
REM Speech creates noise/distraction
REM While hidden payload runs
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('System update in progress. Please wait.'); Start-Process powershell -ArgumentList '-w hidden -c Get-ComputerInfo | Out-File $env:TEMP\info.txt' -WindowStyle Hidden"
ENTER
```

---

## Blue Team Perspective

### Detection
- PowerShell loading System.Speech assembly
- Unusual audio output
- PowerShell with hidden window + speech

### Monitoring
```powershell
# Check PowerShell logs for speech synthesis
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    StartTime=(Get-Date).AddHours(-1)
} | Where-Object { $_.Message -match 'System.Speech' }
```

### User Education
"If your computer starts talking unexpectedly, especially with IT-sounding messages, be suspicious!"

---

## Practice Exercises

### Exercise 1: Custom Message
Make the computer say your name.

### Exercise 2: Speed Variation
Create three versions:
- Slow (Rate = -5)
- Normal (Rate = 0)
- Fast (Rate = 5)

### Exercise 3: Countdown
Make the computer count down from 5 to 1.

```ducky
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; 5..1 | ForEach-Object { $s.Speak($_); Start-Sleep 1 }; $s.Speak('Blast off!')"
```

---

## Payload File

Save as `FZ-B08_Text_to_Speech.txt`:

```ducky
REM FZ-B08: Text-to-Speech
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -c "Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('I am your computer. I have become sentient.')"
ENTER
```

---

[← FZ-B07 Screenshot](FZ-B07_Screenshot.md) | [Next: FZ-B09 Volume Control →](FZ-B09_Volume_Control.md)
