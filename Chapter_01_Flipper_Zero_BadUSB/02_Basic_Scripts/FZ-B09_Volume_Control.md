# FZ-B09: Volume Control - Cross Platform

## Overview

| Property | Value |
|----------|-------|
| **ID** | FZ-B09 |
| **Name** | Volume Control |
| **Difficulty** | Basic |
| **Target OS** | Windows, macOS, Linux |
| **Execution Time** | <1 second |

## What This Payload Does

Uses media keys to control system volume. This demonstrates Flipper Zero's ability to send media key commands.

---

## The Payload

```ducky
REM =============================================
REM BASIC: Mute System Audio
REM Target: Windows/macOS/Linux
REM Action: Toggles mute using media keys
REM Skill: Basic
REM =============================================

DELAY 1000
MEDIA MUTE
```

---

## Media Key Commands

Flipper Zero supports all standard media keys:

| Command | Action |
|---------|--------|
| MEDIA MUTE | Toggle mute |
| MEDIA VOLUMEUP | Increase volume |
| MEDIA VOLUMEDOWN | Decrease volume |
| MEDIA PLAYPAUSE | Play/Pause media |
| MEDIA STOP | Stop playback |
| MEDIA NEXT | Next track |
| MEDIA PREV | Previous track |

---

## Variations

### Mute On/Off Toggle
```ducky
DELAY 1000
MEDIA MUTE
```

### Volume Up (Multiple)
```ducky
DELAY 1000
MEDIA VOLUMEUP
MEDIA VOLUMEUP
MEDIA VOLUMEUP
MEDIA VOLUMEUP
MEDIA VOLUMEUP
```
Or use REPEAT:
```ducky
DELAY 1000
MEDIA VOLUMEUP
REPEAT 10
```

### Volume Down (Multiple)
```ducky
DELAY 1000
MEDIA VOLUMEDOWN
REPEAT 10
```

### Maximum Volume Prank
```ducky
REM Warning: This is LOUD
DELAY 1000
MEDIA MUTE
DELAY 100
MEDIA MUTE
DELAY 100
MEDIA VOLUMEUP
REPEAT 50
```

### Pause Music
```ducky
DELAY 1000
MEDIA PLAYPAUSE
```

### Skip Track
```ducky
DELAY 1000
MEDIA NEXT
```

---

## Why This Is Cross-Platform

Media keys are standardized across operating systems:
- Windows: Built-in support
- macOS: Built-in support
- Linux: Works with most desktop environments

No need for different versions!

---

## Combining with Other Actions

### Mute + Text-to-Speech
```ducky
REM First mute any playing audio
DELAY 1000
MEDIA MUTE
DELAY 500

REM Then speak
GUI r
DELAY 500
STRING powershell -c "Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('Attention please')"
ENTER
```

### Max Volume + Rick Roll
```ducky
REM Volume up
DELAY 1000
MEDIA VOLUMEUP
REPEAT 20
DELAY 500

REM Open Rick Roll
GUI r
DELAY 500
STRING https://www.youtube.com/watch?v=dQw4w9WgXcQ
ENTER
```

---

## Red Team Perspective

### Use Cases
- Distraction (sudden volume change)
- Ensure speech is heard (max volume before speaking)
- Stealth (mute before actions that make sounds)
- Cover presence (pause media that might reveal USB insertion)

### Stealth Considerations
```ducky
REM Mute before any noisy operations
DELAY 1000
MEDIA MUTE

REM Now do something that might make Windows sounds
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
```

---

## Blue Team Perspective

### Detection Difficulty
Media key presses are nearly impossible to distinguish from normal use:
- No processes spawned
- No files created
- No network activity
- Looks like user pressing keyboard

### The Lesson
This demonstrates how USB HID attacks can perform actions that are:
- Instant
- Invisible
- Undetectable

Prevention is key - block unauthorized USB devices.

---

## Practice Exercises

### Exercise 1: Volume Sequence
Create a payload that:
1. Mutes
2. Waits 2 seconds
3. Unmutes

```ducky
DELAY 1000
MEDIA MUTE
DELAY 2000
MEDIA MUTE
```

### Exercise 2: Media Control
Control a media player:
1. Pause current track
2. Wait 3 seconds
3. Play again

```ducky
DELAY 1000
MEDIA PLAYPAUSE
DELAY 3000
MEDIA PLAYPAUSE
```

### Exercise 3: Full Demo
Volume down, then up:
```ducky
DELAY 1000
MEDIA VOLUMEDOWN
REPEAT 10
DELAY 1000
MEDIA VOLUMEUP
REPEAT 10
```

---

## Payload Files

### Mute Toggle
Save as `FZ-B09_Volume_Mute.txt`:
```ducky
REM FZ-B09: Volume Mute Toggle
DELAY 1000
MEDIA MUTE
```

### Volume Up
Save as `FZ-B09_Volume_Up.txt`:
```ducky
REM FZ-B09: Volume Up
DELAY 1000
MEDIA VOLUMEUP
REPEAT 10
```

### Volume Down
Save as `FZ-B09_Volume_Down.txt`:
```ducky
REM FZ-B09: Volume Down
DELAY 1000
MEDIA VOLUMEDOWN
REPEAT 10
```

---

[← FZ-B08 Text-to-Speech](FZ-B08_Text_to_Speech.md) | [Next: FZ-B10 Create Desktop File →](FZ-B10_Create_Desktop_File.md)
