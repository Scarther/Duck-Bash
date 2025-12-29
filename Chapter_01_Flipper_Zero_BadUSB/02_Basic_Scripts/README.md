# Basic Level Scripts (FZ-B01 to FZ-B15)

## Overview

Basic level scripts are your foundation. They teach fundamental DuckyScript concepts through simple, visible, and non-destructive examples.

### Skill Level Characteristics
- **Code Length**: 5-20 lines
- **Purpose**: Single action
- **Visibility**: Obvious execution (user can see what happened)
- **Risk**: Non-destructive
- **Timing**: Fixed delays

---

## Payload Index

| ID | Name | Target | Description | Status |
|----|------|--------|-------------|--------|
| [FZ-B01](FZ-B01_Hello_World.md) | Hello World - Windows | Windows | Open Notepad, type message | Complete |
| [FZ-B02](FZ-B02_Hello_World_macOS.md) | Hello World - macOS | macOS | Open TextEdit via Spotlight | Complete |
| [FZ-B03](FZ-B03_Hello_World_Linux.md) | Hello World - Linux | Linux | Open terminal, echo message | Complete |
| [FZ-B04](FZ-B04_Display_IP.md) | Display IP Address | Windows | Show IP in CMD | Complete |
| [FZ-B05](FZ-B05_Open_Website.md) | Open Website | Windows | Launch default browser to URL | Complete |
| [FZ-B06](FZ-B06_Lock_Workstation.md) | Lock Workstation | Windows | Lock screen immediately | Complete |
| [FZ-B07](FZ-B07_Screenshot.md) | Screenshot Capture | Windows | Capture screen to Paint | Complete |
| [FZ-B08](FZ-B08_Text_to_Speech.md) | Text-to-Speech | Windows | Computer speaks message | Complete |
| [FZ-B09](FZ-B09_Volume_Control.md) | Volume Control | Cross-Platform | Toggle mute | Complete |
| [FZ-B10](FZ-B10_Create_Desktop_File.md) | Create Desktop File | Windows | Create text file on desktop | Complete |

---

## Learning Objectives

After completing all Basic scripts, you should be able to:

- [ ] Write a payload from scratch using REM, DELAY, STRING, ENTER
- [ ] Understand timing and why delays are necessary
- [ ] Use GUI shortcuts (Win+R, Win+L, etc.)
- [ ] Adapt scripts for Windows, macOS, and Linux
- [ ] Test payloads safely in a lab environment

---

## Recommended Learning Order

```
Day 1: FZ-B01, FZ-B02, FZ-B03
       └── Hello World across all platforms
       └── Understand platform differences

Day 2: FZ-B04, FZ-B05, FZ-B06
       └── Practical shortcuts
       └── Run dialog variations

Day 3: FZ-B07, FZ-B08, FZ-B09, FZ-B10
       └── Media keys and system interaction
       └── File creation basics
```

---

## Quick Reference: Commands Used

| Command | Used In | Purpose |
|---------|---------|---------|
| REM | All | Comments |
| DELAY | All | Timing |
| GUI r | B01,B04,B05,B07,B08,B10 | Windows Run dialog |
| GUI SPACE | B02 | macOS Spotlight |
| GUI l | B06 | Lock workstation |
| CTRL ALT t | B03 | Linux terminal |
| STRING | All | Type text |
| STRINGLN | B03 | Type text + Enter |
| ENTER | Most | Press Enter |
| PRINTSCREEN | B07 | Screenshot |
| MEDIA MUTE | B09 | Audio control |

---

[← Back to Chapter 1](../README.md) | [Next: FZ-B01 Hello World →](FZ-B01_Hello_World.md)
