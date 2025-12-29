# Chapter 01: Flipper Zero BadUSB - Assessment Quiz

## Instructions
- Choose the best answer for each question
- Answers are provided at the end
- Passing score: 70% (14/20 correct)

---

## Section A: Fundamentals (5 questions)

### Q1. What does USB HID stand for?
- A) Universal Serial Bus Hardware Interface Device
- B) Universal Serial Bus Human Interface Device
- C) USB Hardware Input Driver
- D) USB Host Interface Driver

### Q2. What is the primary attack vector BadUSB exploits?
- A) USB mass storage vulnerabilities
- B) Trusted relationship between computers and keyboards
- C) USB firmware bugs
- D) Driver installation exploits

### Q3. Which DuckyScript command is used to press the Windows key?
- A) `WINDOWS`
- B) `WIN`
- C) `GUI`
- D) `META`

### Q4. What is the default delay measurement unit in DuckyScript?
- A) Seconds
- B) Milliseconds
- C) Microseconds
- D) Minutes

### Q5. Which command types text character by character?
- A) `TYPE`
- B) `PRINT`
- C) `STRING`
- D) `WRITE`

---

## Section B: Scripting (5 questions)

### Q6. What does this payload do?
```
GUI r
DELAY 500
STRING notepad
ENTER
```
- A) Opens Notepad on Windows
- B) Opens Run dialog on macOS
- C) Creates a new file
- D) Opens Terminal on Linux

### Q7. Which command simulates pressing Enter?
- A) `RETURN`
- B) `ENTER`
- C) `NEWLINE`
- D) Both A and B

### Q8. What timing issue is most common with BadUSB payloads?
- A) Delays are too long
- B) Delays are too short for the target system
- C) Keyboard repeat rate is wrong
- D) USB enumeration fails

### Q9. In DuckyScript 3.0, how do you define a variable?
- A) `SET $var = value`
- B) `VAR $var = value`
- C) `DEFINE $var value`
- D) `LET $var = value`

### Q10. What is a "staged" payload?
- A) A payload that downloads and executes additional code
- B) A payload split across multiple files
- C) A payload that runs in phases with user interaction
- D) A payload tested in a staging environment

---

## Section C: Attack Techniques (5 questions)

### Q11. What MITRE ATT&CK technique ID corresponds to "Replication Through Removable Media"?
- A) T1200
- B) T1091
- C) T1059
- D) T1547

### Q12. Which Windows key combination opens an admin PowerShell from the Power User menu?
- A) Win+X, then A
- B) Win+R, then type "powershell"
- C) Ctrl+Alt+P
- D) Win+Shift+Enter

### Q13. What is the purpose of using `-w hidden` in a PowerShell command?
- A) Run without logging
- B) Run without a visible window
- C) Run with elevated privileges
- D) Run without network access

### Q14. Which persistence mechanism uses `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`?
- A) Service persistence
- B) Scheduled task persistence
- C) Registry Run key persistence
- D) WMI persistence

### Q15. What is "exfiltration" in the context of BadUSB attacks?
- A) Injecting code into processes
- B) Stealing and transmitting data
- C) Escalating privileges
- D) Evading detection

---

## Section D: Defense (5 questions)

### Q16. Which Windows Event ID indicates USB device connection?
- A) 4624
- B) 4688
- C) 2003
- D) 7045

### Q17. What is the purpose of USB device whitelisting?
- A) Speed up USB connections
- B) Only allow approved USB devices
- C) Encrypt USB traffic
- D) Log USB activity

### Q18. Which tool provides detailed PowerShell script logging?
- A) Process Monitor
- B) Script Block Logging
- C) Autoruns
- D) USBDeview

### Q19. What Sysmon Event ID captures process creation?
- A) Event ID 1
- B) Event ID 3
- C) Event ID 7
- D) Event ID 11

### Q20. Which is the MOST effective control against BadUSB attacks?
- A) Antivirus software
- B) USB port blockers combined with device whitelisting
- C) User training alone
- D) Firewall rules

---

## Answer Key

<details>
<summary>Click to reveal answers</summary>

| Question | Answer | Explanation |
|----------|--------|-------------|
| Q1 | B | HID = Human Interface Device |
| Q2 | B | BadUSB exploits the implicit trust computers have in keyboards |
| Q3 | C | GUI is the DuckyScript command for the Windows/Command key |
| Q4 | B | DELAY uses milliseconds |
| Q5 | C | STRING types characters |
| Q6 | A | Opens Run dialog and types "notepad" to open Notepad |
| Q7 | D | Both RETURN and ENTER work |
| Q8 | B | Fast systems often complete operations before the next command |
| Q9 | B | VAR is used to define variables in DuckyScript 3.0 |
| Q10 | A | Staged payloads download additional code from a server |
| Q11 | B | T1091 is Replication Through Removable Media |
| Q12 | A | Win+X opens Power User menu, A selects Admin PowerShell |
| Q13 | B | -w hidden hides the PowerShell window |
| Q14 | C | Registry Run keys auto-start programs at login |
| Q15 | B | Exfiltration is stealing and transmitting data |
| Q16 | C | Event ID 2003 in DriverFrameworks-UserMode log |
| Q17 | B | Whitelisting only allows approved devices |
| Q18 | B | PowerShell Script Block Logging captures script content |
| Q19 | A | Sysmon Event ID 1 is Process Creation |
| Q20 | B | Physical and policy controls are most effective |

**Passing Score: 14/20 (70%)**

</details>

---

## Scoring

- **18-20 correct**: Expert level - Ready for advanced topics
- **14-17 correct**: Proficient - Good understanding, review weak areas
- **10-13 correct**: Developing - Review fundamentals before proceeding
- **Below 10**: Needs improvement - Re-study Chapter 01 material

---

[← Back to Assessments](./README.md) | [Chapter 02 Quiz →](./Chapter_02_Quiz.md)
