# Intermediate Level Scripts (FZ-I01 to FZ-I15)

## Overview

Intermediate scripts introduce data collection, persistence, and hidden execution. You'll learn to extract information and maintain access.

### Skill Level Characteristics
- **Code Length**: 20-60 lines
- **Purpose**: Multiple sequential actions
- **Visibility**: Hidden execution (user doesn't see)
- **Risk**: Data extraction, persistence
- **Timing**: Calculated delays, error tolerance

---

## Payload Index

| ID | Name | Target | Description |
|----|------|--------|-------------|
| [FZ-I01](FZ-I01_System_Info_Collector.md) | System Info Collector | Windows | Full system enumeration |
| [FZ-I02](FZ-I02_WiFi_Password_Extractor.md) | WiFi Password Extractor | Windows | Extract saved WiFi passwords |
| [FZ-I03](FZ-I03_Browser_Data_Locator.md) | Browser Data Locator | Windows | Find browser credential paths |
| [FZ-I04](FZ-I04_Network_Reconnaissance.md) | Network Reconnaissance | Windows | Network mapping |
| [FZ-I05](FZ-I05_User_Enumeration.md) | User Enumeration | Windows | List users and groups |
| [FZ-I06](FZ-I06_Scheduled_Task_Persistence.md) | Scheduled Task Persistence | Windows | Create persistent task |
| [FZ-I07](FZ-I07_Download_Execute.md) | Download and Execute | Windows | Remote payload execution |
| [FZ-I08](FZ-I08_Clipboard_Capture.md) | Clipboard Capture | Windows | Steal clipboard contents |
| [FZ-I09](FZ-I09_Registry_Persistence.md) | Registry Persistence | Windows | Registry Run key |
| [FZ-I10](FZ-I10_macOS_Keychain.md) | macOS Keychain Query | macOS | Query keychain items |
| [FZ-I11](FZ-I11_Android_Recon.md) | Android Reconnaissance | Android | Android system info |
| [FZ-I12](FZ-I12_iOS_Shortcuts.md) | iOS Shortcuts Attack | iOS | Abuse iOS shortcuts |
| [FZ-I13](FZ-I13_Linux_Persistence.md) | Linux Persistence | Linux | Cron-based persistence |
| [FZ-I14](FZ-I14_Process_Enumeration.md) | Process Enumeration | Windows | List running processes |
| [FZ-I15](FZ-I15_Installed_Software.md) | Installed Software | Windows | Software inventory |

---

## Key Concepts Introduced

### Hidden Execution
```ducky
STRING powershell -w hidden
```
The `-w hidden` flag runs PowerShell without a visible window.

### Output to File
```ducky
STRINGLN ... | Out-File "$env:TEMP\output.txt"
```
Results are saved to files instead of displayed.

### USB Device Spoofing
```ducky
ID 046d:c52b Logitech:Unifying Receiver
```
Makes Flipper appear as a specific keyboard brand.

### Multi-line PowerShell
```ducky
STRINGLN $data = @()
STRINGLN $data += "Line 1"
STRINGLN $data += "Line 2"
STRINGLN $data | Out-File "file.txt"
```
Building complex data structures.

---

## Platform Coverage

| Platform | Payloads |
|----------|----------|
| Windows | FZ-I01 through FZ-I09, I14-I15 |
| macOS | FZ-I10 |
| Linux | FZ-I13 |
| Android | FZ-I11 |
| iOS | FZ-I12 |

---

## Learning Objectives

After completing Intermediate scripts:
- [ ] Hide PowerShell execution
- [ ] Extract WiFi credentials
- [ ] Enumerate network configuration
- [ ] Create basic persistence mechanisms
- [ ] Download and execute remote payloads
- [ ] Target mobile devices

---

## Red Team Focus

Intermediate scripts start real attack operations:
- **Reconnaissance**: Gathering target information
- **Credential Access**: Extracting passwords
- **Persistence**: Maintaining access
- **Collection**: Staging data for exfiltration

---

## Blue Team Focus

Detection becomes critical:
- Monitor for hidden PowerShell
- Watch for new scheduled tasks
- Alert on registry Run key changes
- Track file creation in temp directories

---

[← Basic Scripts](../02_Basic_Scripts/) | [Next: FZ-I01 System Info Collector →](FZ-I01_System_Info_Collector.md)
