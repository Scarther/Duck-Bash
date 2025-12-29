# Basic Level CTF Scenarios

## Overview

These Capture The Flag (CTF) scenarios are designed to run on a local Linux machine without internet connectivity. Each scenario simulates real-world BadUSB attack patterns at a beginner level.

---

## How CTF Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CTF WORKFLOW                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. RED TEAM runs attack script (simulates BadUSB)                  │
│     └── Creates artifacts, hides flags                              │
│                                                                      │
│  2. BLUE TEAM investigates the system                               │
│     └── Uses detection scripts and manual analysis                  │
│                                                                      │
│  3. BLUE TEAM finds FLAGS                                           │
│     └── Flags are strings like: FLAG{example_flag_here}             │
│                                                                      │
│  4. Submit flags to verify success                                  │
│     └── Run verify_flags.sh with found flags                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Scenario 01: The Hidden Message

### Background
A user reported their computer acting strangely - the terminal opened briefly and closed. You suspect a BadUSB attack occurred.

### Objective
Find the flag left behind by the attacker.

### Setup
```bash
# Run as Red Team to set up the scenario
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/01_Basic/Practice/
sudo ./red_team/B01_hidden_message_setup.sh
```

### Blue Team Tasks
1. Check for recently modified files in common locations
2. Look for hidden files in the user's home directory
3. Examine temp directories
4. Find the flag

### Hints
<details>
<summary>Hint 1</summary>
BadUSB often writes to /tmp or the user's home directory
</details>

<details>
<summary>Hint 2</summary>
Use `find` with `-mmin` to find recently modified files
</details>

<details>
<summary>Hint 3</summary>
Check for hidden files with `ls -la`
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Find recently modified files
find /tmp -mmin -60 -type f 2>/dev/null

# Check for hidden files
ls -la ~/
ls -la /tmp/

# The flag is in a hidden file
cat /tmp/.badusb_was_here
# or
cat ~/.hidden_payload_output
```
</details>

---

## Scenario 02: Process Hunter

### Background
You noticed unusual CPU activity after a USB device was connected. Find evidence of what ran.

### Objective
Identify the suspicious process that was executed and find the flag.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/01_Basic/Practice/
sudo ./red_team/B02_process_hunter_setup.sh
```

### Blue Team Tasks
1. Check bash history for executed commands
2. Look for log files created by the "attack"
3. Examine process artifacts
4. Find the flag hidden in the evidence

### Hints
<details>
<summary>Hint 1</summary>
Check ~/.bash_history or use `history` command
</details>

<details>
<summary>Hint 2</summary>
Look in /var/log/ for custom log files
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Check command history
cat ~/.bash_history | tail -20

# Check for suspicious log files
ls -la /var/log/ | grep -v "^d"

# Find the evidence
cat /var/log/usb_activity.log
```
</details>

---

## Scenario 03: The Scheduled Surprise

### Background
A maintenance technician plugged in a USB device "to update drivers." Now there's a suspicious scheduled task.

### Objective
Find the persistence mechanism and the flag.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/01_Basic/Practice/
sudo ./red_team/B03_scheduled_surprise_setup.sh
```

### Blue Team Tasks
1. Check crontab for the current user
2. Check system crontabs
3. Look for suspicious scripts in common locations
4. Find and decode the flag

### Hints
<details>
<summary>Hint 1</summary>
Use `crontab -l` to list user crontabs
</details>

<details>
<summary>Hint 2</summary>
Check /etc/cron.d/ and /var/spool/cron/
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# List user crontab
crontab -l

# Check system crontabs
ls -la /etc/cron.d/
cat /etc/cron.d/system_update 2>/dev/null

# Find the script it references
cat /tmp/.system_update.sh

# The flag is base64 encoded in the script
echo "RkxBR3tiYXNpY19wZXJzaXN0ZW5jZV9mb3VuZH0=" | base64 -d
```
</details>

---

## Scenario 04: Data Exfil Basics

### Background
Sensitive files may have been copied. Find evidence of data staging.

### Objective
Locate the staged data and find the flag.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/01_Basic/Practice/
sudo ./red_team/B04_data_exfil_setup.sh
```

### Blue Team Tasks
1. Look for archive files (.zip, .tar, .gz) in temp locations
2. Check for data staging directories
3. Find compressed or encoded data
4. Extract the flag

### Hints
<details>
<summary>Hint 1</summary>
Use `find / -name "*.zip" -o -name "*.tar.gz" 2>/dev/null`
</details>

<details>
<summary>Hint 2</summary>
Check /tmp, /var/tmp, and hidden directories
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Find archives
find /tmp -name "*.tar.gz" -o -name "*.zip" 2>/dev/null

# Extract and examine
cd /tmp
tar -xzf .staged_data.tar.gz
cat staged_data/flag.txt
```
</details>

---

## Scenario 05: The USB Detective

### Background
Multiple USB devices were connected today. Determine which one is suspicious.

### Objective
Analyze USB connection history and find the flag related to the malicious device.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/01_Basic/Practice/
sudo ./red_team/B05_usb_detective_setup.sh
```

### Blue Team Tasks
1. Check dmesg for USB device connections
2. Look at /var/log/syslog or journalctl for USB events
3. Identify the suspicious device (unusual VID/PID)
4. Find the flag associated with the device

### Hints
<details>
<summary>Hint 1</summary>
Use `dmesg | grep -i usb` to see USB messages
</details>

<details>
<summary>Hint 2</summary>
Known BadUSB VID/PID: 0483:5740 (Flipper Zero)
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Check USB history
dmesg | grep -i "usb\|hid" | tail -50

# Check for simulated log
cat /var/log/usb_forensics.log

# The flag is in the log entry for the suspicious device
grep "FLAG" /var/log/usb_forensics.log
```
</details>

---

## Scoring

| Scenario | Points | Difficulty |
|----------|--------|------------|
| 01 - Hidden Message | 100 | Easy |
| 02 - Process Hunter | 100 | Easy |
| 03 - Scheduled Surprise | 150 | Easy-Medium |
| 04 - Data Exfil Basics | 150 | Easy-Medium |
| 05 - USB Detective | 200 | Medium |

**Total Possible: 700 points**

---

## Cleanup

After completing the scenarios, clean up:

```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/01_Basic/Practice/
sudo ./cleanup_all.sh
```

---

[← Back to Basic Level](../README.md)
