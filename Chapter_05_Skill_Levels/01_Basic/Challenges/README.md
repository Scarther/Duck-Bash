# Basic Level Challenges

## Overview

These challenges test your understanding of basic DuckyScript and Bash concepts. Complete them to solidify your knowledge before moving to Intermediate level.

**Prerequisites**: Complete all lessons in Basic Ducky and Basic Bash folders.

---

## Challenge Format

Each challenge provides:
- **Objective**: What you need to accomplish
- **Requirements**: Specific constraints
- **Hints**: Help if you get stuck (try without first!)
- **Solution**: Available after attempting

---

## DuckyScript Challenges

### Challenge D1: The Customizer

**Difficulty**: Easy

**Objective**: Create a payload that opens Notepad and writes a personalized message.

**Requirements**:
1. Open Notepad
2. Type "Created by: [Your Name]"
3. Press Enter twice
4. Type "Date: [Today's Date]"
5. Press Enter twice
6. Type "This is my first custom payload!"

**Hints**:
<details>
<summary>Hint 1</summary>
Use GUI r to open Run dialog, then STRING notepad
</details>

<details>
<summary>Hint 2</summary>
Use ENTER to create new lines, multiple times for blank lines
</details>

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```ducky
REM Challenge D1: The Customizer
DELAY 2000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING Created by: [Your Name]
ENTER
ENTER
STRING Date: December 28, 2025
ENTER
ENTER
STRING This is my first custom payload!
```
</details>

---

### Challenge D2: The Calculator

**Difficulty**: Easy

**Objective**: Open Calculator, perform a calculation, then close it.

**Requirements**:
1. Open Windows Calculator
2. Type the numbers: 1337
3. Wait 3 seconds (so user can see it)
4. Close the calculator

**Hints**:
<details>
<summary>Hint 1</summary>
Calculator opens with: GUI r, STRING calc, ENTER
</details>

<details>
<summary>Hint 2</summary>
ALT F4 closes the active window
</details>

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```ducky
REM Challenge D2: The Calculator
DELAY 2000
GUI r
DELAY 500
STRING calc
ENTER
DELAY 1500
STRING 1337
DELAY 3000
ALT F4
```
</details>

---

### Challenge D3: The Multi-Tasker

**Difficulty**: Medium

**Objective**: Open multiple applications in sequence.

**Requirements**:
1. Open Notepad
2. Type "Window 1"
3. Open a second Notepad window
4. Type "Window 2"
5. Both windows should remain open

**Hints**:
<details>
<summary>Hint 1</summary>
After typing in the first window, use GUI r again to open another
</details>

<details>
<summary>Hint 2</summary>
Add delays between opening each application
</details>

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```ducky
REM Challenge D3: The Multi-Tasker
DELAY 2000

REM First Notepad
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING Window 1

REM Second Notepad
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING Window 2
```
</details>

---

### Challenge D4: Cross-Platform

**Difficulty**: Medium

**Objective**: Create THREE versions of Hello World for different operating systems.

**Requirements**:
Create separate payloads for:
1. Windows (Notepad)
2. macOS (TextEdit)
3. Linux/GNOME (gedit)

**Hints**:
<details>
<summary>macOS Hint</summary>
Use GUI SPACE for Spotlight, type "textedit"
</details>

<details>
<summary>Linux Hint</summary>
Use ALT F2 for run dialog, or CTRL ALT t for terminal
</details>

**Solutions**:
<details>
<summary>Windows Solution</summary>

```ducky
REM Windows Hello World
DELAY 2000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING Hello from Windows!
```
</details>

<details>
<summary>macOS Solution</summary>

```ducky
REM macOS Hello World
DELAY 2000
GUI SPACE
DELAY 500
STRING textedit
DELAY 500
ENTER
DELAY 1500
STRING Hello from macOS!
```
</details>

<details>
<summary>Linux Solution</summary>

```ducky
REM Linux/GNOME Hello World
DELAY 2000
ALT F2
DELAY 500
STRING gedit
ENTER
DELAY 1500
STRING Hello from Linux!
```
</details>

---

### Challenge D5: The Timer

**Difficulty**: Medium

**Objective**: Demonstrate precise timing control.

**Requirements**:
1. Open Notepad
2. Type "1" - wait 1 second
3. Type "2" - wait 1 second
4. Type "3" - wait 1 second
5. Type "GO!"

The numbers should appear one at a time with visible pauses.

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```ducky
REM Challenge D5: The Timer
DELAY 2000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING 1
DELAY 1000
STRING 2
DELAY 1000
STRING 3
DELAY 1000
STRING GO!
```
</details>

---

## Bash Challenges

### Challenge B1: System Reporter

**Difficulty**: Easy

**Objective**: Create a script that displays system information.

**Requirements**:
1. Show current username
2. Show hostname
3. Show current date and time
4. Show kernel version

**Hints**:
<details>
<summary>Hint 1</summary>
Use echo with command substitution: echo "User: $(whoami)"
</details>

<details>
<summary>Hint 2</summary>
Kernel version: uname -r
</details>

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```bash
#!/bin/bash
# Challenge B1: System Reporter

echo "===== System Report ====="
echo "User: $(whoami)"
echo "Hostname: $(hostname)"
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo "========================="
```
</details>

---

### Challenge B2: File Creator

**Difficulty**: Easy

**Objective**: Create a script that sets up a directory structure.

**Requirements**:
1. Create a directory called "my_project"
2. Inside it, create three subdirectories: "src", "docs", "tests"
3. Create an empty README.md file in the main directory
4. List the structure you created

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```bash
#!/bin/bash
# Challenge B2: File Creator

# Create main directory
mkdir -p my_project

# Create subdirectories
mkdir -p my_project/src
mkdir -p my_project/docs
mkdir -p my_project/tests

# Create README
touch my_project/README.md

# Show what we created
echo "Created structure:"
ls -la my_project/
```
</details>

---

### Challenge B3: The Greeter

**Difficulty**: Medium

**Objective**: Create an interactive script that greets the user.

**Requirements**:
1. Ask for the user's name
2. Ask for their favorite color
3. Display a personalized greeting

**Hints**:
<details>
<summary>Hint 1</summary>
Use `read` to get input: read -p "What is your name? " NAME
</details>

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```bash
#!/bin/bash
# Challenge B3: The Greeter

echo "Welcome to the Greeter!"
echo ""

read -p "What is your name? " NAME
read -p "What is your favorite color? " COLOR

echo ""
echo "Hello, $NAME!"
echo "I hear you like the color $COLOR."
echo "Nice to meet you!"
```
</details>

---

### Challenge B4: Network Info

**Difficulty**: Medium

**Objective**: Create a script that displays network information.

**Requirements**:
1. Show the hostname
2. Show all IP addresses
3. Show the default gateway
4. Show DNS servers

**Hints**:
<details>
<summary>Hint 1</summary>
IP addresses: hostname -I or ip addr
</details>

<details>
<summary>Hint 2</summary>
DNS servers: cat /etc/resolv.conf
</details>

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```bash
#!/bin/bash
# Challenge B4: Network Info

echo "===== Network Information ====="
echo ""
echo "Hostname: $(hostname)"
echo ""
echo "IP Addresses:"
hostname -I 2>/dev/null || ip addr show | grep "inet " | awk '{print $2}'
echo ""
echo "Default Gateway:"
ip route | grep default | awk '{print $3}'
echo ""
echo "DNS Servers:"
grep "nameserver" /etc/resolv.conf | awk '{print $2}'
echo ""
echo "==============================="
```
</details>

---

### Challenge B5: Log Analyzer

**Difficulty**: Medium

**Objective**: Create a script that analyzes a log file.

**Requirements**:
1. Create a sample log file with 5+ entries
2. Count total lines
3. Search for a specific word
4. Display the last 3 lines

**Solution**:
<details>
<summary>Click to reveal solution</summary>

```bash
#!/bin/bash
# Challenge B5: Log Analyzer

LOG_FILE="/tmp/sample.log"

# Create sample log
echo "2025-12-28 10:00:00 INFO Starting application" > "$LOG_FILE"
echo "2025-12-28 10:00:01 INFO Loading config" >> "$LOG_FILE"
echo "2025-12-28 10:00:02 WARNING Config file not found, using defaults" >> "$LOG_FILE"
echo "2025-12-28 10:00:03 INFO Application started" >> "$LOG_FILE"
echo "2025-12-28 10:00:04 ERROR Connection failed" >> "$LOG_FILE"
echo "2025-12-28 10:00:05 INFO Retrying connection" >> "$LOG_FILE"
echo "2025-12-28 10:00:06 INFO Connected successfully" >> "$LOG_FILE"

echo "===== Log Analysis ====="
echo ""
echo "Total lines: $(wc -l < "$LOG_FILE")"
echo ""
echo "Lines containing 'ERROR':"
grep "ERROR" "$LOG_FILE"
echo ""
echo "Last 3 lines:"
tail -n 3 "$LOG_FILE"
echo ""
echo "========================"

# Cleanup
rm -f "$LOG_FILE"
```
</details>

---

## Combination Challenges

### Challenge C1: Side-by-Side

**Difficulty**: Hard

**Objective**: Achieve the same goal in both DuckyScript AND Bash.

**Goal**: Display hostname and current user.

**Requirements**:
1. Write a DuckyScript payload that shows this on Windows
2. Write a Bash script that shows this on Linux
3. Compare the approaches

**Solutions**:
<details>
<summary>DuckyScript Solution</summary>

```ducky
REM Challenge C1: Show hostname and user (Windows)
DELAY 2000
GUI r
DELAY 500
STRING cmd /k echo Hostname: %COMPUTERNAME% && echo User: %USERNAME%
ENTER
```
</details>

<details>
<summary>Bash Solution</summary>

```bash
#!/bin/bash
# Challenge C1: Show hostname and user (Linux)

echo "Hostname: $(hostname)"
echo "User: $(whoami)"
```
</details>

---

## Scoring

| Challenge | Points | Your Score |
|-----------|--------|------------|
| D1: The Customizer | 10 | |
| D2: The Calculator | 10 | |
| D3: The Multi-Tasker | 15 | |
| D4: Cross-Platform | 20 | |
| D5: The Timer | 15 | |
| B1: System Reporter | 10 | |
| B2: File Creator | 10 | |
| B3: The Greeter | 15 | |
| B4: Network Info | 15 | |
| B5: Log Analyzer | 20 | |
| C1: Side-by-Side | 25 | |
| **Total** | **165** | |

---

## Advancement Criteria

To advance to Intermediate level:
- Complete at least 8 challenges
- Score at least 100 points
- Successfully run your solutions on test systems

---

## Next Steps

Completed the Basic challenges? Move on to:
- [Intermediate DuckyScript](../../02_Intermediate/Ducky/)
- [Intermediate Bash](../../02_Intermediate/Bash/)
- [Intermediate Challenges](../../02_Intermediate/Challenges/)

---

[← Back to Basic Level](../) | [Next: Intermediate Challenges →](../../02_Intermediate/Challenges/)
