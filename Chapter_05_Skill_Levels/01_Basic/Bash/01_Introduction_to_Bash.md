# Basic Level: Introduction to Bash Scripting

## Lesson 1: What is Bash?

Welcome to your first Bash scripting lesson! By the end of this lesson, you'll understand what Bash is and write your first script.

---

## Learning Objectives

By the end of this lesson, you will be able to:
- [ ] Explain what Bash is and where it runs
- [ ] Write a basic Bash script
- [ ] Understand the shebang (`#!/bin/bash`)
- [ ] Run scripts on Linux systems

---

## What is Bash?

**Bash** (Bourne Again SHell) is a command-line interpreter that lets you control Linux/Unix systems. It's the default shell on most Linux distributions and macOS.

### Shell vs Script

| Term | Meaning |
|------|---------|
| **Shell** | Interactive command prompt where you type commands |
| **Script** | File containing multiple commands to run automatically |

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BASH CONCEPT                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   INTERACTIVE SHELL                    BASH SCRIPT                          │
│   ─────────────────                    ───────────                          │
│                                                                              │
│   $ echo "Hello"                       #!/bin/bash                          │
│   Hello                                echo "Hello"                         │
│   $ ls                                 ls                                   │
│   file1.txt  file2.txt                 pwd                                  │
│   $ pwd                                                                     │
│   /home/user                           # Save as script.sh                  │
│                                        # Run: ./script.sh                   │
│   You type each command                Script runs all commands             │
│   one at a time                        automatically in sequence            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## DuckyScript vs Bash

Throughout this training, you'll learn both. Here's how they differ:

```
┌──────────────────────────────────┬──────────────────────────────────┐
│         DUCKYSCRIPT              │              BASH                │
├──────────────────────────────────┼──────────────────────────────────┤
│                                  │                                  │
│ Runs on: Flipper Zero            │ Runs on: Linux systems           │
│                                  │ (WiFi Pineapple, servers, etc)   │
│                                  │                                  │
│ Purpose: Type keystrokes         │ Purpose: Run system commands     │
│                                  │                                  │
│ Like: Remote control typing      │ Like: Direct system access       │
│                                  │                                  │
│ Target: Computer via USB         │ Target: The Linux system itself  │
│                                  │                                  │
└──────────────────────────────────┴──────────────────────────────────┘
```

---

## Your First Bash Commands

### 1. echo - Print Text

```bash
echo "Hello World"
```

**Output**: `Hello World`

**Purpose**: Display text or variable values

**Examples**:
```bash
echo "Welcome to Bash!"          # Print a message
echo $USER                       # Print username variable
echo "Hello, $USER"              # Combine text and variables
```

---

### 2. Comments (#)

```bash
# This is a comment
# Comments explain your code
echo "This runs"  # Comments can go after code too
```

**Purpose**: Document your code (computer ignores these)

---

### 3. Variables

```bash
NAME="Alice"
echo "Hello, $NAME"
```

**Output**: `Hello, Alice`

**Rules**:
- No spaces around `=`
- Use `$` to read the value
- UPPERCASE for constants, lowercase for variables

```bash
# Setting variables
MESSAGE="Welcome"
COUNT=10
FILE_PATH="/home/user/data.txt"

# Reading variables
echo $MESSAGE
echo "Count is: $COUNT"
echo "File at: $FILE_PATH"
```

---

### 4. pwd - Print Working Directory

```bash
pwd
```

**Output**: `/home/username` (or wherever you are)

**Purpose**: Shows your current location in the filesystem

---

### 5. ls - List Files

```bash
ls           # List files in current directory
ls -l        # Long format (details)
ls -la       # Include hidden files
ls /path     # List specific directory
```

---

### 6. cd - Change Directory

```bash
cd /home/user        # Go to specific directory
cd ..                # Go up one level
cd ~                 # Go to home directory
cd -                 # Go to previous directory
```

---

## Your First Bash Script

### The Shebang Line

Every Bash script should start with:

```bash
#!/bin/bash
```

This tells Linux which interpreter to use. It's called a **shebang** (or hashbang).

### Complete Hello World Script

```bash
#!/bin/bash
#######################################
# Script: hello.sh
# Description: My first Bash script
# Author: Your Name
# Date: 2025
#######################################

# Print a welcome message
echo "Hello, World!"

# Show the current user
echo "You are logged in as: $USER"

# Show current date and time
echo "Current date: $(date)"

# Show current directory
echo "You are in: $(pwd)"
```

### Running the Script

```bash
# Step 1: Save the script
nano hello.sh   # or use any text editor

# Step 2: Make it executable
chmod +x hello.sh

# Step 3: Run it
./hello.sh
```

**Output**:
```
Hello, World!
You are logged in as: username
Current date: Sat Dec 28 10:30:00 UTC 2025
You are in: /home/username
```

---

## Side-by-Side: DuckyScript vs Bash

### Same Task: Display System Info

```
┌──────────────────────────────────┬──────────────────────────────────┐
│      DUCKYSCRIPT (Flipper)       │         BASH (Pineapple)         │
├──────────────────────────────────┼──────────────────────────────────┤
│                                  │                                  │
│ REM Display system info          │ #!/bin/bash                      │
│                                  │ # Display system info            │
│ DELAY 2000                       │                                  │
│ GUI r                            │ # No delay needed                │
│ DELAY 500                        │ # Direct system access           │
│ STRING cmd                       │                                  │
│ ENTER                            │ echo "=== System Info ==="       │
│ DELAY 1000                       │ echo "Hostname: $(hostname)"     │
│ STRING echo === System Info ===  │ echo "User: $USER"               │
│ ENTER                            │ echo "OS: $(uname -a)"           │
│ STRING hostname                  │ echo "IP: $(hostname -I)"        │
│ ENTER                            │                                  │
│ STRING whoami                    │ # Results printed directly       │
│ ENTER                            │                                  │
│ STRING ipconfig                  │                                  │
│ ENTER                            │                                  │
│                                  │                                  │
│ # Types INTO Windows terminal    │ # Runs ON the Linux system       │
│                                  │                                  │
└──────────────────────────────────┴──────────────────────────────────┘
```

**Key Insight**: DuckyScript "pretends to be a user typing" while Bash "directly controls the system"

---

## Essential Bash Concepts

### Command Substitution

Run a command and use its output:

```bash
# Using $()
CURRENT_DATE=$(date)
echo "The date is: $CURRENT_DATE"

# Using backticks (older style)
HOSTNAME=`hostname`
echo "Hostname: $HOSTNAME"
```

### String Quotes

```bash
NAME="World"

# Double quotes - variables are expanded
echo "Hello, $NAME"     # Output: Hello, World

# Single quotes - literal string
echo 'Hello, $NAME'     # Output: Hello, $NAME

# No quotes - words split on spaces
echo Hello,      World  # Output: Hello, World
```

### Exit Codes

```bash
# Every command returns an exit code
# 0 = success, non-zero = failure

ls /existing/path
echo $?  # Output: 0 (success)

ls /nonexistent/path
echo $?  # Output: 2 (failure - no such file)
```

---

## Red Team Perspective

### Why Learn Bash?

1. **Post-exploitation**: After gaining access, Bash lets you:
   - Enumerate the system
   - Find sensitive files
   - Establish persistence
   - Move laterally

2. **WiFi Pineapple**: All payloads are Bash scripts

3. **Linux Targets**: Many servers run Linux

4. **Automation**: Script repetitive tasks

### Common Red Team Bash Uses

```bash
# System enumeration
whoami                    # Current user
id                        # User ID and groups
uname -a                  # System information
cat /etc/passwd           # List users
cat /etc/shadow           # Password hashes (if readable)
ps aux                    # Running processes
netstat -tulpn            # Network connections

# File hunting
find / -name "*.conf" 2>/dev/null     # Find config files
grep -r "password" /etc/ 2>/dev/null  # Search for passwords
```

---

## Blue Team Perspective

### Detecting Malicious Scripts

Watch for:
1. **Unusual script locations**: Scripts in /tmp, /var/tmp
2. **Obfuscated code**: Base64, hex encoding
3. **Network connections**: Unauthorized curl/wget
4. **Privilege escalation attempts**: sudo, SUID exploitation
5. **Persistence mechanisms**: cron jobs, rc.local modifications

### Bash Script Audit Points

```bash
# Check for suspicious cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# Check running processes
ps aux | grep -E "(bash|sh|python|perl|nc|ncat)"

# Check network connections
netstat -tulpn | grep -v "127.0.0.1"

# Check recently modified scripts
find /tmp /var/tmp -type f -name "*.sh" -mtime -1
```

---

## Practice Exercises

### Exercise 1: System Info Script
Write a script that displays:
1. Current username
2. Hostname
3. Current date
4. Kernel version (hint: `uname -r`)

### Exercise 2: Custom Greeting
Write a script that:
1. Asks for the user's name (hint: `read NAME`)
2. Greets them personally
3. Shows the current time

```bash
#!/bin/bash
echo "What is your name?"
read NAME
echo "Hello, $NAME!"
echo "The time is: $(date +%H:%M)"
```

### Exercise 3: File Creator
Write a script that:
1. Creates a directory called "myfiles"
2. Creates three empty files inside it
3. Lists the contents

### Exercise 4: Compare with DuckyScript
Write the same "display hostname and user" script in:
1. Bash (for WiFi Pineapple)
2. DuckyScript (for Flipper Zero on Windows)

---

## Self-Check Quiz

1. What does `#!/bin/bash` mean?
   - [ ] A comment
   - [ ] Tells Linux to use Bash interpreter (correct)
   - [ ] Prints bash

2. How do you read a variable in Bash?
   - [ ] VAR
   - [ ] $VAR (correct)
   - [ ] %VAR%

3. What command shows your current directory?
   - [ ] cd
   - [ ] pwd (correct)
   - [ ] ls

4. How do you make a script executable?
   - [ ] run script.sh
   - [ ] chmod +x script.sh (correct)
   - [ ] bash enable script.sh

---

## Summary

**What you learned**:
- Bash is a command interpreter for Linux
- Scripts are files containing multiple commands
- The shebang (`#!/bin/bash`) specifies the interpreter
- Variables store values, accessed with `$`
- Basic commands: echo, pwd, ls, cd

**Commands mastered**:
- [x] echo - Print output
- [x] pwd - Show current directory
- [x] ls - List files
- [x] cd - Change directory
- [x] chmod - Change permissions

---

## Quick Reference

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      BASH QUICK REFERENCE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SCRIPT STRUCTURE                 VARIABLES                                 │
│  ────────────────                 ─────────                                 │
│  #!/bin/bash                      NAME="value"      # Set                   │
│  # Comment                        echo $NAME        # Read                  │
│  command                          echo "$NAME"      # Read (safer)          │
│                                                                              │
│  NAVIGATION                       OUTPUT                                    │
│  ──────────                       ──────                                    │
│  pwd        # Where am I?         echo "text"       # Print text            │
│  ls         # What's here?        echo $VAR         # Print variable        │
│  cd /path   # Go there            echo "$(cmd)"     # Print command output  │
│  cd ..      # Go up                                                         │
│                                                                              │
│  RUNNING SCRIPTS                  SPECIAL VARIABLES                         │
│  ───────────────                  ─────────────────                         │
│  chmod +x script.sh               $USER      # Current username             │
│  ./script.sh                      $HOME      # Home directory               │
│  bash script.sh                   $PWD       # Current directory            │
│                                   $?         # Last exit code               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Next Lesson

**[Lesson 2: Variables and Input](02_Variables_and_Input.md)**

In the next lesson, you'll learn:
- Different variable types
- Reading user input
- Command-line arguments
- Environment variables

---

[← Back to Basic Bash](README.md) | [Next: Variables and Input →](02_Variables_and_Input.md)
