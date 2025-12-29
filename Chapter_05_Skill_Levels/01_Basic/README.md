# Basic Level - Security Training

## Overview

This section contains beginner-friendly payloads and exercises for learning DuckyScript and Bash scripting fundamentals in the context of security testing.

---

## Contents

| Directory | Description |
|-----------|-------------|
| [Ducky](Ducky/) | Basic DuckyScript payloads for Flipper Zero |
| [Bash](Bash/) | Basic Bash scripts for Linux/macOS |
| [Challenges](Challenges/) | Hands-on exercises to test your skills |
| [Practice](Practice/) | Lab setup and practice environments |

---

## Learning Objectives

After completing the Basic level, you will be able to:

- Understand DuckyScript syntax and commands
- Write simple payloads that open applications
- Use basic timing and delay concepts
- Create text output and simple automation
- Understand payload structure and documentation

---

## Prerequisites

- Basic computer literacy
- Understanding of command line basics
- Access to a test environment (VM recommended)
- Flipper Zero or compatible device for DuckyScript

---

## Recommended Path

```
1. Read the Fundamentals (Chapter 01/01_Fundamentals or Chapter 02/01_Fundamentals)
2. Study the Ducky payloads in this section
3. Set up a practice environment using the Practice directory
4. Complete the Challenges to test your understanding
5. Move to Intermediate level when comfortable
```

---

## Key Concepts

### DuckyScript Basics

```
REM     - Comments (ignored by device)
DELAY   - Wait specified milliseconds
STRING  - Type text
ENTER   - Press Enter key
GUI     - Windows/Command key
ALT     - Alt key combinations
```

### Bash Basics

```bash
#!/bin/bash           # Shebang line
echo "text"           # Print output
read variable         # Read input
if/then/else/fi       # Conditionals
for/do/done           # Loops
```

---

## Safety Reminder

All payloads in this section are for **authorized security testing and educational purposes only**. Always:

1. Test in isolated virtual machines first
2. Obtain written authorization before testing on any system
3. Understand what each payload does before running it
4. Document all testing activities

---

[← Back to Skill Levels](../README.md) | [Next: Intermediate →](../02_Intermediate/)
