# DT-01: Hidden File Dropper

## Difficulty: Beginner

---

## Scenario

You are a security professional learning about BadUSB attacks. Your task is to:

1. **RED TEAM**: Create a script that simulates a BadUSB payload dropping a hidden file
2. **BLUE TEAM**: Create a detection script that finds the hidden file

---

## Objectives

### Attack Objectives (Red Team)
- Create a hidden file in /tmp
- Write some "malicious" content to it (simulated)
- Make the file non-obvious to casual inspection

### Defense Objectives (Blue Team)
- Detect newly created hidden files in common locations
- Alert on files with suspicious content patterns
- Report findings to the user

---

## Requirements

### Attack Script Must:
- [ ] Create a hidden file (starts with .)
- [ ] Write at least 3 lines of content
- [ ] Include a timestamp
- [ ] Include system information
- [ ] Be executable

### Defense Script Must:
- [ ] Search /tmp for hidden files
- [ ] Check file creation time (recent files)
- [ ] Read and analyze content
- [ ] Print alerts with colors
- [ ] Exit with appropriate status code

---

## Templates

Use `attack_template.sh` for your attack script.
Use `defense_template.sh` for your defense script.

---

## Testing

1. Run your attack: `./attack_template.sh`
2. Run your defense: `./defense_template.sh`
3. The defense should detect what the attack created

---

## Success Criteria

- Attack successfully creates hidden file
- Defense successfully detects and reports it
- Both scripts are well-commented

---

## Hints

<details>
<summary>Attack Hint 1</summary>
Use `echo` or `cat > filename` to create files
</details>

<details>
<summary>Attack Hint 2</summary>
Files starting with . are hidden in Linux
</details>

<details>
<summary>Defense Hint 1</summary>
Use `find /tmp -name ".*" -type f` to find hidden files
</details>

<details>
<summary>Defense Hint 2</summary>
Use `grep` to search file contents for patterns
</details>

---

## When Complete

Check the `solutions/` directory to compare your approach.
