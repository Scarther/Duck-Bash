# Intermediate Level CTF Scenarios

## Overview

These CTF scenarios increase in complexity, introducing encoded payloads, multi-stage attacks, network simulation, and more sophisticated persistence mechanisms.

---

## Scenario 01: Encoded Secrets

### Background
Analysis of a suspected BadUSB attack reveals base64-encoded data. Decode the layers to find the flag.

### Objective
Find and decode the multi-layer encoded flag.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/02_Intermediate/Practice/
sudo ./red_team/I01_encoded_secrets_setup.sh
```

### Blue Team Tasks
1. Locate encoded files in temp directories
2. Identify the encoding method(s) used
3. Decode through multiple layers
4. Extract the flag

### Hints
<details>
<summary>Hint 1</summary>
The payload uses multiple encoding layers
</details>

<details>
<summary>Hint 2</summary>
Try: base64 -d, then look for hex encoding
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Find the encoded file
cat /tmp/.encoded_payload

# Decode base64 first layer
cat /tmp/.encoded_payload | base64 -d

# The result is hex encoded - decode it
cat /tmp/.encoded_payload | base64 -d | xxd -r -p

# Or use the automated decoder
echo "RkxBR3tlbmNvZGVkX3NlY3JldHNfdW5sb2NrZWR9" | base64 -d
```
</details>

---

## Scenario 02: Credential Heist

### Background
A BadUSB may have harvested credentials from the system. Find evidence of credential theft.

### Objective
Locate the stolen credentials and find the hidden flag.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/02_Intermediate/Practice/
sudo ./red_team/I02_credential_heist_setup.sh
```

### Blue Team Tasks
1. Check for credential harvesting scripts
2. Find where credentials were staged
3. Identify what was stolen (simulated)
4. Find the flag in the stolen data

### Hints
<details>
<summary>Hint 1</summary>
Check for scripts that read password files or browser data locations
</details>

<details>
<summary>Hint 2</summary>
Look in /tmp for JSON or text files containing "password" or "credential"
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Find credential-related files
find /tmp -name "*cred*" -o -name "*pass*" 2>/dev/null

# Check the harvested data
cat /tmp/.harvested_creds.json

# The flag is embedded in the JSON
grep -o "FLAG{[^}]*}" /tmp/.harvested_creds.json
```
</details>

---

## Scenario 03: Network Beacon

### Background
Suspicious network activity was detected after USB insertion. A beacon may be calling home.

### Objective
Find the beacon configuration and extract the C2 information.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/02_Intermediate/Practice/
sudo ./red_team/I03_network_beacon_setup.sh
```

### Blue Team Tasks
1. Check for scheduled network tasks
2. Find beacon configuration files
3. Identify the C2 server (simulated)
4. Extract the flag from the config

### Hints
<details>
<summary>Hint 1</summary>
Beacons often use cron or systemd timers
</details>

<details>
<summary>Hint 2</summary>
Look for URLs or IP addresses in hidden files
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Check for beacon cron
crontab -l
cat /etc/cron.d/network_check

# Find beacon script
cat /tmp/.beacon.sh

# Extract C2 config
cat /tmp/.c2_config.json
# FLAG is in the config file
```
</details>

---

## Scenario 04: Living Off the Land

### Background
The attacker used only built-in system tools (LOLBins). No malware was dropped.

### Objective
Trace the attack through system logs and find evidence of LOLBin abuse.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/02_Intermediate/Practice/
sudo ./red_team/I04_lolbins_setup.sh
```

### Blue Team Tasks
1. Review command history for suspicious patterns
2. Check for unusual uses of curl, wget, python, etc.
3. Find evidence of data exfiltration
4. Locate the flag

### Hints
<details>
<summary>Hint 1</summary>
Check bash history for curl, wget, nc, python one-liners
</details>

<details>
<summary>Hint 2</summary>
Look for temporary Python or Perl scripts
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Check history for LOLBins
cat ~/.bash_history | grep -E "curl|wget|python|perl|nc"

# Find the data exfil log
cat /var/log/lolbin_activity.log

# Flag is in the exfiltration evidence
grep "FLAG" /var/log/lolbin_activity.log
```
</details>

---

## Scenario 05: Registry Persistence (Linux Equivalent)

### Background
While Linux doesn't have a registry, attackers use equivalent persistence mechanisms. Find them all.

### Objective
Identify all persistence mechanisms installed and find the flags.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/02_Intermediate/Practice/
sudo ./red_team/I05_persistence_hunt_setup.sh
```

### Blue Team Tasks
1. Check all cron locations
2. Examine bashrc/profile files
3. Look for systemd user services
4. Check for authorized_keys modifications
5. Find ALL flags (there are 3)

### Hints
<details>
<summary>Hint 1</summary>
Persistence locations: ~/.bashrc, crontab, ~/.config/systemd/user/
</details>

<details>
<summary>Hint 2</summary>
Each persistence mechanism has its own flag
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Flag 1: Check bashrc
grep "FLAG" ~/.bashrc

# Flag 2: Check crontab
crontab -l | grep "FLAG"

# Flag 3: Check systemd user services
cat ~/.config/systemd/user/update.service 2>/dev/null | grep "FLAG"
```
</details>

---

## Scenario 06: Memory Artifact

### Background
The attacker stored sensitive data in environment variables and temp files that mimic memory artifacts.

### Objective
Find the in-memory secrets and decode the flag.

### Setup
```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/02_Intermediate/Practice/
sudo ./red_team/I06_memory_artifact_setup.sh
```

### Blue Team Tasks
1. Check environment variables for unusual entries
2. Examine /dev/shm for temporary data
3. Look for process-related artifacts
4. Decode the memory artifact to get the flag

### Hints
<details>
<summary>Hint 1</summary>
/dev/shm is RAM-based storage, often used for stealth
</details>

<details>
<summary>Hint 2</summary>
Check `env` for unusual variables
</details>

### Solution
<details>
<summary>Show Solution</summary>

```bash
# Check environment
env | grep -i "secret\|key\|flag"

# Check /dev/shm
ls -la /dev/shm/
cat /dev/shm/.memory_artifact

# Decode the artifact
cat /dev/shm/.memory_artifact | base64 -d
```
</details>

---

## Scoring

| Scenario | Points | Flags | Difficulty |
|----------|--------|-------|------------|
| 01 - Encoded Secrets | 200 | 1 | Medium |
| 02 - Credential Heist | 200 | 1 | Medium |
| 03 - Network Beacon | 250 | 1 | Medium |
| 04 - Living Off Land | 250 | 1 | Medium-Hard |
| 05 - Persistence Hunt | 300 | 3 | Medium-Hard |
| 06 - Memory Artifact | 300 | 1 | Hard |

**Total Possible: 1500 points**

---

## Cleanup

```bash
cd /mnt/work/Scripts/Payloads/Pager/Ducky_Bash/Chapter_05_Skill_Levels/02_Intermediate/Practice/
sudo ./cleanup_all.sh
```

---

[← Back to Intermediate Level](../README.md)
