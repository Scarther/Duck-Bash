# DT-02: Cron Persistence

## Difficulty: Beginner

---

## Scenario

Learn how attackers establish persistence via cron jobs, and how to detect them.

---

## Objectives

### Attack (Red Team)
- Add a cron entry that runs every 5 minutes
- The cron should execute a hidden script
- The script should log activity (simulate beacon)

### Defense (Blue Team)
- Detect new/suspicious cron entries
- Find the associated script
- Alert on persistence indicators

---

## Templates

- `attack_template.sh` - Your attack script
- `defense_template.sh` - Your detection script

---

## Testing

1. Run attack: `./attack_template.sh`
2. Verify: `crontab -l`
3. Run defense: `./defense_template.sh`
4. Cleanup: Remove the cron entry and script

---

## Success Criteria

- [ ] Cron entry successfully created
- [ ] Hidden script exists and is executable
- [ ] Detection script finds the cron entry
- [ ] Detection script identifies the suspicious pattern
