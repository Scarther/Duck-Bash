# Dual Training - Attack & Defense

## Overview

Dual Training exercises require you to create both an "infection" script (Red Team) and a "counter" script (Blue Team). This approach provides comprehensive understanding of attack techniques and their defenses.

---

## How Dual Training Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DUAL TRAINING WORKFLOW                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PHASE 1: CREATE ATTACK                                             │
│  ├── Read the scenario and objectives                               │
│  ├── Design your attack payload                                     │
│  ├── Implement the "infection" script                               │
│  └── Test in your lab environment                                   │
│                                                                      │
│  PHASE 2: CREATE DEFENSE                                            │
│  ├── Analyze what artifacts your attack creates                     │
│  ├── Design detection logic                                         │
│  ├── Implement the "counter" script                                 │
│  └── Test against your attack                                       │
│                                                                      │
│  PHASE 3: VALIDATE                                                  │
│  ├── Run attack → Verify counter detects it                         │
│  ├── Improve attack evasion                                         │
│  ├── Improve detection capabilities                                 │
│  └── Document lessons learned                                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Exercise Levels

| Level | Exercises | Focus |
|-------|-----------|-------|
| [Beginner](Beginner/) | DT-01 to DT-05 | Basic payloads and file-based detection |
| [Intermediate](Intermediate/) | DT-06 to DT-10 | Persistence and behavioral detection |
| [Advanced](Advanced/) | DT-11 to DT-15 | Evasion and advanced hunting |

---

## File Structure

Each exercise contains:
```
DT-XX_Exercise_Name/
├── SCENARIO.md           # The challenge description
├── attack_template.sh    # Template for your attack
├── defense_template.sh   # Template for your defense
├── solution_attack.sh    # Reference solution (hidden)
└── solution_defense.sh   # Reference solution (hidden)
```

---

## Getting Started

1. **Choose an exercise** from the appropriate level
2. **Read SCENARIO.md** carefully
3. **Create your attack** using the template
4. **Test your attack** in a VM
5. **Create your defense** based on what you learned
6. **Test the detection** against your attack
7. **Compare with solutions** after completing

---

[← Back to Skill Levels](../README.md)
