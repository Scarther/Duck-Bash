# Keyboard Layout Reference

## Overview

Different keyboard layouts produce different characters for the same key codes. BadUSB payloads must account for target system keyboard layouts to function correctly.

---

## Why Layouts Matter

```
Example: Pressing the 'Y' key position

US Layout (QWERTY):  Types "Y"
German Layout (QWERTZ): Types "Z"
French Layout (AZERTY): Types "Y"

If your payload types "YES" but target uses German layout:
Intended: YES
Result:   ZES
```

---

## Common Keyboard Layouts

### US QWERTY (Default)

```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬─────┐
│ ` │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │ 0 │ - │ = │ BS  │
├───┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬───┤
│ Tab │ Q │ W │ E │ R │ T │ Y │ U │ I │ O │ P │ [ │ ] │ \ │
├─────┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴───┤
│ Caps │ A │ S │ D │ F │ G │ H │ J │ K │ L │ ; │ ' │Enter │
├──────┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴──────┤
│ Shift  │ Z │ X │ C │ V │ B │ N │ M │ , │ . │ / │ Shift  │
└────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴────────┘
```

### German QWERTZ

```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬─────┐
│ ^ │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │ 0 │ ß │ ´ │ BS  │
├───┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬───┤
│ Tab │ Q │ W │ E │ R │ T │ Z │ U │ I │ O │ P │ Ü │ + │ # │
├─────┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴───┤
│ Caps │ A │ S │ D │ F │ G │ H │ J │ K │ L │ Ö │ Ä │Enter │
├──────┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴──────┤
│ Shift  │ Y │ X │ C │ V │ B │ N │ M │ , │ . │ - │ Shift  │
└────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴────────┘

Key Differences from US:
- Y and Z are swapped
- @ is AltGr+Q (not Shift+2)
- Special characters: ß, Ü, Ö, Ä
```

### French AZERTY

```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬─────┐
│ ² │ & │ é │ " │ ' │ ( │ - │ è │ _ │ ç │ à │ ) │ = │ BS  │
├───┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬───┤
│ Tab │ A │ Z │ E │ R │ T │ Y │ U │ I │ O │ P │ ^ │ $ │ * │
├─────┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴───┤
│ Caps │ Q │ S │ D │ F │ G │ H │ J │ K │ L │ M │ ù │Enter │
├──────┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴──────┤
│ Shift  │ W │ X │ C │ V │ B │ N │ , │ ; │ : │ ! │ Shift  │
└────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴────────┘

Key Differences from US:
- A and Q are swapped
- Z and W are swapped
- M is on the home row
- Numbers require Shift
```

### UK QWERTY

```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬─────┐
│ ` │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │ 0 │ - │ = │ BS  │
├───┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬───┤
│ Tab │ Q │ W │ E │ R │ T │ Y │ U │ I │ O │ P │ [ │ ] │   │
├─────┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴───┤
│ Caps │ A │ S │ D │ F │ G │ H │ J │ K │ L │ ; │ ' │Enter │
├────┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴──────┤
│Shft│ \ │ Z │ X │ C │ V │ B │ N │ M │ , │ . │ / │ Shift  │
└────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴────────┘

Key Differences from US:
- @ is Shift+' (not Shift+2)
- " is Shift+2 (not Shift+')
- # is on its own key
- £ is Shift+3
- Extra key next to left Shift
```

---

## DuckyScript Layout Configuration

### Setting Keyboard Layout

```
REM Flipper Zero / USB Rubber Ducky
REM Place at start of payload

REM For US keyboard (default)
REM No configuration needed

REM For German keyboard
ATTACKMODE HID DE

REM For French keyboard
ATTACKMODE HID FR

REM For UK keyboard
ATTACKMODE HID GB
```

### Layout-Specific Commands

| Intended Character | US | DE | FR |
|-------------------|-----|-----|-----|
| @ | Shift+2 | AltGr+Q | AltGr+0 |
| # | Shift+3 | # key | AltGr+3 |
| \ | \ key | AltGr+ß | AltGr+8 |
| { | Shift+[ | AltGr+7 | AltGr+4 |
| } | Shift+] | AltGr+0 | AltGr+= |
| [ | [ key | AltGr+8 | AltGr+5 |
| ] | ] key | AltGr+9 | AltGr+) |
| \| | Shift+\ | AltGr+< | AltGr+6 |

---

## Layout Detection Payload

```
REM Payload: Detect Target Keyboard Layout
REM Works by checking which characters are produced

DELAY 2000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000

REM Type test sequence - results reveal layout
STRING Layout Test: @#$[]{}|\
ENTER
STRING If you see @#$[]{}|\ the target uses US layout
ENTER
STRING If @ shows as " the target uses UK layout
ENTER
STRING If @ shows as Q the target uses German (QWERTZ)
ENTER
STRING If first letter is Q the target uses French (AZERTY)
```

---

## Character Mapping Tables

### US to German Translation

```python
#!/usr/bin/env python3
"""
US to German Keyboard Translation
For payload conversion
"""

US_TO_DE = {
    'y': 'z',
    'z': 'y',
    'Y': 'Z',
    'Z': 'Y',
    '@': 'ALTGR_Q',      # Requires AltGr
    '[': 'ALTGR_8',
    ']': 'ALTGR_9',
    '{': 'ALTGR_7',
    '}': 'ALTGR_0',
    '\\': 'ALTGR_BETA',  # ß key with AltGr
    '|': 'ALTGR_<',
    ';': 'SHIFT_COMMA',
    ':': 'SHIFT_PERIOD',
    "'": 'SHIFT_HASH',
    '"': 'SHIFT_2',
    '-': 'SLASH',        # Different position
    '_': 'SHIFT_SLASH',
}

def convert_us_to_de(payload):
    """Convert US layout payload to German layout"""
    result = []
    for char in payload:
        if char in US_TO_DE:
            result.append(f"[{US_TO_DE[char]}]")
        else:
            result.append(char)
    return ''.join(result)

# Example
us_payload = "powershell -ep bypass"
print(f"US: {us_payload}")
print(f"DE: {convert_us_to_de(us_payload)}")
# Note: z and y swapped, - becomes different key
```

### US to French Translation

```python
US_TO_FR = {
    'a': 'q',
    'q': 'a',
    'z': 'w',
    'w': 'z',
    'A': 'Q',
    'Q': 'A',
    'Z': 'W',
    'W': 'Z',
    'm': ',',           # M is different position
    'M': '?',
    '1': 'SHIFT_1',     # Numbers need shift
    '2': 'SHIFT_2',
    '@': 'ALTGR_0',
    '[': 'ALTGR_5',
    ']': 'ALTGR_)',
    '{': 'ALTGR_4',
    '}': 'ALTGR_=',
}
```

---

## Flipper Zero Layout Files

### Location

```
/ext/badusb/assets/layouts/
├── de.kl       # German
├── fr.kl       # French
├── gb.kl       # UK
├── us.kl       # US (default)
├── es.kl       # Spanish
├── it.kl       # Italian
└── ...
```

### Layout File Format

```
# Example layout file structure (.kl)
# Maps USB HID codes to characters for the layout

# Format: HID_CODE NORMAL SHIFT ALTGR SHIFT_ALTGR
0x04 a A    # Key A
0x05 b B    # Key B
0x06 c C    # Key C
0x1E 1 !    # Key 1
0x1F 2 @    # Key 2 (US: @ with Shift)
# ... etc
```

### Creating Custom Layout

```bash
#!/bin/bash
#######################################
# Create Custom Keyboard Layout
# For Flipper Zero BadUSB
#######################################

OUTPUT_FILE="custom.kl"

cat > "$OUTPUT_FILE" << 'EOF'
# Custom keyboard layout
# Based on US QWERTY with modifications

# Letters (same as US)
0x04 a A
0x05 b B
0x06 c C
0x07 d D
0x08 e E
0x09 f F
0x0A g G
0x0B h H
0x0C i I
0x0D j J
0x0E k K
0x0F l L
0x10 m M
0x11 n N
0x12 o O
0x13 p P
0x14 q Q
0x15 r R
0x16 s S
0x17 t T
0x18 u U
0x19 v V
0x1A w W
0x1B x X
0x1C y Y
0x1D z Z

# Numbers
0x1E 1 !
0x1F 2 @
0x20 3 #
0x21 4 $
0x22 5 %
0x23 6 ^
0x24 7 &
0x25 8 *
0x26 9 (
0x27 0 )
EOF

echo "[+] Created layout file: $OUTPUT_FILE"
echo "[*] Copy to Flipper: /ext/badusb/assets/layouts/"
```

---

## Multi-Layout Payload Strategy

### Universal Payload Approach

```
REM Universal payload that works across layouts
REM Uses only keys that are consistent

REM Method 1: Use PowerShell's ability to interpret
REM Write payload to file, then execute

GUI r
DELAY 500
STRING powershell
ENTER
DELAY 1000

REM Use ASCII codes to avoid layout issues
STRINGLN $c=[char]99;$m=[char]109;$d=[char]100;iex "$c$m$d"
```

### Layout-Aware Payload

```
REM Check layout and adapt
REM This is a conceptual example

GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000

REM Type a test character and check result
REM If using automation, script can detect and switch
```

---

## Regional Keyboard Statistics

| Region | Common Layouts | Market Share |
|--------|---------------|--------------|
| USA | US QWERTY | 95%+ |
| UK | UK QWERTY | 90%+ |
| Germany | QWERTZ | 95%+ |
| France | AZERTY | 90%+ |
| Spain | Spanish QWERTY | 95%+ |
| Japan | JIS (106/109) | 80%+ |
| International | US International | Varies |

---

## Testing Layouts

### Layout Test Script

```bash
#!/bin/bash
#######################################
# Test Keyboard Layout Detection
#######################################

echo "[*] Current keyboard layout:"
setxkbmap -query

echo ""
echo "[*] Available layouts:"
localectl list-x11-keymap-layouts | head -20

echo ""
echo "[*] To change layout temporarily:"
echo "    setxkbmap us    # US layout"
echo "    setxkbmap de    # German layout"
echo "    setxkbmap fr    # French layout"

echo ""
echo "[*] Key position test - Press the key left of '1':"
read -n1 KEY
echo ""
echo "[+] You pressed: '$KEY'"

case "$KEY" in
    '`') echo "    Layout appears to be: US QWERTY" ;;
    '²') echo "    Layout appears to be: French AZERTY" ;;
    '^') echo "    Layout appears to be: German QWERTZ" ;;
    *) echo "    Layout unknown or custom" ;;
esac
```

---

## Quick Reference Card

### Characters That Differ Between Layouts

| Char | US | UK | DE | FR |
|------|-----|-----|-----|-----|
| @ | Shift+2 | Shift+' | AltGr+Q | AltGr+0 |
| # | Shift+3 | ~ key | # key | AltGr+3 |
| £ | N/A | Shift+3 | N/A | N/A |
| € | N/A | AltGr+4 | AltGr+E | AltGr+E |
| \ | \ key | # key | AltGr+ß | AltGr+8 |
| / | / key | / key | Shift+7 | Shift+: |

### Safe Characters (Same Across Common Layouts)

Letters A-Z (but beware Y/Z in German, Q/A/W/Z in French)
Space, Enter, Tab, Escape, Backspace
Arrow keys, Function keys

---

[← Back to Technical Addendum](../README.md)
