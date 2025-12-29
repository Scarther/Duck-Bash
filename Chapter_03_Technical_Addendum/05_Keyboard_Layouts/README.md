# Keyboard Layouts Reference

## Overview

Different keyboard layouts produce different characters for the same key codes. Payloads must match the target system's keyboard layout to type correctly.

---

## Common Layout Differences

### US vs International Layouts

| Character | US QWERTY | UK QWERTY | German QWERTZ | French AZERTY |
|-----------|-----------|-----------|---------------|---------------|
| @ | Shift+2 | Shift+' | AltGr+Q | AltGr+0 |
| # | Shift+3 | Shift+3 | (not direct) | AltGr+3 |
| $ | Shift+4 | Shift+4 | Shift+4 | $ |
| \ | \ | \ | AltGr+ß | AltGr+8 |
| / | / | / | Shift+7 | Shift+: |
| { | Shift+[ | Shift+[ | AltGr+7 | AltGr+4 |
| } | Shift+] | Shift+] | AltGr+0 | AltGr+= |
| [ | [ | [ | AltGr+8 | AltGr+5 |
| ] | ] | ] | AltGr+9 | AltGr+) |
| < | Shift+, | Shift+, | < | < |
| > | Shift+. | Shift+. | Shift+< | Shift+< |
| \| | Shift+\ | Shift+\ | AltGr+< | AltGr+6 |
| ~ | Shift+` | Shift+# | AltGr++ | AltGr+2 |
| ` | ` | ` | Shift+´ | AltGr+7 |
| ; | ; | ; | Shift+, | , |
| : | Shift+; | Shift+; | Shift+. | . |
| ' | ' | ' | Shift+# | 4 |
| " | Shift+' | Shift+2 | Shift+2 | 3 |

---

## Layout Quick Reference

### US QWERTY (Default)
```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───────┐
│ ` │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │ 0 │ - │ = │ Bksp  │
├───┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─────┤
│ Tab │ Q │ W │ E │ R │ T │ Y │ U │ I │ O │ P │ [ │ ] │  \  │
├─────┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴─────┤
│ Caps │ A │ S │ D │ F │ G │ H │ J │ K │ L │ ; │ ' │ Enter  │
├──────┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴────────┤
│ Shift  │ Z │ X │ C │ V │ B │ N │ M │ , │ . │ / │  Shift   │
└────────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴──────────┘
```

### German QWERTZ
```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───────┐
│ ^ │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │ 0 │ ß │ ´ │ Bksp  │
├───┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─────┤
│ Tab │ Q │ W │ E │ R │ T │ Z │ U │ I │ O │ P │ Ü │ + │Enter│
├─────┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┐    │
│ Caps │ A │ S │ D │ F │ G │ H │ J │ K │ L │ Ö │ Ä │ # │    │
├────┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴───┴────┤
│Shft│ < │ Y │ X │ C │ V │ B │ N │ M │ , │ . │ - │  Shift   │
└────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴──────────┘

Key Differences:
  - Y and Z are swapped
  - Umlauts (Ü, Ö, Ä) replace [, ;, '
  - @ is AltGr+Q
  - Special chars via AltGr
```

### French AZERTY
```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───────┐
│ ² │ & │ é │ " │ ' │ ( │ - │ è │ _ │ ç │ à │ ) │ = │ Bksp  │
├───┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─────┤
│ Tab │ A │ Z │ E │ R │ T │ Y │ U │ I │ O │ P │ ^ │ $ │Enter│
├─────┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┬──┴┐    │
│ Caps │ Q │ S │ D │ F │ G │ H │ J │ K │ L │ M │ ù │ * │    │
├────┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴───┴────┤
│Shft│ < │ W │ X │ C │ V │ B │ N │ , │ ; │ : │ ! │  Shift   │
└────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴──────────┘

Key Differences:
  - A/Q and Z/W are swapped
  - Numbers require Shift
  - Many special chars via AltGr
```

---

## Flipper Zero Layout Configuration

### Setting Layout in Payload
```
REM Set keyboard layout
ALTCODE DE

REM Or in badusb config:
LOCALE de
```

### Available Layouts
| Code | Layout |
|------|--------|
| US | US English (Default) |
| UK | UK English |
| DE | German |
| FR | French |
| ES | Spanish |
| IT | Italian |
| PT | Portuguese |
| RU | Russian |
| DK | Danish |
| NO | Norwegian |
| SE | Swedish |
| FI | Finnish |
| BE | Belgian |
| CH | Swiss |
| BR | Brazilian Portuguese |

---

## Cross-Layout Compatible Commands

### Universal Commands (No Special Chars)
```ducky
REM These work on most layouts:
WINDOWS r
STRING cmd
ENTER
STRING powershell
ENTER
STRING whoami
ENTER
```

### Problematic Characters
```
Characters that vary by layout:
  @ # $ % ^ & * ( ) _ + { } | : " < > ?
  [ ] \ ; ' , . / ` ~

Safe characters (same on most layouts):
  A-Z a-z 0-9 Space Enter Tab
```

### Layout-Aware Payload Template
```ducky
REM Universal payload structure
REM Avoid special characters where possible

DELAY 1000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 500

REM Use ALT codes for problematic chars
REM ALT+64 = @ on numpad
```

---

## ALT Code Reference

### Windows ALT Codes (Numpad)
| Character | ALT Code | Character | ALT Code |
|-----------|----------|-----------|----------|
| @ | ALT+64 | # | ALT+35 |
| $ | ALT+36 | % | ALT+37 |
| ^ | ALT+94 | & | ALT+38 |
| * | ALT+42 | ( | ALT+40 |
| ) | ALT+41 | _ | ALT+95 |
| + | ALT+43 | { | ALT+123 |
| } | ALT+125 | \| | ALT+124 |
| : | ALT+58 | " | ALT+34 |
| < | ALT+60 | > | ALT+62 |
| ? | ALT+63 | \ | ALT+92 |
| / | ALT+47 | ~ | ALT+126 |
| ` | ALT+96 | [ | ALT+91 |
| ] | ALT+93 | ; | ALT+59 |
| ' | ALT+39 | , | ALT+44 |
| . | ALT+46 | = | ALT+61 |

### Using ALT Codes in Payloads
```ducky
REM Type @ using ALT code
HOLD ALT
NUMPAD 6
NUMPAD 4
RELEASE ALT
```

---

## Testing Layout Detection

### PowerShell Layout Detector
```powershell
# Get current keyboard layout
Get-WinUserLanguageList | Select-Object LanguageTag, InputMethodTips
```

### Linux Layout Check
```bash
# Get current layout
setxkbmap -query

# List available layouts
localectl list-keymaps
```

### macOS Layout Check
```bash
# Get current input source
defaults read ~/Library/Preferences/com.apple.HIToolbox.plist AppleInputSourceHistory
```

---

[← USB VID/PID Database](../04_USB_VID_PID_Database/) | [Back to Technical Addendum](../README.md) | [Next: MITRE ATT&CK Mapping →](../06_MITRE_ATT_CK_Mapping/)
