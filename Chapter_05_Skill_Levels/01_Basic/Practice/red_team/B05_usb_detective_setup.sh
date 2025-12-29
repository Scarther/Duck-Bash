#!/bin/bash
#######################################
# CTF Scenario B05: USB Detective
# Red Team Setup Script
# Purpose: Simulate USB device forensics scenario
# Level: Basic
#######################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║          RED TEAM - CTF SCENARIO SETUP                     ║${NC}"
echo -e "${RED}║          B05: USB Detective                                ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

SETUP_USER="${SUDO_USER:-$USER}"
echo -e "${YELLOW}[*] Setting up scenario for user: $SETUP_USER${NC}"

# Create simulated USB forensics log
echo -e "${YELLOW}[*] Creating USB connection history...${NC}"

cat > /var/log/usb_forensics.log << 'EOF'
========================================
USB DEVICE CONNECTION LOG
Generated for CTF Training
========================================

[08:30:15] USB Device Connected
  Vendor ID:  046D
  Product ID: C52B
  Manufacturer: Logitech
  Product: Unifying Receiver
  Serial: 1234567890
  Status: LEGITIMATE - Known wireless mouse receiver

[09:45:22] USB Device Connected
  Vendor ID:  0781
  Product ID: 5567
  Manufacturer: SanDisk
  Product: Cruzer Blade
  Serial: ABCD1234EFGH
  Status: LEGITIMATE - Known USB storage device

[10:15:03] USB Device Connected
  Vendor ID:  0483
  Product ID: 5740
  Manufacturer: Flipper Devices
  Product: Flipper Zero
  Serial: flip_abc123
  Status: SUSPICIOUS - Known BadUSB device!
  FLAG{usb_forensics_master}
  Note: This device can emulate keyboards and inject keystrokes

[11:30:45] USB Device Connected
  Vendor ID:  8087
  Product ID: 0026
  Manufacturer: Intel Corp
  Product: Bluetooth Device
  Serial: None
  Status: LEGITIMATE - Built-in Bluetooth adapter

[14:22:11] USB Device Connected
  Vendor ID:  413C
  Product ID: 2107
  Manufacturer: Dell
  Product: USB Keyboard
  Serial: None
  Status: LEGITIMATE - Standard Dell keyboard

========================================
END OF LOG
========================================
EOF

chmod 644 /var/log/usb_forensics.log

# Create additional clue in dmesg-style log
cat > /tmp/.kernel_usb.log << 'EOF'
[12345.123456] usb 1-1: new full-speed USB device number 5 using xhci_hcd
[12345.234567] usb 1-1: New USB device found, idVendor=0483, idProduct=5740
[12345.345678] usb 1-1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[12345.456789] usb 1-1: Product: Flipper Zero
[12345.567890] usb 1-1: Manufacturer: Flipper Devices Inc.
[12345.678901] input: Flipper Zero as /devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0/0003:0483:5740.0001/input/input5
[12345.789012] hid-generic 0003:0483:5740.0001: input: USB HID v1.11 Keyboard
[12346.000000] WARNING: Rapid keystroke injection detected!
EOF

echo -e "${GREEN}[✓] Scenario B05 setup complete${NC}"
echo ""
echo -e "${YELLOW}Instructions for Blue Team:${NC}"
echo "1. Multiple USB devices were connected today"
echo "2. Analyze the connection history"
echo "3. Identify the suspicious device (hint: known BadUSB VID/PID)"
echo "4. Find the flag associated with the malicious device"
echo ""
echo -e "${RED}Blue Team should NOT look at this script!${NC}"
