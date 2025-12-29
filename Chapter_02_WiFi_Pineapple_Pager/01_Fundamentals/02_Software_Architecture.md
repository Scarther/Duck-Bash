# Software Architecture

## Operating System

The WiFi Pineapple runs OpenWrt, a Linux distribution designed for embedded devices.

```
┌─────────────────────────────────────────────────────────────┐
│                    SOFTWARE STACK                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                  WEB INTERFACE                       │   │
│   │            (PHP + JavaScript)                        │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                   PINEAPPLE API                      │   │
│   │               (REST + WebSocket)                     │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                    MODULES                           │   │
│   │     (PineAP, Recon, Logging, etc.)                   │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                  CORE SERVICES                       │   │
│   │   (nginx, php-fpm, hostapd, dnsmasq, etc.)          │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                  OPENWRT LINUX                       │   │
│   │            (Kernel + BusyBox + ubus)                 │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                    HARDWARE                          │   │
│   │          (WiFi Radios, Storage, USB)                 │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Filesystem Layout

```
/
├── bin/                    # Essential binaries
├── etc/                    # Configuration files
│   ├── config/             # OpenWrt UCI configs
│   ├── init.d/             # Startup scripts
│   ├── rc.d/               # Runlevel links
│   └── pineapple/          # Pineapple configs
├── lib/                    # Libraries
├── overlay/                # Writable overlay (changes stored here)
├── pineapple/              # Pineapple application
│   ├── api/                # REST API code
│   ├── modules/            # Installed modules
│   ├── components/         # UI components
│   └── scripts/            # Helper scripts
├── root/                   # Root home directory
├── sd/                     # SD card mount point
├── tmp/                    # Temporary files (RAM)
├── usr/                    # User binaries
│   ├── bin/                # User programs
│   ├── lib/                # User libraries
│   └── sbin/               # System binaries
└── var/                    # Variable data
    ├── log/                # Log files
    └── run/                # Runtime data
```

---

## Key Directories

### /pineapple/ - Application Root
```bash
/pineapple/
├── api/                    # PHP API endpoints
│   ├── pineap.php          # PineAP API
│   ├── recon.php           # Recon API
│   └── ...
├── modules/                # Installed modules
│   ├── PineAP/
│   ├── Recon/
│   ├── Logging/
│   └── ...
├── components/             # UI components
├── scripts/                # Shell scripts
│   ├── pineap_start.sh
│   ├── pineap_stop.sh
│   └── ...
└── version                 # Firmware version
```

### /etc/config/ - UCI Configuration
```bash
/etc/config/
├── dhcp                    # DHCP/DNS settings
├── dropbear                # SSH settings
├── firewall                # Firewall rules
├── network                 # Network config
├── pineap                  # PineAP config
├── system                  # System settings
└── wireless                # WiFi config
```

### /tmp/ - Temporary Storage
```bash
/tmp/                       # RAM-based, fast but volatile
├── dnsmasq.leases          # DHCP leases
├── hostapd.conf            # Runtime hostapd config
├── pineap.log              # PineAP log
└── *.pid                   # Process IDs
```

---

## Core Services

### Service Management

```bash
# List services
ls /etc/init.d/

# Start/stop/restart
/etc/init.d/nginx start
/etc/init.d/nginx stop
/etc/init.d/nginx restart

# Enable/disable at boot
/etc/init.d/nginx enable
/etc/init.d/nginx disable
```

### Key Services

| Service | Purpose | Port |
|---------|---------|------|
| nginx | Web server | 1471 |
| php-fpm | PHP processor | - |
| hostapd | Access point | - |
| dnsmasq | DHCP/DNS | 53, 67 |
| dropbear | SSH server | 22 |
| crond | Scheduled tasks | - |

### Service Scripts

```bash
#!/bin/sh /etc/rc.common
# Custom service example
# /etc/init.d/myservice

START=99
STOP=10

start() {
    echo "Starting myservice"
    /path/to/myservice &
}

stop() {
    echo "Stopping myservice"
    killall myservice
}
```

---

## Configuration System (UCI)

OpenWrt uses UCI (Unified Configuration Interface):

```bash
# View configuration
uci show network
uci show wireless

# Set value
uci set wireless.radio0.channel=6

# Commit changes
uci commit wireless

# Reload service
wifi reload
```

### Common UCI Commands

```bash
# Network
uci show network.lan
uci set network.lan.ipaddr='192.168.1.1'
uci commit network
/etc/init.d/network restart

# Wireless
uci show wireless
uci set wireless.default_radio0.ssid='MySSID'
uci commit wireless
wifi

# Firewall
uci show firewall
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-SSH'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='22'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall restart
```

---

## Package Management (opkg)

```bash
# Update package list
opkg update

# Search packages
opkg list | grep aircrack

# Install package
opkg install aircrack-ng

# Remove package
opkg remove aircrack-ng

# List installed
opkg list-installed

# Check package info
opkg info aircrack-ng

# Find package files
opkg files aircrack-ng
```

### Essential Packages

```bash
# Wireless tools
opkg install aircrack-ng hostapd-utils wireless-tools

# Network tools
opkg install tcpdump nmap netcat

# Development
opkg install python3 bash

# Utilities
opkg install nano screen tmux
```

---

## Process Management

```bash
# List processes
ps w
ps aux

# Find process
pgrep hostapd
pidof dnsmasq

# Kill process
kill PID
killall processname
kill -9 PID  # Force kill

# Background/foreground
./script.sh &          # Run in background
fg                     # Bring to foreground
bg                     # Continue in background
nohup ./script.sh &    # Survive logout
```

---

## Logging System

### Log Locations

```bash
# System log
logread
logread -f  # Follow

# Kernel messages
dmesg

# Service logs
cat /var/log/nginx/access.log
cat /var/log/nginx/error.log

# PineAP log
cat /tmp/pineap.log
```

### Logging to Syslog

```bash
# From script
logger -t myscript "This is a log message"

# View
logread | grep myscript
```

---

## Startup Sequence

```
┌─────────────────────────────────────────────────────────────┐
│                    BOOT SEQUENCE                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. HARDWARE INIT                                          │
│      └── CPU, RAM, Storage initialization                   │
│                                                              │
│   2. BOOTLOADER (U-Boot)                                    │
│      └── Load kernel image                                  │
│                                                              │
│   3. KERNEL INIT                                            │
│      └── Mount root filesystem                              │
│      └── Start init process                                 │
│                                                              │
│   4. INIT SCRIPTS                                           │
│      └── /etc/rc.d/S* scripts run in order                  │
│      └── S10boot, S19dnsmasq, S50dropbear...               │
│                                                              │
│   5. SERVICES START                                         │
│      └── Network, WiFi, Web server                          │
│                                                              │
│   6. USER SCRIPTS                                           │
│      └── /etc/rc.local                                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Run Scripts at Startup

```bash
# Add to /etc/rc.local (before 'exit 0')
/root/my_startup_script.sh &

# Or create init.d script
chmod +x /etc/init.d/myscript
/etc/init.d/myscript enable
```

---

## Memory Management

```bash
# Check memory
free -m

# Clear caches
echo 3 > /proc/sys/vm/drop_caches

# Find memory-hungry processes
ps aux --sort=-%mem | head
```

### Memory Tips
- `/tmp/` is RAM-based
- Clear old capture files
- Use SD card for large storage
- Restart services if memory low

---

## Overlay Filesystem

OpenWrt uses SquashFS + overlayfs:

```
┌──────────────────────────────────────────┐
│           READ-WRITE OVERLAY              │
│         (Changes stored here)             │
└─────────────────┬────────────────────────┘
                  │
┌─────────────────▼────────────────────────┐
│          READ-ONLY SQUASHFS              │
│         (Original firmware)               │
└──────────────────────────────────────────┘
```

```bash
# See overlay usage
df -h /overlay

# Reset to factory (WARNING: erases changes)
firstboot
reboot
```

---

[← Hardware Overview](01_Hardware_Overview.md) | [Back to Fundamentals](README.md) | [Next: Aircrack-ng Suite →](03_Aircrack_Suite.md)
