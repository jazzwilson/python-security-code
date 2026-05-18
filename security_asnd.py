#!/usr/bin/env python3
import time
import requests
import socket
import json
import os
import subprocess
import re
import threading
from datetime import datetime

HOST_ID = socket.gethostname()

# Config file
config_file = '/etc/asnd/config.json'

# Try to load config
try:
    with open(config_file, 'r') as f:
        config = json.load(f)
except:
    config = {'slack_webhook': '', 'scan_interval': 30}

webhook = config.get('slack_webhook', '')

def send_slack_message(message, severity="INFO"):
    """Send a message to Slack"""
    if not webhook:
        print("No webhook configured")
        return
    try:
        payload = {"text": f"[{severity}] {HOST_ID}: {message}"}
        requests.post(webhook, json=payload, timeout=5)
        print(f"Alert sent: {message[:50]}")
    except Exception as e:
        print(f"Failed to send: {e}")

def watch_logs_continuously():
    """Watch auth.log in real-time for failed logins"""
    try:
        process = subprocess.Popen(['sudo', 'tail', '-F', '/var/log/auth.log'],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True)

        print("Log monitoring active - watching for failed logins...")

        for line in process.stdout:
            if 'Failed password' in line:
                match = re.search(r'Failed password for (\S+) from (\S+)', line)
                if match:
                    user, ip = match.groups()
                    send_slack_message(f"Failed SSH login! User: {user} from IP: {ip}", "HIGH")
                    print(f"Alert sent: Failed login for {user} from {ip}")

            elif 'sudo' in line and 'failure' in line.lower():
                send_slack_message(f"Sudo failure detected", "MEDIUM")
                print(f"Alert sent: Sudo failure")

    except KeyboardInterrupt:
        print("\nStopping log watcher")
    except Exception as e:
        print(f"Error watching logs: {e}")

# ==================== DASHBOARD GENERATOR ====================

def generate_dashboard():
    """Create HTML dashboard showing installed vs missing software"""
    print("📊 Generating security dashboard...")

    tools = {
        "ClamAV (Antivirus)": "clamscan",
        "Fail2ban (Brute Force)": "fail2ban-server",
        "UFW (Firewall)": "ufw",
        "Python3": "python3",
        "Git": "git"
    }

    # Get host IP
    try:
        host_ip = subprocess.getoutput("hostname -I").strip()
    except:
        host_ip = "Unknown"

    # Build HTML
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>ASND Security Dashboard - {HOST_ID}</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="60">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #eee;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            color: #00d4ff;
            margin-bottom: 10px;
            font-size: 2em;
        }}
        .header {{
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            overflow: hidden;
        }}
        th {{
            background: #00d4ff;
            color: #1a1a2e;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .installed {{
            color: #00ff88;
            font-weight: bold;
        }}
        .missing {{
            color: #ff4444;
            font-weight: bold;
        }}
        .footer {{
            margin-top: 20px;
            text-align: center;
            font-size: 0.8em;
            color: #888;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ ASND Security Dashboard</h1>
        <p>Host: <strong>{HOST_ID}</strong> | IP: <strong>{host_ip}</strong></p>
        <p>Last Updated: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></p>
    </div>

    <h3>📊 Security Tools Status</h3>
    <table>
        <tr>
            <th>Security Tool</th>
            <th>Status</th>
            <th>Recommendation</th>
        </tr>
"""

    for tool_name, command in tools.items():
        result = subprocess.run(['which', command], capture_output=True, text=True)
        if result.returncode == 0:
            status = '<span class="installed">✅ INSTALLED</span>'
            recommendation = 'Active'
        else:
            status = '<span class="missing">❌ MISSING</span>'
            recommendation = f'Run: sudo apt install {command.split()[0]}'

        html += f"""
        <tr>
            <td>{tool_name}</td>
            <td>{status}</td>
            <td>{recommendation}</td>
        </tr>
        """

    html += f"""
    </table>

    <div style="margin-top: 20px;">
        <h3>📋 System Information</h3>
        <table>
            <tr><td>Hostname</td><td>{HOST_ID}</td></tr>
            <tr><td>OS</td><td>{subprocess.getoutput('uname -a')[:80]}</td></tr>
            <tr><td>Uptime</td><td>{subprocess.getoutput('uptime -p')}</td></tr>
            <tr><td>Last Scan</td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
        </table>
    </div>

    <div class="footer">
        <p>Auto Secure Network Deployment (ASND) - Security Monitoring Agent</p>
        <p>Alerts are sent to Slack in real-time | Dashboard refreshes every 60 seconds</p>
    </div>
</div>
</body>
</html>
"""

    # Save dashboard
    dashboard_path = '/var/www/html/dashboard.html'
    try:
        os.makedirs('/var/www/html', exist_ok=True)
        with open(dashboard_path, 'w') as f:
            f.write(html)
        print(f"✅ Dashboard saved to {dashboard_path}")
    except Exception as e:
        print(f"❌ Could not save dashboard: {e}")
        # Try alternative location
        dashboard_path = '/tmp/dashboard.html'
        with open(dashboard_path, 'w') as f:
            f.write(html)
        print(f"✅ Dashboard saved to {dashboard_path}")

# ==================== MAIN AGENT ====================

print("=" * 50)
print("ASND Security Agent with Login Monitoring")
print("Host: " + HOST_ID)
print("=" * 50)

# Send startup alert
send_slack_message("Security Agent with login monitoring is online", "INFO")

# Start log monitoring in background
log_thread = threading.Thread(target=watch_logs_continuously, daemon=True)
log_thread.start()

# Generate initial dashboard
generate_dashboard()

# Main heartbeat loop
count = 0
try:
    while True:
        time.sleep(config.get('scan_interval', 30))
        count += 1
        print(f"Heartbeat {count} - monitoring active")

        # Regenerate dashboard every 5 heartbeats (approx every 2-3 minutes)
        if count % 5 == 0:
            generate_dashboard()

        if count % 5 == 0:
            send_slack_message(f"Heartbeat - Monitoring active", "INFO")
except KeyboardInterrupt:
    print("\nStopping agent...")
    send_slack_message("Security Agent stopping", "INFO")
    print("Agent stopped")
