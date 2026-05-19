import subprocess
import os
from datetime import datetime

HOST_ID = os.uname().nodename

def generate_dashboard():
    tools = {
        "ClamAV": "clamscan",
        "Fail2ban": "fail2ban-server", 
        "UFW": "ufw",
        "Python3": "python3"
    }
    
    host_ip = subprocess.getoutput("hostname -I").strip()
    
    html = f"""<!DOCTYPE html>
<html>
<head><title>ASND Dashboard</title>
<meta http-equiv="refresh" content="60">
<style>
body {{ font-family: Arial; background: #1a1a2e; color: white; padding: 20px; }}
h1 {{ color: #00d4ff; }}
table {{ width: 100%; background: #16213e; }}
th {{ background: #00d4ff; color: black; padding: 10px; }}
td {{ padding: 10px; }}
.installed {{ color: #00ff88; }}
.missing {{ color: #ff4444; }}
</style>
</head>
<body>
<h1>🛡️ ASND Security Dashboard</h1>
<p>Host: {HOST_ID} | IP: {host_ip}</p>
<p>Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<table>
<tr><th>Security Tool</th><th>Status</th></tr>
"""
    for name, cmd in tools.items():
        result = subprocess.run(['which', cmd], capture_output=True)
        status = '<span class="installed">✅ INSTALLED</span>' if result.returncode == 0 else '<span class="missing">❌ MISSING</span>'
        html += f"<tr><td>{name}</td><td>{status}</td></tr>"
    
    html += "</table><p>ASND Security Agent - Monitoring Active</p></body></html>"
    
    os.makedirs('/var/www/html', exist_ok=True)
    with open('/var/www/html/dashboard.html', 'w') as f:
        f.write(html)
    print("Dashboard created at /var/www/html/dashboard.html")

if __name__ == "__main__":
    generate_dashboard()
EOF

# Install Apache and create dashboard
sudo apt install apache2 -y
python3 make_dashboard.py

# Find your IP
hostname -I
