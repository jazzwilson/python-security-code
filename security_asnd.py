#!/usr/bin/env python3
"""
Auto Secure Network Deployment (ASND) - Security Agent
Author: Jasminn Wilson
Description: Deploys and monitors security software across network devices
"""

import time
import re
import json
import subprocess
import os
import sys
import hashlib
import logging
import threading
import socket
import platform
import psutil  # type: ignore (pip install psutil)
import requests # type: ignore
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ------------------ CONFIGURATION ------------------

HOST_ID = os.environ.get('HOST_ID', socket.gethostname())
HOST_IP = socket.gethostbyname(HOST_ID)

# Load configuration from environment or config file
CONFIG_FILE = "/etc/asnd/config.json"
DEFAULT_CONFIG = {
    'auth_log': '/var/log/auth.log' if platform.system() == 'Linux' else 'C:\\Windows\\System32\\LogFiles\\Security',
    'failed_login_threshold': 3,
    'sudo_failure_threshold': 2,
    'threshold_window_minutes': 5,
    
    'sensitive_files': [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/sshd_config'
    ] if platform.system() == 'Linux' else [
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\Windows\\System32\\config\\SECURITY'
    ],
    
    # Slack webhook URL (REPLACE WITH YOURS)
    'slack_webhook': os.environ.get("SLACK_WEBHOOK", "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"),
    
    # Central server for dashboard (optional)
    'central_server': os.environ.get("CENTRAL_SERVER", "http://localhost:5000/api/alerts"),
    'api_key': os.environ.get("API_KEY", ""),
    
    # Security tool paths
    'security_tools': {
        'linux': ['clamav', 'fail2ban', 'auditd'],
        'windows': ['Windows Defender', 'Malwarebytes']
    },
    
    'scan_interval': 60,  # seconds
    'enable_realtime': True,
    'network_scan_interval': 300,  # 5 minutes
    'deployment_retry_interval': 1800,  # 30 minutes
}

def load_config():
    """Load configuration from file or use defaults"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                user_config = json.load(f)
                DEFAULT_CONFIG.update(user_config)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
    return DEFAULT_CONFIG

CONFIG = load_config()

# ------------------ LOGGING SETUP ------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(host)s] %(message)s",
    handlers=[
        logging.FileHandler(f"asnd_{HOST_ID}.log"),
        logging.StreamHandler()
    ]
)
# Add host to all log entries
logging.LoggerAdapter(logging.getLogger(), {'host': HOST_ID})

# ------------------ ALERT TRACKER ------------------
class AlertTracker:
    """Track alert frequency to prevent flooding"""
    
    def __init__(self, window_minutes=5):
        self.window_minutes = window_minutes
        self.events = defaultdict(list)
        self.lock = threading.Lock()

    def add_event(self, event_type: str):
        with self.lock:
            self.events[event_type].append(datetime.now())
            self._clean(event_type)

    def get_count(self, event_type: str) -> int:
        with self.lock:
            self._clean(event_type)
            cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
            return sum(1 for t in self.events[event_type] if t > cutoff)

    def _clean(self, event_type: str):
        cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
        self.events[event_type] = [t for t in self.events[event_type] if t > cutoff]

# ------------------ SLACK NOTIFICATION ------------------
class SlackNotifier:
    """Send alerts to Slack channel"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.last_alert_time = defaultdict(datetime)
        
    def send(self, message: str, severity: str = "MEDIUM", rule: str = "unknown"):
        """Send alert to Slack with appropriate emoji based on severity"""
        
        # Rate limiting: don't send same alert more than once per minute
        alert_key = f"{rule}_{severity}"
        if alert_key in self.last_alert_time:
            if (datetime.now() - self.last_alert_time[alert_key]).seconds < 60:
                return
        
        self.last_alert_time[alert_key] = datetime.now()
        
        # Choose emoji based on severity
        emoji = {
            "HIGH": ":red_circle: :alert:",
            "MEDIUM": ":orange_circle:",
            "LOW": ":yellow_circle:"
        }.get(severity, ":information_source:")
        
        # Choose color for Slack attachment
        color = {
            "HIGH": "danger",
            "MEDIUM": "warning", 
            "LOW": "good"
        }.get(severity, "#cccccc")
        
        payload = {
            "attachments": [{
                "color": color,
                "title": f"{emoji} ASND Security Alert - {severity}",
                "text": message,
                "fields": [
                    {"title": "Host", "value": HOST_ID, "short": True},
                    {"title": "IP Address", "value": HOST_IP, "short": True},
                    {"title": "Rule", "value": rule, "short": True},
                    {"title": "Time", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "short": True}
                ],
                "footer": "Auto Secure Network Deployment",
                "ts": int(datetime.now().timestamp())
            }]
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            if response.status_code != 200:
                logging.error(f"Slack webhook failed: {response.status_code}")
        except Exception as e:
            logging.error(f"Failed to send Slack alert: {e}")

# ------------------ FILE INTEGRITY MONITOR ------------------
class FileIntegrityMonitor:
    """Monitor sensitive files for unauthorized changes"""
    
    def __init__(self, files: List[str]):
        self.files = files
        self.baseline_path = f"/var/lib/asnd/baseline_{HOST_ID}.json"
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        self.baselines = self._load()

    def _load(self) -> Dict:
        if os.path.exists(self.baseline_path):
            try:
                with open(self.baseline_path, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save(self):
        with open(self.baseline_path, 'w') as f:
            json.dump(self.baselines, f, indent=2)

    def _hash(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None

    def check(self) -> List[str]:
        alerts = []
        for f in self.files:
            if not os.path.exists(f):
                continue
            h = self._hash(f)
            if not h:
                continue
            if f not in self.baselines:
                self.baselines[f] = h
            elif self.baselines[f] != h:
                alerts.append(f"SECURITY: File changed - {f}")
                self.baselines[f] = h
        self._save()
        return alerts

# ------------------ SECURITY TOOL MONITOR ------------------
class SecurityToolMonitor:
    """Monitor that security tools are running"""
    
    def __init__(self):
        self.system = platform.system()
        
    def check_tools(self) -> List[str]:
        """Check if required security tools are running"""
        alerts = []
        def get_dashboard_status(self) -> Dict:
        """Generate dashboard data for IT manager"""
        return {
            "total_hosts": len(self.discovery.known_hosts),
            "protected_hosts": sum(1 for h in self.discovery.known_hosts.values() 
                                  if h.get("status") == "protected"),
            "vulnerable_hosts": sum(1 for h in self.discovery.known_hosts.values() 
                                   if h.get("status") == "new"),
            "last_scan": datetime.now().isoformat(),
            "alerts_today": self._get_alert_count_today()
        }
    
    def _get_alert_count_today(self) -> int:
        """Count today's alerts from log file"""
        today = datetime.now().strftime("%Y-%m-%d")
        count = 0
        log_file = f"asnd_{HOST_ID}.log"
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                for line in f:
                    if today in line:
                        count += 1
        return count

# ------------------ LOG MONITOR (REAL-TIME) ------------------
class LogMonitor:
    """Monitor auth logs for suspicious activity"""
    
    def __init__(self, log_path: str, notifier: SlackNotifier):
        self.log_path = log_path
        self.notifier = notifier
        self.tracker = AlertTracker(CONFIG["threshold_window_minutes"])
        self.running = True

    def start(self):
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()

    def _run(self):
        if not os.path.exists(self.log_path):
            logging.warning(f"Log file {self.log_path} not found")
            return
            
        try:
            process = subprocess.Popen(
                ["tail", "-F", self.log_path] if platform.system() == "Linux" else ["powershell", "Get-Content", "-Wait", self.log_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )

            for line in process.stdout:
                if not self.running:
                    break
                self._process(line.strip())

        except Exception as e:
            logging.error(f"Log monitor error: {e}")

    def _process(self, line: str):
        if not line:
            return

        # SSH failed login attempts
        m = re.search(r"Failed password for (\S+) from (\S+)", line)
        if m:
            user, ip = m.groups()
            self.tracker.add_event("ssh_fail")
            
            count = self.tracker.get_count("ssh_fail")
            if count >= CONFIG["failed_login_threshold"]:
                self.notifier.send(
                    f"🚨 Multiple SSH failures from {ip} (user: {user}) - {count} attempts in {CONFIG['threshold_window_minutes']} minutes",
                    "HIGH",
                    "ssh_bruteforce"
                )

        # Sudo failures
        if "sudo" in line and ("failure" in line.lower() or "FAILED" in line):
            self.tracker.add_event("sudo_fail")
            count = self.tracker.get_count("sudo_fail")
            
            if count >= CONFIG["sudo_failure_threshold"]:
                self.notifier.send(
                    f"⚠️ Repeated sudo failures - {count} attempts in {CONFIG['threshold_window_minutes']} minutes",
                    "HIGH",
                    "sudo_abuse"
                )

        # Root login
        if "Accepted password for root" in line:
            self.notifier.send(
                "🔴 ROOT LOGIN DETECTED - Immediate investigation required",
                "HIGH",
                "root_login"
            )
            
        # New user creation
        if "new user" in line.lower() or "useradd" in line:
            self.notifier.send(
                f"👤 New user created: {line}",
                "MEDIUM",
                "user_creation"
            )

# ------------------ MAIN SECURITY AGENT ------------------
class SecurityAgent:
    """Main security agent orchestrating all monitoring"""
    
    def __init__(self):
        self.notifier = SlackNotifier(CONFIG["slack_webhook"])
        self.file_monitor = FileIntegrityMonitor(CONFIG["sensitive_files"])
        self.tool_monitor = SecurityToolMonitor()
        self.discovery = NetworkDiscovery()
        self.deployment_manager = DeploymentManager(self.notifier)
        self.running = True
        
    def start(self):
        logging.info(f"🚀 ASND Security Agent started on {HOST_ID} ({HOST_IP})")
        self.notifier.send(
            f"✅ Security Agent started on {HOST_ID}",
            "LOW",
            "agent_startup"
        )
        
        # Start real-time log monitoring
        if CONFIG["enable_realtime"] and os.path.exists(CONFIG["auth_log"]):
            self.log_monitor = LogMonitor(CONFIG["auth_log"], self.notifier)
            self.log_monitor.start()
            logging.info("Real-time log monitoring active")
        
        last_network_scan = datetime.now() - timedelta(minutes=10)
        last_dashboard_report = datetime.now() - timedelta(minutes=10)
        
        # Main monitoring loop
        while self.running:
            try:
                # 1. Check file integrity
                file_alerts = self.file_monitor.check()
                for alert in file_alerts:
                    self.notifier.send(alert, "HIGH", "file_integrity")
                
                # 2. Check security tools
                tool_alerts = self.tool_monitor.check_tools()
                for alert in tool_alerts:
                    self.notifier.send(alert, "HIGH", "security_tool")
                    
                    # Attempt auto-remediation for missing tools
                    if "missing" in alert.lower():
                        tool_name = alert.split()[-1]
                        if self.tool_monitor.auto_remediate(tool_name):
                            self.notifier.send(
                                f"🔄 Auto-remediated: {tool_name} has been restarted",
                                "MEDIUM",
                                "auto_remediation"
                            )
                
                # 3. Network discovery (periodic)
                if (datetime.now() - last_network_scan).seconds >= CONFIG["network_scan_interval"]:
                    new_devices = self.discovery.scan_network()
                    for device in new_devices:
                        self.notifier.send(
                            f"🖥️ New device detected: {device} - Initiating security deployment",
                            "MEDIUM",
                            "new_device"
                        )
                        self.deployment_manager.deploy_to_host(device)
                    last_network_scan = datetime.now()
                
                # 4. Dashboard report (every hour)
                if (datetime.now() - last_dashboard_report).seconds >= 3600:
                    status = self.deployment_manager.get_dashboard_status()
                    self._report_dashboard_status(status)
                    last_dashboard_report = datetime.now()
                
                time.sleep(CONFIG["scan_interval"])
                
            except Exception as e:
                logging.error(f"Agent error: {e}")
                time.sleep(5)
    
    def _report_dashboard_status(self, status: Dict):
        """Send periodic dashboard update to Slack"""
        message = f"""📊 *ASND Dashboard Update*
• Total Hosts: {status['total_hosts']}
• Protected: ✅ {status['protected_hosts']}
• Vulnerable: ⚠️ {status['vulnerable_hosts']}
• Alerts Today: {status['alerts_today']}
• Last Scan: {status['last_scan']}
"""
        self.notifier.send(message, "LOW", "dashboard_update")
    
    def stop(self):
        self.running = False
        logging.info("🛑 Security Agent stopped")
        self.notifier.send("Security Agent stopped", "LOW", "agent_stop")

# ------------------ ENTRY POINT ------------------
if __name__ == "__main__":
    # Check for required dependencies
    try:
        import psutil
    except ImportError:
        print("Please install psutil: pip install psutil")
        sys.exit(1)
        
    agent = SecurityAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
        print("\nAgent stopped by user")

import os
import subprocess
from datetime import datetime

def generate_dashboard():
    # 1. Define the tools you want to check
    security_tools = {
        "ClamAV (Antivirus)": "clamscan",
        "Fail2ban (Brute force)": "fail2ban-server",
        "UFW (Firewall)": "ufw",
        "AppArmor": "aa-status"
    }
    
    # 2. HTML Template (Modern, clean dashboard style)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ASND Security Dashboard</title>
        <style>
            body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
            h1 {{ color: #58a6ff; }}
            .container {{ max-width: 800px; margin: auto; background: #161b22; padding: 20px; border-radius: 10px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ text-align: left; padding: 10px; background: #21262d; }}
            td {{ padding: 10px; border-bottom: 1px solid #30363d; }}
            .installed {{ color: #2ea043; font-weight: bold; }}
            .missing {{ color: #f85149; font-weight: bold; }}
            .footer {{ margin-top: 20px; font-size: 0.8em; color: #8b949e; }}
        </style>
    </head>
    <body>
    <div class="container">
        <h1>🛡️ ASND - Endpoint Security Report</h1>
        <p>Host: <strong>{os.uname().nodename}</strong> | IP: {subprocess.getoutput("hostname -I")}</p>
        <p>Last Scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <table>
            <tr><th>Security Tool</th><th>Status</th><th>Action</th></tr>
    """
    
    # 3. The logic to check each tool
    for tool_name, command in security_tools.items():
        # Check if binary exists OR if service is active
        check = subprocess.run(["which", command], capture_output=True, text=True)
        if check.returncode == 0:
            status_html = '<span class="installed">✅ INSTALLED</span>'
            action = "Monitoring Active"
        else:
            status_html = '<span class="missing">❌ MISSING</span>'
            action = f'<a href="https://ubuntu.com/server/docs/security-{tool_name.split()[0].lower()}" target="_blank">Install Guide</a>'
        
        html_content += f"""
            <tr>
                <td>{tool_name}</td>
                <td>{status_html}</td>
                <td>{action}</td>
            </tr>
        """
    
    html_content += """
        </table>
        <div class="footer">
            <p>⚠️ Note: This is an automated report by the ASND Security Agent.</p>
            <p>If a tool is missing, please install it using <code>sudo apt install &lt;toolname&gt;</code></p>
        </div>
    </div>
    </body>
    </html>
    """
    
    # 4. Save the dashboard to a file
    with open("/var/www/html/dashboard.html", "w") as f:
        f.write(html_content)
    
    print("[+] Dashboard generated at /var/www/html/dashboard.html")

        if self.system == "Linux":
            for tool in CONFIG['security_tools']['linux']:
                if not self._check_process(tool):
                    alerts.append(f"SECURITY TOOL MISSING: {tool} is not running")
                    
        elif self.system == "Windows":
            for tool in CONFIG['security_tools']['windows']:
                if not self._check_windows_service(tool):
                    alerts.append(f"SECURITY TOOL MISSING: {tool} is not running")
                    
        return alerts
    
    def _check_process(self, process_name: str) -> bool:
        """Check if a Linux process is running"""
        try:
            result = subprocess.run(
                ["pgrep", "-x", process_name],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False
    
    def _check_windows_service(self, service_name: str) -> bool:
        """Check if a Windows service is running"""
        try:
            result = subprocess.run(
                ["sc", "query", service_name],
                capture_output=True,
                text=True
            )
            return "RUNNING" in result.stdout
        except:
            return False
            
    def auto_remediate(self, tool_name: str) -> bool:
        """Attempt to restart a stopped security tool"""
        logging.info(f"Attempting to restart {tool_name}")
        
        if self.system == "Linux":
            try:
                subprocess.run(["sudo", "systemctl", "start", tool_name], 
                             capture_output=True, check=True)
                return True
            except:
                return False
        return False

# ------------------ NETWORK DISCOVERY ------------------
class NetworkDiscovery:
    """Discover new devices on the network"""
    
    def __init__(self):
        self.known_hosts = self._load_known_hosts()
        self.network_base = self._get_network_base()
        
    def _get_network_base(self) -> str:
        """Get local network base (e.g., 192.168.1.0/24)"""
        try:
            # Get primary IP and determine network
            host_ip = socket.gethostbyname(socket.gethostname())
            parts = host_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            return "192.168.1.0/24"
    
    def _load_known_hosts(self) -> Dict:
        """Load list of known hosts from file"""
        known_file = f"/var/lib/asnd/known_hosts_{HOST_ID}.json"
        if os.path.exists(known_file):
            try:
                with open(known_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_known_hosts(self):
        known_file = f"/var/lib/asnd/known_hosts_{HOST_ID}.json"
        os.makedirs(os.path.dirname(known_file), exist_ok=True)
        with open(known_file, 'w') as f:
            json.dump(self.known_hosts, f, indent=2)
    
    def scan_network(self) -> List[str]:
        """Scan network for new devices"""
        new_devices = []
        
        # Simple ping sweep (use nmap if available for better results)
        base_ip = ".".join(self.network_base.split('.')[:3])
        
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            if ip == HOST_IP:
                continue
                
            # Ping test
            response = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                text=True
            )
            
            if response.returncode == 0:
                if ip not in self.known_hosts:
                    new_devices.append(ip)
                    self.known_hosts[ip] = {
                        "first_seen": datetime.now().isoformat(),
                        "status": "new"
                    }
        
        self._save_known_hosts()
        return new_devices

# ------------------ DEPLOYMENT MANAGER ------------------
class DeploymentManager:
    """Manage deployment of security software to new hosts"""
    
    def __init__(self, notifier: SlackNotifier):
        self.notifier = notifier
        self.deployment_queue = []
        
    def deploy_to_host(self, host_ip: str) -> bool:
        """Deploy security agent to a new host"""
        logging.info(f"Deploying security agent to {host_ip}")
        
        # This would use SSH (Linux) or WinRM (Windows) to install
        # For demonstration, we'll log and notify
        
        self.notifier.send(
            f"New device detected: {host_ip}. Security software deployment initiated.",
            "MEDIUM",
            "auto_deploy"
        )
        
        # Actual deployment logic would go here:
        # - Copy agent script to remote host
        # - Install dependencies
        # - Start agent as service
        
        return True
    
    def verify_deployment(self, host_ip: str) -> bool:
        """Verify that security software is installed on a host"""
        # Check if agent is responding
        # This would query the remote host's API endpoint
        return False
