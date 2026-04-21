#!/usr/bin/env python3

import time
import re
import json
import subprocess
import os
import sys
import hashlib
import logging
import threading
import queue
import requests # type: ignore
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# ------------------ LOGGING (SECURE) ------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("security_agent.log"),
        logging.StreamHandler()
    ]
)

# ------------------ CONFIG ------------------
HOST_ID = os.environ.get('HOST_ID', 'UNKNOWN_HOST')

CONFIG = {
    'auth_log': '/var/log/auth.log',
    'failed_login_threshold': 3,
    'sudo_failure_threshold': 2,
    'threshold_window_minutes': 5,

    'sensitive_files': [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/sshd_config'
    ],

    # SECURE: pull from environment
    'central_server': os.environ.get("CENTRAL_SERVER"),
    'api_key': os.environ.get("API_KEY"),

    'scan_interval': 60,
    'enable_realtime': True
}

# ------------------ ALERT TRACKER ------------------
class AlertTracker:
    def __init__(self, window_minutes=5):
        self.window_minutes = window_minutes
        self.events = defaultdict(list)
        self.lock = threading.Lock()

    def add_event(self, event_type):
        with self.lock:
            self.events[event_type].append(datetime.now())
            self._clean(event_type)

    def get_count(self, event_type):
        with self.lock:
            self._clean(event_type)
            cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
            return sum(1 for t in self.events[event_type] if t > cutoff)

    def _clean(self, event_type):
        cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
        self.events[event_type] = [t for t in self.events[event_type] if t > cutoff]


# ------------------ FILE INTEGRITY ------------------
class FileIntegrityMonitor:
    def __init__(self, files):
        self.files = files
        self.baseline_path = f"./baseline_{HOST_ID}.json"
        self.baselines = self._load()

    def _load(self):
        if os.path.exists(self.baseline_path):
            try:
                return json.load(open(self.baseline_path))
            except:
                return {}
        return {}

    def _save(self):
        json.dump(self.baselines, open(self.baseline_path, "w"), indent=2)

    def _hash(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None

    def check(self):
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
                alerts.append(f"File changed: {f}")
                self.baselines[f] = h

        self._save()
        return alerts


# ------------------ ALERT MANAGER ------------------
class AlertManager:
    def __init__(self):
        self.tracker = AlertTracker()

    def send(self, message, severity="MEDIUM", rule="unknown"):
        alert = {
            "host": HOST_ID,
            "time": datetime.now().isoformat(),
            "severity": severity,
            "rule": rule,
            "message": message
        }

        logging.warning(f"[{severity}] {message}")

        # SECURE: send to server if configured
        if CONFIG["central_server"] and CONFIG["api_key"]:
            try:
                requests.post(
                    CONFIG["central_server"],
                    json=alert,
                    headers={"Authorization": f"Bearer {CONFIG['api_key']}"},
                    timeout=5
                )
            except Exception as e:
                logging.error(f"Failed to send alert: {e}")


# ------------------ LOG MONITOR ------------------
class LogMonitor:
    def __init__(self, path, alerts):
        self.path = path
        self.alerts = alerts
        self.running = True

    def start(self):
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()

    def _run(self):
        try:
            process = subprocess.Popen(
                ["tail", "-F", self.path],
                stdout=subprocess.PIPE,
                text=True
            )

            for line in process.stdout:
                if not self.running:
                    break
                self._process(line.strip())

        except Exception as e:
            logging.error(f"log monitor error: {e}")

    def _process(self, line):
        if not line:
            return

        # SSH FAIL
        m = re.search(r"Failed password for (\S+) from (\S+)", line)
        if m:
            user, ip = m.groups()
            self.alerts.tracker.add_event("ssh_fail")

            if self.alerts.tracker.get_count("ssh_fail") >= CONFIG["failed_login_threshold"]:
                self.alerts.send(f"Multiple SSH failures from {ip}", "HIGH", "ssh_fail")

        # SUDO FAIL (FIXED LOGIC)
        if ("sudo" in line) and ("failure" in line.lower()):
            self.alerts.tracker.add_event("sudo_fail")

            if self.alerts.tracker.get_count("sudo_fail") >= CONFIG["sudo_failure_threshold"]:
                self.alerts.send("Repeated sudo failures", "HIGH", "sudo_fail")

        # ROOT LOGIN
        if "Accepted password for root" in line:
            self.alerts.send("Root login detected", "HIGH", "root_login")


# ------------------ MAIN AGENT ------------------
class SecurityAgent:
    def __init__(self):
        self.alerts = AlertManager()
        self.file_monitor = FileIntegrityMonitor(CONFIG["sensitive_files"])
        self.running = True

    def start(self):
        logging.info(f"Agent started on {HOST_ID}")

        # Start log monitor
        if CONFIG["enable_realtime"]:
            self.log_monitor = LogMonitor(CONFIG["auth_log"], self.alerts)
            self.log_monitor.start()

        # File monitoring loop
        while self.running:
            try:
                alerts = self.file_monitor.check()
                for a in alerts:
                    self.alerts.send(a, "HIGH", "file_change")

                time.sleep(CONFIG["scan_interval"])

            except Exception as e:
                logging.error(f"Agent error: {e}")
                time.sleep(5)

    def stop(self):
        self.running = False
        logging.info("Agent stopped")


# ------------------ ENTRY ------------------
if __name__ == "__main__":
    agent = SecurityAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()