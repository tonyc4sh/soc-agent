import time
from collections import defaultdict

class SSHBruteForceRule:

    def __init__(self):
        self.attempts = {}
        self.alerted_ips = set()

    def check(self, event):

        if event["event"] != "FAILED_LOGIN":
            return None

        ip = event["ip"]

        self.attempts.setdefault(ip, []).append(time.time())

        # filtr 60s
        self.attempts[ip] = [
            t for t in self.attempts[ip]
            if time.time() - t <= 60
        ]

        if len(self.attempts[ip]) >= 5:

            if ip in self.alerted_ips:
                return None

            self.alerted_ips.add(ip)

            return {
                "alert_type": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "ip": ip,
                "attempts_last_60s": len(self.attempts[ip])
            }