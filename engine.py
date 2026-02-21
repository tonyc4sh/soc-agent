import time
from collections import defaultdict

class DetectionEngine:

    def __init__(self):
        self.failed_attempts = defaultdict(list)

    def process(self, event):

        alerts = []

        if event["event"] == "FAILED_LOGIN":
            ip = event.get("ip")
            now = time.time()

            self.failed_attempts[ip].append(now)

            self.failed_attempts[ip] = [
                t for t in self.failed_attempts[ip]
                if now - t <= 60
            ]

            if len(self.failed_attempts[ip]) >= 5:
                alerts.append({
                    "alert_type": "SSH_BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": ip,
                    "attempts": len(self.failed_attempts[ip])
                })

        return alerts
