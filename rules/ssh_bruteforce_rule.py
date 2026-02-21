import time
from collections import defaultdict

class SSHBruteForceRule:

    def __init__(self):
        self.failed_attempts = defaultdict(list)

    def check(self, event):

        if event["event"] != "FAILED_LOGIN":
            return None

        ip = event.get("ip")
        now = time.time()

        self.failed_attempts[ip].append(now)

        # usuń starsze niż 60 sekund
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip]
            if now - t <= 60
        ]

        if len(self.failed_attempts[ip]) >= 5:
            return {
                "alert_type": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "ip": ip,
                "attempts_last_60s": len(self.failed_attempts[ip])
            }

        return None