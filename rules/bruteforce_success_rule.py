import time


class BruteForceSuccessRule:

    def __init__(self):
        self.failed_ips = {}

    def check(self, event):

        if event["event"] == "FAILED_LOGIN":
            ip = event["ip"]
            self.failed_ips.setdefault(ip, []).append(time.time())

        if event["event"] == "SUCCESS_LOGIN":
            ip = event["ip"]

            attempts = self.failed_ips.get(ip, [])

            recent = [
                t for t in attempts
                if time.time() - t <= 120
            ]

            if len(recent) >= 5:
                return {
                    "alert_type": "SSH_BRUTE_FORCE_SUCCESS",
                    "severity": "CRITICAL",
                    "ip": ip,
                    "failed_attempts": len(recent)
                }

        return None