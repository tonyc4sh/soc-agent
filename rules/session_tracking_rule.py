import time

class SessionTrackingRule:

    def __init__(self):
        self.active_sessions = {}

    def check(self, event):

        if event["event"] == "SUCCESS_LOGIN":

            pid = event.get("pid")
            if not pid:
                return None

            self.active_sessions[pid] = {
                "user": event.get("user"),
                "ip": event.get("ip"),
                "start_time": time.time()
            }

            return None

        if event["event"] == "SESSION_CLOSED":

            user = event.get("user")

            for pid, session in list(self.active_sessions.items()):
                if session["user"] == user:

                    self.active_sessions.pop(pid)

                    duration = int(time.time() - session["start_time"])

                    return {
                        "alert_type": "SSH_SESSION_SUMMARY",
                        "severity": "INFO",
                        "user": session["user"],
                        "ip": session["ip"],
                        "duration_seconds": duration
                    }

            return None

        return None