class SessionClosedRule:

    def check(self, event):

        if event["event"] == "SSH_SESSION_CLOSED":
            return {
                "alert_type": "SSH_SESSION_CLOSED",
                "severity": "INFO",
                "data": event
            }

        return None