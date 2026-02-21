class FailedLoginRule:

    def check(self, event):

        if event["event"] == "FAILED_LOGIN":
            return {
                "alert_type": "FAILED_SSH_LOGIN",
                "severity": "MEDIUM",
                "data": event
            }

        return None