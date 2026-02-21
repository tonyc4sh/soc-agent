class SuccessfulLoginRule:

    def check(self, event):

        if event["event"] == "SUCCESS_LOGIN":
            return {
                "alert_type": "SUCCESSFUL_SSH_LOGIN",
                "severity": "LOW",
                "ip": event.get("ip"),
                "data": event
            }

        return None