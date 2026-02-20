class RuleEngine:

    def process(self, parsed_event):
        if not parsed_event:
            return None

        event = parsed_event["event"]

        if event == "FAILED_LOGIN":
            return {
                "alert_type": "FAILED_SSH_LOGIN",
                "severity": "MEDIUM",
                "data": parsed_event
            }

        if event == "SUCCESS_LOGIN":
            return {
                "alert_type": "SUCCESSFUL_SSH_LOGIN",
                "severity": "LOW",
                "data": parsed_event
            }

        return None
