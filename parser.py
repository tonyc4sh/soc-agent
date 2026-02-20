class SSHParser:

    @staticmethod
    def parse(line: str):
        if "Failed password" in line:
            return {
                "event": "FAILED_LOGIN",
                "raw": line
            }

        if "Accepted password" in line:
            return {
                "event": "SUCCESS_LOGIN",
                "raw": line
            }

        return None
