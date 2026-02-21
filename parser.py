import re

class SSHParser:

    @staticmethod
    def parse(line: str):

        if "Failed password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else None

            return {
                "event": "FAILED_LOGIN",
                "ip": ip,
                "raw": line
            }

        if "Accepted" in line and "sshd" in line:
            return {
                "event": "SUCCESS_LOGIN",
                "raw": line
            }

        return None
