import re

class SSHParser:

    def parse(self, line):

        if "Failed password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else None

            return {
                "event": "FAILED_LOGIN",
                "ip": ip,
                "raw": line.strip()
            }

        if "Accepted" in line and "sshd" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else None

            return {
                "event": "SUCCESS_LOGIN",
                "ip": ip,
                "raw": line.strip()
            }

        return None