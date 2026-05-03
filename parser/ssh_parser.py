import re


class SSHParser:

    def __init__(self):
        self.ip_pattern = re.compile(r'from (\d+\.\d+\.\d+\.\d+)')
        self.user_pattern = re.compile(r'for (\w+)')
        self.pid_pattern = re.compile(r'sshd\[(\d+)\]')
        self.closed_user_pattern = re.compile(r'user (\w+)')

    def _extract(self, pattern, text):
        """Bezpieczne wyciąganie danych z regexa"""
        match = pattern.search(text)
        return match.group(1) if match else None

    def parse(self, line: str):
        line = line.strip()

        # FAILED LOGIN
        if "Failed password" in line:
            return {
                "event": "FAILED_LOGIN",
                "ip": self._extract(self.ip_pattern, line),
                "raw": line
            }

        # SUCCESS LOGIN
        if "Accepted" in line and "sshd" in line:
            return {
                "event": "SUCCESS_LOGIN",
                "ip": self._extract(self.ip_pattern, line),
                "user": self._extract(self.user_pattern, line),
                "pid": self._extract(self.pid_pattern, line),
                "raw": line
            }

        # SESSION CLOSED
        if "session closed" in line:
            return {
                "event": "SESSION_CLOSED",
                "user": self._extract(self.closed_user_pattern, line),
                "pid": self._extract(self.pid_pattern, line),  # może być None (pam_unix)
                "raw": line
            }

        return None