from watcher.log_watcher import LogWatcher
from parser.ssh_parser import SSHParser
from engine.detection_engine import DetectionEngine

from rules.failed_login_rule import FailedLoginRule
from rules.ssh_bruteforce_rule import SSHBruteForceRule
from rules.success_login_rule import SuccessLoginRule

from outputs.stdout_output import StdoutOutput
from outputs.file_output import FileOutput

import yaml

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def main():
    config = load_config()

    logfile = config["log_sources"]["ssh"]["path"]
    alertfile = config["outputs"]["file"]["path"]

    watcher = LogWatcher(logfile)
    parser = SSHParser()

    rules = [
        FailedLoginRule(),
        SSHBruteForceRule(),
        SuccessLoginRule()
    ]

    engine = DetectionEngine(rules)

    stdout = StdoutOutput()
    fileout = FileOutput(alertfile)

    print(f"SOC-Agent started. Monitoring {logfile}")

    for line in watcher.follow():
        event = parser.parse(line)

        if event:
            alerts = engine.process(event)

            for alert in alerts:
                stdout.send(alert)
                fileout.send(alert)


if __name__ == "__main__":
    main()