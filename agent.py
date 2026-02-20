from watcher import LogWatcher
from parser import SSHParser
from rules import RuleEngine
from outputs.stdout import StdoutOutput
from outputs.file import FileOutput

LOG_FILE = "/var/log/auth.log"

def main():
    watcher = LogWatcher(LOG_FILE)
    parser = SSHParser()
    rules = RuleEngine()

    stdout = StdoutOutput()
    fileout = FileOutput("/var/log/soc-agent.log")

    print("SOC-Agent started...")

    for line in watcher.follow():
        parsed = parser.parse(line)
        alert = rules.process(parsed)

        if alert:
            stdout.send(alert)
            fileout.send(alert)

if __name__ == "__main__":
    main()
