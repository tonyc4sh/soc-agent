import time

class LogWatcher:

    def __init__(self, logfile):
        self.logfile = logfile

    def follow(self):
        with open(self.logfile) as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                yield line