from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os


class _LogHandler(FileSystemEventHandler):

    def __init__(self, logfile):
        self.logfile = os.path.abspath(logfile)
        self._file = open(self.logfile)
        self._file.seek(0, 2)
        self._buffer = []

    def on_modified(self, event):
        
        if os.path.basename(event.src_path) != "auth.log":
            return

        while True:
            line = self._file.readline()
            if not line:
                break
            self._buffer.append(line)

    def get_lines(self):
        lines = self._buffer[:]
        self._buffer.clear()
        return lines


class LogWatcher:

    def __init__(self, logfile):
        self.logfile = logfile

    def follow(self):

        handler = _LogHandler(self.logfile)

        observer = Observer()
        log_dir = os.path.dirname(self.logfile)

        observer.schedule(handler, path=log_dir, recursive=False)
        observer.start()

        try:
            while True:
                lines = handler.get_lines()

                for line in lines:
                    yield line

                time.sleep(0.1)

        finally:
            observer.stop()
            observer.join()