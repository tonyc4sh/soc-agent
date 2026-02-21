import json

class FileOutput:

    def __init__(self, path):
        self.path = path

    def send(self, alert):
        with open(self.path, "a") as f:
            f.write(json.dumps(alert) + "\n")