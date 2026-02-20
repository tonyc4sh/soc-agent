class StdoutOutput:

    def send(self, alert):
        print(f"[ALERT] {alert}")
