class DetectionEngine:

    def __init__(self, rules):
        self.rules = rules

    def process(self, event):
        alerts = []

        for rule in self.rules:
            result = rule.check(event)
            if result:
                alerts.append(result)

        return alerts