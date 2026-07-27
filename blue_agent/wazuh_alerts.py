import json
from pathlib import Path


class WazuhAlertsReader:
    def __init__(self, alerts_path: str):
        self.alerts_path = alerts_path
        self._lines_read = 0

    def poll_new_alerts(self) -> list:
        path = Path(self.alerts_path)
        if not path.exists():
            return []

        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = lines[self._lines_read:]
        self._lines_read = len(lines)

        alerts = []
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return alerts
