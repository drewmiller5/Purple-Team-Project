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

        # A trailing line with no newline means the writer may still be
        # mid-write on it -- don't mark it "read" until it's complete, or a
        # line that finishes between polls would be silently skipped forever.
        if lines and not lines[-1].endswith("\n"):
            complete_lines = lines[:-1]
        else:
            complete_lines = lines

        new_lines = complete_lines[self._lines_read:]
        self._lines_read = len(complete_lines)

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
