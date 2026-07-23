import json
from datetime import datetime, timezone
from pathlib import Path


def log_event(log_path: str, event: dict) -> dict:
    p = Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    event = dict(event)
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    return event


def read_events(log_path: str) -> list:
    p = Path(log_path)
    if not p.exists():
        return []
    events = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
