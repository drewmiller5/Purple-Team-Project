import json
import os
from datetime import datetime, timezone
from pathlib import Path


def log_event(log_path: str, event: dict) -> dict:
    p = Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    event = dict(event)
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

    line = (json.dumps(event) + "\n").encode("utf-8")
    fd = os.open(str(p), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)

    return event


def read_events(log_path: str) -> list:
    p = Path(log_path)
    if not p.exists():
        return []
    events = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events
