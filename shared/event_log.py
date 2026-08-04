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
    # Read as raw bytes and decode per-line with errors="replace" so a
    # single invalid UTF-8 byte anywhere in the file only mangles that one
    # line instead of raising an uncaught UnicodeDecodeError that would
    # abort the read of the entire file (H30).
    with open(p, "rb") as f:
        for raw_line in f:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            # A syntactically-valid-but-non-dict line (bare number, string,
            # array) must be skipped too -- downstream consumers all call
            # .get(...) on each event (H29).
            if not isinstance(parsed, dict):
                continue
            events.append(parsed)
    return events
