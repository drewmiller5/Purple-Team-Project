import json
from datetime import datetime, timezone
from pathlib import Path


def new_empty_memory(side: str) -> dict:
    if side not in ("red", "blue"):
        raise ValueError(f"side must be 'red' or 'blue', got {side!r}")
    return {
        "side": side,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "entries": [],
    }


def load_memory(path: str):
    p = Path(path)
    if not p.exists():
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def save_memory(path: str, data: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def append_memory_entry(path: str, entry: dict) -> dict:
    data = load_memory(path)
    if data is None:
        if "side" not in entry:
            raise ValueError("entry must include 'side' when memory doesn't exist yet")
        data = new_empty_memory(entry["side"])

    entry = dict(entry)
    entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    data["entries"].append(entry)
    save_memory(path, data)
    return data
