import json
import os
from datetime import datetime, timezone
from pathlib import Path


def new_empty_memory(side: str) -> dict:
    if side not in ("red", "blue", "white"):
        raise ValueError(f"side must be 'red', 'blue', or 'white', got {side!r}")
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
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Memory file at {p} contains invalid JSON and appears corrupt: {e}"
            ) from e


def save_memory(path: str, data: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temp file in the same directory, then atomically replace the
    # target so a concurrent reader never observes a truncated/partial file.
    tmp_path = p.with_name(f".{p.name}.tmp-{os.getpid()}")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, p)
    finally:
        # If os.replace succeeded, tmp_path no longer exists; this only
        # cleans up leftovers from a failure before the replace happened.
        if tmp_path.exists():
            tmp_path.unlink()


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
