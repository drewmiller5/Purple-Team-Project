import json
import shutil
import sys
from pathlib import Path

from shared.event_log import read_events
from shared.memory import load_memory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RED_MEMORY_PATH = PROJECT_ROOT / "memory" / "red_memory.json"
BLUE_MEMORY_PATH = PROJECT_ROOT / "memory" / "blue_memory.json"
EVENT_LOG_PATH = PROJECT_ROOT / "memory" / "events.jsonl"
ARCHIVE_ROOT = PROJECT_ROOT / "archive"


def _count_events_by_field(events: list, field: str, value) -> int:
    return sum(1 for e in events if e.get(field) == value)


def build_summary(red_memory: dict, blue_memory: dict, events: list) -> dict:
    return {
        "red_entry_count": len(red_memory.get("entries", [])),
        "blue_entry_count": len(blue_memory.get("entries", [])),
        "total_events": len(events),
        "red_actions": _count_events_by_field(events, "side", "red"),
        "blue_actions": _count_events_by_field(events, "side", "blue"),
    }


def capture_checkpoint(version: str, archive_root: Path = ARCHIVE_ROOT) -> Path:
    dest = archive_root / version
    dest.mkdir(parents=True, exist_ok=True)

    # Reuse shared.memory's loader (Task 8) instead of re-implementing
    # file-read logic here — DRY.
    red_memory = load_memory(str(RED_MEMORY_PATH)) or {"side": "red", "entries": []}
    blue_memory = load_memory(str(BLUE_MEMORY_PATH)) or {"side": "blue", "entries": []}

    # Reuse shared.event_log's hardened parser (Task 9) instead of re-implementing
    # — it gracefully skips corrupt JSON lines instead of crashing.
    events = read_events(str(EVENT_LOG_PATH))

    with open(dest / "red_memory.json", "w", encoding="utf-8") as f:
        json.dump(red_memory, f, indent=2)
    with open(dest / "blue_memory.json", "w", encoding="utf-8") as f:
        json.dump(blue_memory, f, indent=2)

    if EVENT_LOG_PATH.exists():
        shutil.copy(EVENT_LOG_PATH, dest / "events.jsonl")
    else:
        (dest / "events.jsonl").touch()

    summary = build_summary(red_memory, blue_memory, events)
    summary["version"] = version
    with open(dest / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return dest


if __name__ == "__main__":
    version_arg = sys.argv[1] if len(sys.argv) > 1 else "v0"
    result_path = capture_checkpoint(version_arg)
    print(f"Checkpoint captured: {result_path}")
