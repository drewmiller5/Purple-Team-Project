import math
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RefereeConfig:
    event_log_path: str
    referee_log_path: str
    state_dir: str
    max_round_seconds: int
    blue_stale_seconds: int
    blue_win_streak: int
    poll_interval_seconds: float
    white_memory_path: str
    red_memory_path: str


def _env_int(name: str, default: str) -> int:
    raw = os.environ.get(name, default)
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


def _env_float(name: str, default: str) -> float:
    raw = os.environ.get(name, default)
    try:
        return float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None


def load_config() -> RefereeConfig:
    blue_win_streak = _env_int("REFEREE_BLUE_WIN_STREAK", "3")
    if blue_win_streak < 1:
        # H28: streak_threshold=0 degenerates blue_decisive_win's
        # red_requests[-streak:] slice into red_requests[-0:] -- the WHOLE
        # list, not an empty one (Python's [-0:] means [0:]) -- so all()
        # over zero red requests returns True instantly: an evidence-free
        # blue win the moment blue heartbeats once.
        raise ValueError(
            f"REFEREE_BLUE_WIN_STREAK must be a positive integer, got {blue_win_streak}"
        )

    poll_interval_seconds = _env_float("REFEREE_POLL_INTERVAL_SECONDS", "3.0")
    if not math.isfinite(poll_interval_seconds) or poll_interval_seconds < 0:
        # time.sleep() raises ValueError on a negative argument -- reject it
        # here, at startup, instead of deep in the round loop. A plain
        # "< 0" check alone isn't enough: float('nan') < 0 is False (NaN
        # comparisons are always False), so NaN would silently pass and
        # still crash time.sleep() later; float('inf') < 0 is also False,
        # and time.sleep(inf) doesn't raise at all -- it blocks forever, a
        # silent permanent hang in the poll loop. isfinite() catches both.
        raise ValueError(
            f"REFEREE_POLL_INTERVAL_SECONDS must be a finite, non-negative number, got {poll_interval_seconds}"
        )

    return RefereeConfig(
        event_log_path=os.environ.get("EVENT_LOG_PATH", "shared_logs/events.jsonl"),
        referee_log_path=os.environ.get("REFEREE_LOG_PATH", "referee_logs/referee_assessments.jsonl"),
        state_dir=os.environ.get("REFEREE_STATE_DIR", "/app/referee_state"),
        max_round_seconds=_env_int("REFEREE_MAX_ROUND_SECONDS", "900"),
        blue_stale_seconds=_env_int("REFEREE_BLUE_STALE_SECONDS", "90"),
        blue_win_streak=blue_win_streak,
        poll_interval_seconds=poll_interval_seconds,
        white_memory_path=os.environ.get("WHITE_MEMORY_PATH", "referee_logs/white_memory.json"),
        red_memory_path=os.environ.get("RED_MEMORY_PATH", "red_memory_ro/red_memory.json"),
    )
