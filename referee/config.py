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


def load_config() -> RefereeConfig:
    return RefereeConfig(
        event_log_path=os.environ.get("EVENT_LOG_PATH", "shared_logs/events.jsonl"),
        referee_log_path=os.environ.get("REFEREE_LOG_PATH", "referee_logs/referee_assessments.jsonl"),
        state_dir=os.environ.get("REFEREE_STATE_DIR", "/app/referee_state"),
        max_round_seconds=int(os.environ.get("REFEREE_MAX_ROUND_SECONDS", "900")),
        blue_stale_seconds=int(os.environ.get("REFEREE_BLUE_STALE_SECONDS", "90")),
        blue_win_streak=int(os.environ.get("REFEREE_BLUE_WIN_STREAK", "3")),
        poll_interval_seconds=float(os.environ.get("REFEREE_POLL_INTERVAL_SECONDS", "3.0")),
    )
