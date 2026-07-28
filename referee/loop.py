import time
from datetime import datetime, timezone
from pathlib import Path

from shared.event_log import log_event, read_events

from referee.monitor import blue_decisive_win, has_blue_heartbeat, red_decisive_win


def run(config) -> None:
    state_dir = Path(config.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    go_path = state_dir / "go.flag"
    stop_path = state_dir / "stop.flag"

    # H27: referee-state is a persistent Docker volume -- a restart mid-lab
    # (or, as here, a fresh round on a reused volume) must not let a prior
    # round's flags leak in, or red/blue immediately misread the new round
    # as already over before it starts.
    go_path.unlink(missing_ok=True)
    stop_path.unlink(missing_ok=True)

    start = datetime.now(timezone.utc)
    go_signaled = False

    while True:
        events = read_events(config.event_log_path)
        now = datetime.now(timezone.utc)

        if not go_signaled and has_blue_heartbeat(events):
            go_path.touch()
            go_signaled = True
            log_event(config.referee_log_path, {"side": "white", "phase": "go_signal"})

        elapsed = (now - start).total_seconds()
        budget_expired = elapsed >= config.max_round_seconds

        outcome = None
        if go_signaled and blue_decisive_win(events, config.blue_win_streak):
            outcome = "blue"
        elif go_signaled and red_decisive_win(events, now, config.blue_stale_seconds):
            outcome = "red"
        elif budget_expired:
            outcome = "budget_expired"

        if outcome is not None:
            stop_path.touch()
            log_event(
                config.referee_log_path,
                {
                    "side": "white",
                    "phase": "round_over",
                    "outcome": outcome,
                    "elapsed_seconds": elapsed,
                },
            )
            return

        time.sleep(config.poll_interval_seconds)
