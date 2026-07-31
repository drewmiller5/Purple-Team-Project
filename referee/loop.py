import time
from datetime import datetime, timezone
from pathlib import Path

from shared.event_log import log_event, read_events

from referee.monitor import blue_decisive_win, has_blue_heartbeat, red_decisive_win
from referee.white_memory import prepare_round


def _read_processed_through(state_dir: Path) -> int:
    """How many lines of the shared event log belong to rounds already
    concluded. Defaults to 0 (process the whole log) when no marker exists
    yet -- a fresh install, or a test's isolated tmp_path, both correctly
    fall back to "everything logged so far is this round"."""
    marker_path = state_dir / "processed_through.txt"
    if not marker_path.exists():
        return 0
    try:
        return int(marker_path.read_text().strip())
    except (ValueError, OSError):
        return 0


def _write_processed_through(state_dir: Path, index: int) -> None:
    (state_dir / "processed_through.txt").write_text(str(index))


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

    # White team prepares the round before anything else: pick the flag red
    # should focus on this round, favoring one neither white has assigned
    # nor red has already found, so rounds stop re-covering the same ground.
    # Recorded in white's own memory file only -- never the shared event
    # log, same boundary referee's own assessments already respect.
    prepare_round(config.white_memory_path, config.red_memory_path)

    # The shared event log is deliberately never wiped between rounds (it's
    # how cross-round learning works), but that means a fresh round would
    # otherwise re-read the *previous* round's tail events and could satisfy
    # a win condition before this round's agents ever act. processed_through
    # marks where the previous round ended, so only events appended during
    # THIS round are considered below.
    processed_through = _read_processed_through(state_dir)

    start = datetime.now(timezone.utc)
    go_signaled = False

    while True:
        all_events = read_events(config.event_log_path)
        round_events = all_events[processed_through:]
        now = datetime.now(timezone.utc)

        if not go_signaled and has_blue_heartbeat(round_events):
            go_path.touch()
            go_signaled = True
            log_event(config.referee_log_path, {"side": "white", "phase": "go_signal"})

        elapsed = (now - start).total_seconds()
        budget_expired = elapsed >= config.max_round_seconds

        outcome = None
        if go_signaled and blue_decisive_win(round_events, config.blue_win_streak):
            outcome = "blue"
        elif go_signaled and red_decisive_win(round_events, now, config.blue_stale_seconds):
            outcome = "red"
        elif budget_expired:
            outcome = "budget_expired"

        if outcome is not None:
            stop_path.touch()
            _write_processed_through(state_dir, len(all_events))
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
