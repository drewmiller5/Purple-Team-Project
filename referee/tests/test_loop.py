import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from referee.config import RefereeConfig
from referee.loop import run
from shared.event_log import log_event


def _config(tmp_path, **overrides):
    defaults = dict(
        event_log_path=str(tmp_path / "events.jsonl"),
        referee_log_path=str(tmp_path / "referee_assessments.jsonl"),
        state_dir=str(tmp_path / "referee_state"),
        max_round_seconds=0,
        blue_stale_seconds=90,
        blue_win_streak=3,
        poll_interval_seconds=0.0,
    )
    defaults.update(overrides)
    return RefereeConfig(**defaults)


def test_run_ends_round_immediately_on_zero_second_budget(tmp_path):
    config = _config(tmp_path, max_round_seconds=0)
    run(config)

    assert (Path(config.state_dir) / "stop.flag").exists()
    assessments = [json.loads(l) for l in Path(config.referee_log_path).read_text().splitlines()]
    assert any(a["phase"] == "round_over" and a["outcome"] == "budget_expired" for a in assessments)


def test_run_clears_stale_flags_from_a_prior_round_at_start(tmp_path):
    """H27 regression: referee-state is a persistent Docker volume. A prior
    round's go.flag/stop.flag must not leak into a new round, or red/blue
    agents (which just check for the files' existence) misread the fresh
    round as already over before it starts."""
    config = _config(tmp_path, max_round_seconds=0)
    state_dir = Path(config.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "go.flag").touch()
    (state_dir / "stop.flag").touch()

    # No blue heartbeat logged this round -- run() itself would never
    # legitimately touch go.flag on this path (only budget_expired fires).
    run(config)

    assert not (state_dir / "go.flag").exists(), (
        "stale go.flag from a prior round leaked into this round -- "
        "red/blue would wrongly see 'go' already signaled"
    )


def test_run_signals_go_once_blue_heartbeat_appears(tmp_path):
    config = _config(tmp_path, max_round_seconds=0)
    log_event(config.event_log_path, {"side": "blue", "phase": "heartbeat"})

    run(config)

    assert (Path(config.state_dir) / "go.flag").exists()
    assessments = [json.loads(l) for l in Path(config.referee_log_path).read_text().splitlines()]
    assert any(a["phase"] == "go_signal" for a in assessments)


def test_run_declares_blue_win_when_streak_and_heartbeat_present(tmp_path):
    config = _config(tmp_path, max_round_seconds=999, blue_win_streak=3)
    log_event(config.event_log_path, {"side": "blue", "phase": "heartbeat"})
    for _ in range(3):
        log_event(config.event_log_path, {
            "side": "red", "phase": "http_request", "response": {"status_code": 403},
        })

    run(config)

    assessments = [json.loads(l) for l in Path(config.referee_log_path).read_text().splitlines()]
    assert any(a["phase"] == "round_over" and a["outcome"] == "blue" for a in assessments)


def test_run_never_writes_assessment_into_shared_event_log(tmp_path):
    config = _config(tmp_path, max_round_seconds=0)
    run(config)

    events = Path(config.event_log_path)
    if events.exists():
        for line in events.read_text().splitlines():
            assert json.loads(line).get("side") != "white"


def test_run_prefers_blue_win_over_budget_expired_when_both_conditions_hold(tmp_path):
    config = _config(tmp_path, max_round_seconds=0, blue_win_streak=3)
    log_event(config.event_log_path, {"side": "blue", "phase": "heartbeat"})
    for _ in range(3):
        log_event(config.event_log_path, {
            "side": "red", "phase": "http_request", "response": {"status_code": 403},
        })

    run(config)

    assessments = [json.loads(l) for l in Path(config.referee_log_path).read_text().splitlines()]
    round_over = [a for a in assessments if a["phase"] == "round_over"]
    assert len(round_over) == 1
    assert round_over[0]["outcome"] == "blue"


def test_run_prefers_red_win_over_budget_expired_when_both_conditions_hold(tmp_path):
    """Regression test: ensure red_decisive_win is checked before budget_expired.
    If the if/elif order were changed to check budget_expired first,
    this test would fail by producing outcome='budget_expired' instead of 'red'."""
    config = _config(tmp_path, max_round_seconds=0, blue_stale_seconds=1)

    # Log blue heartbeat with a timestamp far in the past (so it's stale by run() time)
    stale_timestamp = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    log_event(config.event_log_path, {
        "side": "blue", "phase": "heartbeat", "timestamp": stale_timestamp
    })

    # Log red's successful access to /admin/diagnostics
    log_event(config.event_log_path, {
        "side": "red", "phase": "http_request",
        "request": {"path": "/admin/diagnostics"}, "response": {"status_code": 200},
    })

    run(config)

    assessments = [json.loads(l) for l in Path(config.referee_log_path).read_text().splitlines()]
    round_over = [a for a in assessments if a["phase"] == "round_over"]
    assert len(round_over) == 1
    assert round_over[0]["outcome"] == "red"
