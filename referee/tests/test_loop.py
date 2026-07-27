import json
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
