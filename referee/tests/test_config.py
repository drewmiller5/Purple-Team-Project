import pytest

from referee.config import load_config


def test_load_config_uses_defaults_when_env_unset(monkeypatch):
    for var in (
        "EVENT_LOG_PATH", "REFEREE_LOG_PATH", "REFEREE_STATE_DIR",
        "REFEREE_MAX_ROUND_SECONDS", "REFEREE_BLUE_STALE_SECONDS",
        "REFEREE_BLUE_WIN_STREAK", "REFEREE_POLL_INTERVAL_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)

    config = load_config()

    assert config.event_log_path == "shared_logs/events.jsonl"
    assert config.referee_log_path == "referee_logs/referee_assessments.jsonl"
    assert config.state_dir == "/app/referee_state"
    assert config.max_round_seconds == 900
    assert config.blue_stale_seconds == 90
    assert config.blue_win_streak == 3
    assert config.poll_interval_seconds == 3.0


def test_load_config_reads_env_overrides(monkeypatch):
    monkeypatch.setenv("REFEREE_MAX_ROUND_SECONDS", "60")
    monkeypatch.setenv("REFEREE_BLUE_WIN_STREAK", "5")

    config = load_config()

    assert config.max_round_seconds == 60
    assert config.blue_win_streak == 5


def test_load_config_rejects_zero_blue_win_streak(monkeypatch):
    """H28: streak_threshold=0 degenerates blue_decisive_win's
    red_requests[-streak:] slice into red_requests[-0:] -- the WHOLE list,
    not an empty one (Python's [-0:] means [0:]) -- so all() over an empty
    red_requests list returns True instantly, an evidence-free blue win."""
    monkeypatch.setenv("REFEREE_BLUE_WIN_STREAK", "0")

    with pytest.raises(ValueError, match="REFEREE_BLUE_WIN_STREAK"):
        load_config()


def test_load_config_rejects_negative_blue_win_streak(monkeypatch):
    monkeypatch.setenv("REFEREE_BLUE_WIN_STREAK", "-1")

    with pytest.raises(ValueError, match="REFEREE_BLUE_WIN_STREAK"):
        load_config()


def test_load_config_rejects_negative_poll_interval_seconds(monkeypatch):
    """time.sleep() raises ValueError on a negative argument -- must be
    rejected here, at startup, with a clear message, not deep in the
    round loop with a bare traceback."""
    monkeypatch.setenv("REFEREE_POLL_INTERVAL_SECONDS", "-1.0")

    with pytest.raises(ValueError, match="REFEREE_POLL_INTERVAL_SECONDS"):
        load_config()


def test_load_config_rejects_nan_poll_interval_seconds(monkeypatch):
    """float('nan') < 0 is False -- NaN silently bypasses a plain '< 0'
    check, then crashes time.sleep(nan) deep in the round loop instead."""
    monkeypatch.setenv("REFEREE_POLL_INTERVAL_SECONDS", "nan")

    with pytest.raises(ValueError, match="REFEREE_POLL_INTERVAL_SECONDS"):
        load_config()


def test_load_config_rejects_infinite_poll_interval_seconds(monkeypatch):
    """float('inf') < 0 is also False, and time.sleep(inf) doesn't raise --
    it blocks forever, a silent permanent hang in the poll loop."""
    monkeypatch.setenv("REFEREE_POLL_INTERVAL_SECONDS", "inf")

    with pytest.raises(ValueError, match="REFEREE_POLL_INTERVAL_SECONDS"):
        load_config()


def test_load_config_rejects_non_numeric_max_round_seconds_with_clear_message(monkeypatch):
    monkeypatch.setenv("REFEREE_MAX_ROUND_SECONDS", "not-a-number")

    with pytest.raises(ValueError, match="REFEREE_MAX_ROUND_SECONDS"):
        load_config()
