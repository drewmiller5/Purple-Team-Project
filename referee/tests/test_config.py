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
