from blue_agent.config import load_config


def test_load_config_uses_defaults_when_env_unset(monkeypatch):
    for var in (
        "TARGET_BASE_URL", "OLLAMA_HOST", "OLLAMA_MODEL", "BLUE_MEMORY_PATH",
        "EVENT_LOG_PATH", "WAZUH_ALERTS_PATH", "REFEREE_STATE_DIR",
        "BLUE_MAX_ITERATIONS", "BLUE_POLL_INTERVAL_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)

    config = load_config()

    assert config.target_base_url == "http://target:5000"
    assert config.ollama_host == "http://host.docker.internal:11434"
    assert config.ollama_model == "qwen2.5:7b"
    assert config.memory_path == "blue_agent/memory/blue_memory.json"
    assert config.event_log_path == "shared_logs/events.jsonl"
    assert config.alerts_log_path == "/var/ossec/logs/alerts/alerts.json"
    assert config.referee_state_dir == "/app/referee_state"
    assert config.max_iterations == 200
    assert config.poll_interval_seconds == 5.0


def test_load_config_reads_env_overrides(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.2:3b")
    monkeypatch.setenv("BLUE_MAX_ITERATIONS", "10")
    monkeypatch.setenv("BLUE_POLL_INTERVAL_SECONDS", "1.5")

    config = load_config()

    assert config.ollama_model == "llama3.2:3b"
    assert config.max_iterations == 10
    assert config.poll_interval_seconds == 1.5
