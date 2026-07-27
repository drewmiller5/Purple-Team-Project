import os

from red_agent.config import load_config


def test_load_config_uses_defaults_when_env_unset(monkeypatch):
    for var in (
        "TARGET_BASE_URL", "OLLAMA_HOST", "OLLAMA_MODEL",
        "RED_MEMORY_PATH", "EVENT_LOG_PATH", "RED_MAX_ITERATIONS",
        "REFEREE_STATE_DIR",
    ):
        monkeypatch.delenv(var, raising=False)

    config = load_config()

    assert config.target_base_url == "http://target:5000"
    assert config.ollama_host == "http://host.docker.internal:11434"
    assert config.ollama_model == "qwen2.5:7b"
    assert config.memory_path == "red_agent/memory/red_memory.json"
    assert config.event_log_path == "shared_logs/events.jsonl"
    assert config.max_iterations == 50
    assert config.referee_state_dir == "/app/referee_state"


def test_load_config_reads_env_overrides(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.2:3b")
    monkeypatch.setenv("RED_MAX_ITERATIONS", "10")

    config = load_config()

    assert config.ollama_model == "llama3.2:3b"
    assert config.max_iterations == 10
