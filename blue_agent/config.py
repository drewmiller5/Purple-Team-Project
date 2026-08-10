import os
from dataclasses import dataclass


@dataclass(frozen=True)
class BlueAgentConfig:
    target_base_url: str
    ollama_host: str
    ollama_model: str
    memory_path: str
    event_log_path: str
    alerts_log_path: str
    referee_state_dir: str
    max_iterations: int
    poll_interval_seconds: float
    memory_enabled: bool = True


def load_config() -> BlueAgentConfig:
    return BlueAgentConfig(
        target_base_url=os.environ.get("TARGET_BASE_URL", "http://target:5000"),
        ollama_host=os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434"),
        ollama_model=os.environ.get("OLLAMA_MODEL", "qwen2.5:7b"),
        memory_path=os.environ.get("BLUE_MEMORY_PATH", "blue_agent/memory/blue_memory.json"),
        event_log_path=os.environ.get("EVENT_LOG_PATH", "shared_logs/events.jsonl"),
        alerts_log_path=os.environ.get("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json"),
        referee_state_dir=os.environ.get("REFEREE_STATE_DIR", "/app/referee_state"),
        max_iterations=int(os.environ.get("BLUE_MAX_ITERATIONS", "200")),
        poll_interval_seconds=float(os.environ.get("BLUE_POLL_INTERVAL_SECONDS", "5.0")),
        # Memory on/off toggle: gates recall only (state.py's recall_summary),
        # never the underlying blue_memory.json writes -- comparison/demo
        # feature, not a data-retention control.
        memory_enabled=os.environ.get("MEMORY_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off"),
    )
