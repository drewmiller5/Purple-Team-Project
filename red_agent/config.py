import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RedAgentConfig:
    target_base_url: str
    ollama_host: str
    ollama_model: str
    memory_path: str
    event_log_path: str
    max_iterations: int
    referee_state_dir: str
    memory_enabled: bool = True


def load_config() -> RedAgentConfig:
    return RedAgentConfig(
        target_base_url=os.environ.get("TARGET_BASE_URL", "http://target:5000"),
        ollama_host=os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434"),
        ollama_model=os.environ.get("OLLAMA_MODEL", "qwen2.5:7b"),
        memory_path=os.environ.get("RED_MEMORY_PATH", "red_agent/memory/red_memory.json"),
        event_log_path=os.environ.get("EVENT_LOG_PATH", "shared_logs/events.jsonl"),
        max_iterations=int(os.environ.get("RED_MAX_ITERATIONS", "50")),
        referee_state_dir=os.environ.get("REFEREE_STATE_DIR", "/app/referee_state"),
        # Memory on/off toggle: gates recall only (state.py's recall_summary),
        # never the underlying red_memory.json writes -- comparison/demo
        # feature, not a data-retention control.
        memory_enabled=os.environ.get("MEMORY_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off"),
    )
