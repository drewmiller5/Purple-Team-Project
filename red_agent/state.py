from pathlib import Path

from shared.event_log import log_event
from shared.memory import append_memory_entry, load_memory


class RedAgentState:
    def __init__(self, config):
        self.config = config
        # K5: phase-gate state -- no recon-class http_request has happened
        # yet this round. Set True by tools.dispatch_tool_call once one lands.
        self.recon_done = False

    def log_event(self, event: dict) -> None:
        event = dict(event)
        event["side"] = "red"
        try:
            log_event(self.config.event_log_path, event)
        except OSError:
            # Review-round fix: every direct state.log_event(...) call site
            # (heartbeat, reasoning, ollama_error, run_complete, etc.) routes
            # through here. A disk-full/permission error writing the event
            # log must degrade (skip the write), not crash the process --
            # mirrors BlueAgentState.log_event()'s existing guard.
            pass

    def heartbeat(self) -> None:
        self.log_event({"phase": "heartbeat"})

    def record_finding(self, category: str, detail: str, success: bool) -> None:
        entry = {"side": "red", "category": category, "detail": detail, "success": success}
        append_memory_entry(self.config.memory_path, entry)
        self.log_event({"phase": "finding", "category": category, "detail": detail, "success": success})

    def recall_summary(self) -> str:
        # Dashboard memory toggle (2026-08-12): a per-round referee-state
        # flag file can additionally disable recall even when
        # MEMORY_ENABLED=true -- round_helper only restarts existing
        # containers, it can't inject a new env var per round, so a live
        # dashboard toggle needs a runtime-checked file (same mechanism as
        # loop.py's hint_mode.flag), not just the env var.
        if not self.config.memory_enabled or Path(self.config.referee_state_dir, "memory_disabled.flag").exists():
            return ""
        data = load_memory(self.config.memory_path)
        if not data or not data.get("entries"):
            return ""
        lines = [
            f"- [{e.get('category', '?')}] {e.get('detail', '')} (success={e.get('success')})"
            for e in data["entries"][-20:]
        ]
        return "\n".join(lines)
