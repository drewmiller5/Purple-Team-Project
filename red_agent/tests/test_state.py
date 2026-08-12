from pathlib import Path
from unittest.mock import patch

from red_agent.config import RedAgentConfig
from red_agent.state import RedAgentState
from shared.event_log import read_events
from shared.memory import load_memory


def _config(tmp_path, memory_enabled=True):
    return RedAgentConfig(
        target_base_url="http://target:5000",
        ollama_host="http://host.docker.internal:11434",
        ollama_model="qwen2.5:7b",
        memory_path=str(tmp_path / "red_memory.json"),
        event_log_path=str(tmp_path / "events.jsonl"),
        max_iterations=5,
        referee_state_dir=str(tmp_path / "referee_state"),
        memory_enabled=memory_enabled,
    )


def test_log_event_writes_to_event_log_with_side_tagged(tmp_path):
    state = RedAgentState(_config(tmp_path))
    state.log_event({"phase": "recon", "path": "/search"})

    events = read_events(str(tmp_path / "events.jsonl"))
    assert len(events) == 1
    assert events[0]["side"] == "red"
    assert events[0]["phase"] == "recon"


def test_record_finding_writes_to_memory_and_event_log(tmp_path):
    state = RedAgentState(_config(tmp_path))
    state.record_finding("sqli", "/search?q= is injectable", True)

    memory = load_memory(str(tmp_path / "red_memory.json"))
    assert memory["side"] == "red"
    assert len(memory["entries"]) == 1
    assert memory["entries"][0]["category"] == "sqli"
    assert memory["entries"][0]["success"] is True

    events = read_events(str(tmp_path / "events.jsonl"))
    assert any(e.get("phase") == "finding" for e in events)


def test_recall_summary_empty_when_no_memory_yet(tmp_path):
    state = RedAgentState(_config(tmp_path))
    assert state.recall_summary() == ""


def test_recall_summary_lists_recorded_findings(tmp_path):
    state = RedAgentState(_config(tmp_path))
    state.record_finding("sqli", "/search?q= is injectable", True)
    state.record_finding("creds", "admin/wrongpass failed", False)

    summary = state.recall_summary()
    assert "sqli" in summary
    assert "creds" in summary


def test_heartbeat_logs_a_heartbeat_phase_event(tmp_path):
    """K1: red_agent gets its own heartbeat, mirroring BlueAgentState.heartbeat()."""
    state = RedAgentState(_config(tmp_path))
    state.heartbeat()

    events = read_events(str(tmp_path / "events.jsonl"))
    assert len(events) == 1
    assert events[0]["side"] == "red"
    assert events[0]["phase"] == "heartbeat"


def test_recall_summary_empty_when_memory_disabled_even_with_entries(tmp_path):
    """Memory on/off toggle: MEMORY_ENABLED=false must blank out recall
    without touching red_memory.json -- record_finding still writes it."""
    state = RedAgentState(_config(tmp_path, memory_enabled=False))
    state.record_finding("sqli", "/search?q= is injectable", True)

    assert state.recall_summary() == ""
    memory = load_memory(str(tmp_path / "red_memory.json"))
    assert len(memory["entries"]) == 1


def test_recall_summary_empty_when_memory_disabled_flag_present_even_if_config_enabled(tmp_path):
    """Dashboard memory toggle (2026-08-12): a per-round referee-state flag
    file overrides the env-var default, same mechanism as hint_mode.flag --
    round_helper only restarts existing containers, it can't inject a new
    env var per round, so a live dashboard toggle needs a runtime-checked
    file instead. Never touches red_memory.json -- record_finding still
    writes it, only recall is blanked."""
    state = RedAgentState(_config(tmp_path, memory_enabled=True))
    state.record_finding("sqli", "/search?q= is injectable", True)
    state_dir = Path(state.config.referee_state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "memory_disabled.flag").touch()

    assert state.recall_summary() == ""
    memory = load_memory(str(tmp_path / "red_memory.json"))
    assert len(memory["entries"]) == 1


def test_recon_done_defaults_to_false(tmp_path):
    """K5: phase-gate state starts closed -- no recon-class request yet this round."""
    state = RedAgentState(_config(tmp_path))
    assert state.recon_done is False


def test_log_event_survives_oserror_from_underlying_write(tmp_path):
    """Review-round fix: every direct state.log_event(...) call site in
    loop.py (round_stop_acknowledged, ollama_error, reasoning, run_complete,
    memory_corrupt) routes through this one method. Guarding it here --
    instead of only at the heartbeat call site -- is the root-cause fix,
    mirroring BlueAgentState.log_event()'s existing guard: a disk-full/
    permission OSError on the underlying file write must degrade (skip the
    write), not crash the process."""
    state = RedAgentState(_config(tmp_path))
    with patch("red_agent.state.log_event", side_effect=OSError("disk full")):
        state.log_event({"phase": "round_start"})  # must not raise
