from blue_agent.config import BlueAgentConfig
from blue_agent.state import BlueAgentState
from shared.event_log import read_events
from shared.memory import load_memory


def _config(tmp_path):
    return BlueAgentConfig(
        target_base_url="http://target:5000",
        ollama_host="http://host.docker.internal:11434",
        ollama_model="qwen2.5:7b",
        memory_path=str(tmp_path / "blue_memory.json"),
        event_log_path=str(tmp_path / "events.jsonl"),
        alerts_log_path=str(tmp_path / "alerts.json"),
        referee_state_dir=str(tmp_path / "referee_state"),
        max_iterations=5,
        poll_interval_seconds=0.0,
    )


def test_log_event_writes_to_event_log_with_side_tagged(tmp_path):
    state = BlueAgentState(_config(tmp_path))
    state.log_event({"phase": "alert_seen", "rule_id": "100101"})

    events = read_events(str(tmp_path / "events.jsonl"))
    assert len(events) == 1
    assert events[0]["side"] == "blue"
    assert events[0]["phase"] == "alert_seen"


def test_heartbeat_logs_a_heartbeat_phase_event(tmp_path):
    state = BlueAgentState(_config(tmp_path))
    state.heartbeat()

    events = read_events(str(tmp_path / "events.jsonl"))
    assert len(events) == 1
    assert events[0]["side"] == "blue"
    assert events[0]["phase"] == "heartbeat"


def test_record_finding_writes_to_memory_and_event_log(tmp_path):
    state = BlueAgentState(_config(tmp_path))
    state.record_finding("escalation", "locked admin after bruteforce alert", True)

    memory = load_memory(str(tmp_path / "blue_memory.json"))
    assert memory["side"] == "blue"
    assert memory["entries"][0]["category"] == "escalation"
    assert memory["entries"][0]["success"] is True

    events = read_events(str(tmp_path / "events.jsonl"))
    assert any(e.get("phase") == "finding" for e in events)


def test_recall_summary_empty_when_no_memory_yet(tmp_path):
    state = BlueAgentState(_config(tmp_path))
    assert state.recall_summary() == ""


def test_recall_summary_lists_recorded_findings(tmp_path):
    state = BlueAgentState(_config(tmp_path))
    state.record_finding("escalation", "locked admin", True)
    state.record_finding("hold", "single failed login, below threshold", True)

    summary = state.recall_summary()
    assert "escalation" in summary
    assert "hold" in summary
