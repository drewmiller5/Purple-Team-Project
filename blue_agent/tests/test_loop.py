import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from blue_agent.config import BlueAgentConfig
from blue_agent.loop import run


def _config(tmp_path, max_iterations=3):
    return BlueAgentConfig(
        target_base_url="http://target:5000",
        ollama_host="http://host.docker.internal:11434",
        ollama_model="qwen2.5:7b",
        memory_path=str(tmp_path / "blue_memory.json"),
        event_log_path=str(tmp_path / "events.jsonl"),
        alerts_log_path=str(tmp_path / "alerts.json"),
        referee_state_dir=str(tmp_path / "referee_state"),
        max_iterations=max_iterations,
        poll_interval_seconds=0.0,
    )


def _touch_go_flag(config):
    state_dir = Path(config.referee_state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "go.flag").touch()


def test_run_waits_for_go_flag_before_logging_round_start(tmp_path):
    config = _config(tmp_path, max_iterations=1)

    # go.flag never appears -> run() must not proceed past the wait.
    # Use a real short timeout via a patched wait helper so the test is fast
    # and deterministic instead of hanging.
    with patch("blue_agent.loop._wait_for_go") as mock_wait:
        with patch("blue_agent.loop.OllamaClient"):
            run(config)
        mock_wait.assert_called_once_with(config.referee_state_dir, config.poll_interval_seconds)


def test_run_stops_immediately_when_stop_flag_already_present(tmp_path):
    config = _config(tmp_path, max_iterations=5)
    _touch_go_flag(config)
    (Path(config.referee_state_dir) / "stop.flag").touch()

    with patch("blue_agent.loop.OllamaClient") as MockOllama:
        run(config)
        MockOllama.return_value.chat.assert_not_called()

    events_path = Path(config.event_log_path)
    events = [json.loads(l) for l in events_path.read_text().splitlines()]
    assert any(e["phase"] == "round_stop_acknowledged" for e in events)


def test_run_heartbeats_every_iteration_with_no_new_alerts(tmp_path):
    config = _config(tmp_path, max_iterations=3)
    _touch_go_flag(config)

    with patch("blue_agent.loop.OllamaClient") as MockOllama:
        run(config)
        MockOllama.return_value.chat.assert_not_called()

    events_path = Path(config.event_log_path)
    events = [json.loads(l) for l in events_path.read_text().splitlines()]
    heartbeats = [e for e in events if e["phase"] == "heartbeat"]
    assert len(heartbeats) == 3


def test_run_calls_ollama_and_dispatches_tool_calls_when_new_alerts_appear(tmp_path):
    config = _config(tmp_path, max_iterations=1)
    _touch_go_flag(config)
    Path(config.alerts_log_path).write_text('{"rule": {"id": "100101"}}\n', encoding="utf-8")

    tool_call_response = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "recall_past_findings", "arguments": {}}}
            ],
        }
    }
    with patch("blue_agent.loop.OllamaClient") as MockOllama, \
         patch("blue_agent.loop.dispatch_tool_call") as mock_dispatch:
        mock_dispatch.return_value = "No prior findings."
        MockOllama.return_value.chat.return_value = tool_call_response
        run(config)
        mock_dispatch.assert_called_once()
        MockOllama.return_value.chat.assert_called_once()


def test_run_includes_target_base_url_in_system_prompt(tmp_path):
    config = _config(tmp_path, max_iterations=1)
    _touch_go_flag(config)
    Path(config.alerts_log_path).write_text('{"rule": {"id": "100101"}}\n', encoding="utf-8")

    fake_response = {"message": {"role": "assistant", "content": "ok", "tool_calls": []}}
    with patch("blue_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = fake_response
        run(config)

        messages_arg = MockOllama.return_value.chat.call_args.kwargs["messages"]
        system_message = messages_arg[0]
        assert system_message["role"] == "system"
        assert "http://target:5000" in system_message["content"]
