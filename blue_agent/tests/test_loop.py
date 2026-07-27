import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

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
    # 1 unconditional pre-wait heartbeat (fires before _wait_for_go, so the referee
    # has something to key its go-signal off of) + 3 in-loop heartbeats (one per
    # max_iterations=3 iteration) = 4 total.
    assert len(heartbeats) == 4


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


def test_run_handles_malformed_tool_call_missing_function_key(tmp_path):
    """Test that a malformed tool_call (missing 'function' key) doesn't crash the loop."""
    config = _config(tmp_path, max_iterations=1)
    _touch_go_flag(config)
    Path(config.alerts_log_path).write_text('{"rule": {"id": "100101"}}\n', encoding="utf-8")

    # Simulate Ollama returning a malformed tool_calls entry (missing "function" key)
    malformed_response = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [{}],  # Missing "function" key entirely
        }
    }
    with patch("blue_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = malformed_response
        # Should not raise KeyError; should complete normally
        run(config)

    events_path = Path(config.event_log_path)
    events = [json.loads(l) for l in events_path.read_text().splitlines()]
    # Verify run_complete was logged (loop continued after malformed call)
    assert any(e["phase"] == "run_complete" for e in events)


def test_run_handles_ollama_http_error_gracefully(tmp_path):
    """Test that Ollama HTTP errors don't crash the loop."""
    config = _config(tmp_path, max_iterations=2)
    _touch_go_flag(config)
    Path(config.alerts_log_path).write_text('{"rule": {"id": "100101"}}\n', encoding="utf-8")

    with patch("blue_agent.loop.OllamaClient") as MockOllama:
        # First iteration: raise HTTPError
        error_response = requests.Response()
        error_response.status_code = 500
        http_error = requests.HTTPError(response=error_response)
        MockOllama.return_value.chat.side_effect = http_error

        # Should not raise; should complete normally
        run(config)
        MockOllama.return_value.chat.assert_called()

    events_path = Path(config.event_log_path)
    events = [json.loads(l) for l in events_path.read_text().splitlines()]
    # Verify ollama_error was logged
    assert any(e["phase"] == "ollama_error" for e in events)
    # Verify run_complete was logged (loop continued after error)
    assert any(e["phase"] == "run_complete" for e in events)


def test_run_heartbeats_before_waiting_for_go_flag(tmp_path):
    """Regression test for the go-signal deadlock (found live in Task 12's
    end-to-end run): blue must emit a heartbeat unconditionally, before
    waiting on go.flag, so the referee has something to key its go-signal
    off of. Without this, blue and referee deadlock forever: referee only
    writes go.flag after seeing a blue heartbeat, but blue never wrote
    anything until go.flag already existed."""
    config = _config(tmp_path, max_iterations=1)

    def fake_wait(referee_state_dir, poll_interval):
        events = [json.loads(l) for l in Path(config.event_log_path).read_text().splitlines()]
        assert any(e["phase"] == "heartbeat" for e in events)
        Path(referee_state_dir).mkdir(parents=True, exist_ok=True)
        (Path(referee_state_dir) / "stop.flag").touch()

    with patch("blue_agent.loop._wait_for_go", side_effect=fake_wait):
        with patch("blue_agent.loop.OllamaClient"):
            run(config)


def test_run_handles_ollama_key_error_gracefully(tmp_path):
    """Test that unexpected Ollama response shapes (KeyError) don't crash the loop."""
    config = _config(tmp_path, max_iterations=2)
    _touch_go_flag(config)
    Path(config.alerts_log_path).write_text('{"rule": {"id": "100101"}}\n', encoding="utf-8")

    with patch("blue_agent.loop.OllamaClient") as MockOllama:
        # Return a response missing the "message" key
        bad_response = {"unexpected_field": "value"}
        MockOllama.return_value.chat.return_value = bad_response

        # Should not raise; should complete normally
        run(config)
        MockOllama.return_value.chat.assert_called()

    events_path = Path(config.event_log_path)
    events = [json.loads(l) for l in events_path.read_text().splitlines()]
    # Verify ollama_error was logged
    assert any(e["phase"] == "ollama_error" for e in events)
    # Verify run_complete was logged (loop continued after error)
    assert any(e["phase"] == "run_complete" for e in events)
