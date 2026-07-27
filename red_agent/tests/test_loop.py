# red_agent/tests/test_loop.py
import json
from pathlib import Path
from unittest.mock import patch

import requests

from red_agent.config import RedAgentConfig
from red_agent.loop import run


def _config(tmp_path, max_iterations=2):
    return RedAgentConfig(
        target_base_url="http://target:5000",
        ollama_host="http://host.docker.internal:11434",
        ollama_model="qwen2.5:7b",
        memory_path=str(tmp_path / "red_memory.json"),
        event_log_path=str(tmp_path / "events.jsonl"),
        max_iterations=max_iterations,
        referee_state_dir=str(tmp_path / "referee_state"),
    )


def _touch_go_flag(config):
    state_dir = Path(config.referee_state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "go.flag").touch()


def test_run_stops_after_max_iterations(tmp_path):
    config = _config(tmp_path, max_iterations=3)
    _touch_go_flag(config)
    fake_chat_response = {
        "message": {"role": "assistant", "content": "thinking", "tool_calls": []}
    }
    with patch("red_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = fake_chat_response
        run(config)
        assert MockOllama.return_value.chat.call_count == 3


def test_run_dispatches_tool_calls(tmp_path):
    config = _config(tmp_path, max_iterations=1)
    _touch_go_flag(config)
    tool_call_response = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "record_finding", "arguments": {"category": "sqli", "detail": "x", "success": True}}}
            ],
        }
    }
    with patch("red_agent.loop.OllamaClient") as MockOllama, \
         patch("red_agent.loop.dispatch_tool_call") as mock_dispatch:
        mock_dispatch.return_value = '{"recorded": true}'
        MockOllama.return_value.chat.return_value = tool_call_response
        run(config)
        mock_dispatch.assert_called_once()


def test_run_includes_target_base_url_in_system_prompt(tmp_path):
    config = _config(tmp_path, max_iterations=1)
    _touch_go_flag(config)
    fake_chat_response = {"message": {"role": "assistant", "content": "ok", "tool_calls": []}}
    with patch("red_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = fake_chat_response
        run(config)

        messages_arg = MockOllama.return_value.chat.call_args.kwargs["messages"]
        system_message = messages_arg[0]
        assert system_message["role"] == "system"
        assert "http://target:5000" in system_message["content"]


def test_run_seeds_past_findings_into_context_when_present(tmp_path):
    from red_agent.state import RedAgentState
    config = _config(tmp_path, max_iterations=1)
    _touch_go_flag(config)
    RedAgentState(config).record_finding("sqli", "prior run found it", True)

    fake_chat_response = {"message": {"role": "assistant", "content": "ok", "tool_calls": []}}
    with patch("red_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = fake_chat_response
        run(config)

        messages_arg = MockOllama.return_value.chat.call_args.kwargs["messages"]
        assert any("prior run found it" in m.get("content", "") for m in messages_arg)


def test_run_waits_for_go_flag_before_starting(tmp_path):
    config = _config(tmp_path, max_iterations=1)
    # No go.flag created -- patch the wait helper so the test doesn't hang,
    # and assert it was actually called with the right arguments (same
    # pattern used for blue_agent's equivalent test).
    with patch("red_agent.loop._wait_for_go") as mock_wait, \
         patch("red_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = {
            "message": {"role": "assistant", "content": "ok", "tool_calls": []}
        }
        run(config)
        mock_wait.assert_called_once_with(config.referee_state_dir, 1.0)


def test_run_stops_immediately_when_stop_flag_already_present(tmp_path):
    config = _config(tmp_path, max_iterations=5)
    _touch_go_flag(config)
    (Path(config.referee_state_dir) / "stop.flag").touch()

    with patch("red_agent.loop.OllamaClient") as MockOllama:
        run(config)
        MockOllama.return_value.chat.assert_not_called()

    events = [json.loads(l) for l in Path(config.event_log_path).read_text().splitlines()]
    assert any(e["phase"] == "round_stop_acknowledged" for e in events)


def test_run_handles_malformed_tool_call_missing_function_key(tmp_path):
    """Test that a malformed tool_call (missing 'function' key) doesn't crash the loop."""
    config = _config(tmp_path, max_iterations=1)
    _touch_go_flag(config)

    # Simulate Ollama returning a malformed tool_calls entry (missing "function" key)
    malformed_response = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [{}],  # Missing "function" key entirely
        }
    }
    with patch("red_agent.loop.OllamaClient") as MockOllama:
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

    with patch("red_agent.loop.OllamaClient") as MockOllama:
        # Every iteration: raise HTTPError
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


def test_run_handles_ollama_key_error_gracefully(tmp_path):
    """Test that unexpected Ollama response shapes (KeyError) don't crash the loop."""
    config = _config(tmp_path, max_iterations=2)
    _touch_go_flag(config)

    with patch("red_agent.loop.OllamaClient") as MockOllama:
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
