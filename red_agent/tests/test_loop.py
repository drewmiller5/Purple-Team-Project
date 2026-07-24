# red_agent/tests/test_loop.py
from unittest.mock import MagicMock, patch

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
    )


def test_run_stops_after_max_iterations(tmp_path):
    fake_chat_response = {
        "message": {"role": "assistant", "content": "thinking", "tool_calls": []}
    }
    with patch("red_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = fake_chat_response
        run(_config(tmp_path, max_iterations=3))
        assert MockOllama.return_value.chat.call_count == 3


def test_run_dispatches_tool_calls(tmp_path):
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
        run(_config(tmp_path, max_iterations=1))
        mock_dispatch.assert_called_once()


def test_run_includes_target_base_url_in_system_prompt(tmp_path):
    fake_chat_response = {"message": {"role": "assistant", "content": "ok", "tool_calls": []}}
    with patch("red_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = fake_chat_response
        run(_config(tmp_path, max_iterations=1))

        messages_arg = MockOllama.return_value.chat.call_args.kwargs["messages"]
        system_message = messages_arg[0]
        assert system_message["role"] == "system"
        assert "http://target:5000" in system_message["content"]


def test_run_seeds_past_findings_into_context_when_present(tmp_path):
    from red_agent.state import RedAgentState
    config = _config(tmp_path, max_iterations=1)
    RedAgentState(config).record_finding("sqli", "prior run found it", True)

    fake_chat_response = {"message": {"role": "assistant", "content": "ok", "tool_calls": []}}
    with patch("red_agent.loop.OllamaClient") as MockOllama:
        MockOllama.return_value.chat.return_value = fake_chat_response
        run(config)

        messages_arg = MockOllama.return_value.chat.call_args.kwargs["messages"]
        assert any("prior run found it" in m.get("content", "") for m in messages_arg)
