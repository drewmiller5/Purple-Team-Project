import json
from unittest.mock import MagicMock

from blue_agent.tools import TOOL_SCHEMAS, dispatch_tool_call


def test_tool_schemas_include_exactly_two_tools():
    names = {t["function"]["name"] for t in TOOL_SCHEMAS}
    assert names == {"escalate_response", "recall_past_findings"}


def test_dispatch_escalate_response_lock_account_posts_to_lock_account_endpoint():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": '{"locked": "admin"}'}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "lock_account", "target": "admin"},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/lock-account", data={"username": "admin"}
    )
    state.log_event.assert_called_once()
    assert json.loads(result) == {"status_code": 200, "body": '{"locked": "admin"}'}


def test_dispatch_escalate_response_kill_session_posts_to_kill_session_endpoint():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "{}"}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "kill_session", "target": "1"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/kill-session", data={"user_id": "1"}
    )


def test_dispatch_escalate_response_block_ip_posts_to_block_ip_endpoint():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "{}"}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "block_ip", "target": "172.19.0.5"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/block-ip", data={"source_ip": "172.19.0.5"}
    )


def test_dispatch_escalate_response_parses_string_arguments():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "{}"}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": json.dumps({"action": "lock_account", "target": "admin"}),
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/lock-account", data={"username": "admin"}
    )


def test_dispatch_escalate_response_unknown_action_returns_error():
    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "nuke_from_orbit", "target": "x"},
        }
    }
    result = dispatch_tool_call(call, http=MagicMock(), state=MagicMock())
    assert json.loads(result) == {"error": "unknown action nuke_from_orbit"}


def test_dispatch_escalate_response_missing_action_returns_error():
    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"target": "admin"},
        }
    }
    result = dispatch_tool_call(call, http=MagicMock(), state=MagicMock())
    assert json.loads(result) == {"error": "missing or invalid arguments for escalate_response: 'action'"}


def test_dispatch_escalate_response_missing_target_returns_error():
    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "lock_account"},
        }
    }
    result = dispatch_tool_call(call, http=MagicMock(), state=MagicMock())
    assert json.loads(result) == {"error": "missing or invalid arguments for escalate_response: 'target'"}


def test_dispatch_recall_past_findings_calls_state():
    state = MagicMock()
    state.recall_summary.return_value = "- [escalation] locked admin (success=True)"
    call = {"function": {"name": "recall_past_findings", "arguments": {}}}

    result = dispatch_tool_call(call, http=MagicMock(), state=state)

    assert result == "- [escalation] locked admin (success=True)"


def test_dispatch_recall_past_findings_defaults_when_empty():
    state = MagicMock()
    state.recall_summary.return_value = ""
    call = {"function": {"name": "recall_past_findings", "arguments": {}}}

    result = dispatch_tool_call(call, http=MagicMock(), state=state)

    assert result == "No prior findings."


def test_dispatch_unknown_tool_returns_error():
    call = {"function": {"name": "nonexistent_tool", "arguments": {}}}
    result = dispatch_tool_call(call, http=MagicMock(), state=MagicMock())
    assert json.loads(result) == {"error": "unknown tool nonexistent_tool"}
