# red_agent/tests/test_tools.py
import json
from unittest.mock import MagicMock

from red_agent.tools import TOOL_SCHEMAS, dispatch_tool_call


def test_tool_schemas_include_all_three_tools():
    names = {t["function"]["name"] for t in TOOL_SCHEMAS}
    assert names == {"http_request", "record_finding", "recall_past_findings"}


def test_dispatch_http_request_calls_http_tool_and_logs():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "ok"}
    state = MagicMock()

    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "GET", "path": "/search", "params": {"q": "x"}},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(method="GET", path="/search", params={"q": "x"}, data=None)
    state.log_event.assert_called_once()
    assert json.loads(result) == {"status_code": 200, "body": "ok"}


def test_dispatch_http_request_parses_string_arguments():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "ok"}
    state = MagicMock()

    call = {
        "function": {
            "name": "http_request",
            "arguments": json.dumps({"method": "GET", "path": "/"}),
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(method="GET", path="/", params=None, data=None)


def test_dispatch_record_finding_calls_state():
    state = MagicMock()
    call = {
        "function": {
            "name": "record_finding",
            "arguments": {"category": "sqli", "detail": "found it", "success": True},
        }
    }
    result = dispatch_tool_call(call, http=MagicMock(), state=state)

    state.record_finding.assert_called_once_with("sqli", "found it", True)
    assert json.loads(result) == {"recorded": True}


def test_dispatch_recall_past_findings_calls_state():
    state = MagicMock()
    state.recall_summary.return_value = "- [sqli] found it (success=True)"
    call = {"function": {"name": "recall_past_findings", "arguments": {}}}

    result = dispatch_tool_call(call, http=MagicMock(), state=state)

    assert result == "- [sqli] found it (success=True)"


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


def test_dispatch_http_request_missing_required_arg_returns_clean_error():
    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "GET"},  # missing required "path"
        }
    }
    result = dispatch_tool_call(call, http=MagicMock(), state=MagicMock())

    parsed = json.loads(result)
    assert "error" in parsed
