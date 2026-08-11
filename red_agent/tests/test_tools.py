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


def test_dispatch_recall_past_findings_handles_corrupt_memory():
    """H66: shared/memory.py's typed ValueError on corrupt JSON, raised
    from state.recall_summary() when the model calls this tool mid-run,
    must not crash the process -- same guard as H17's round-start call in
    loop.py, applied to this second call site."""
    state = MagicMock()
    state.recall_summary.side_effect = ValueError("corrupt memory file")
    call = {"function": {"name": "recall_past_findings", "arguments": {}}}

    result = dispatch_tool_call(call, http=MagicMock(), state=state)

    assert result == "No prior findings."
    state.log_event.assert_called_once()
    assert state.log_event.call_args[0][0]["phase"] == "memory_corrupt"


def test_dispatch_unknown_tool_returns_error():
    call = {"function": {"name": "nonexistent_tool", "arguments": {}}}
    result = dispatch_tool_call(call, http=MagicMock(), state=MagicMock())
    assert json.loads(result) == {"error": "unknown tool nonexistent_tool"}


def test_dispatch_record_finding_coerces_string_bool_success():
    """H18: TOOL_SCHEMAS declares `success` as a boolean, but a model can
    emit a string like "true" -- must be coerced, not persisted as-is."""
    state = MagicMock()
    call = {
        "function": {
            "name": "record_finding",
            "arguments": {"category": "sqli", "detail": "found it", "success": "true"},
        }
    }
    result = dispatch_tool_call(call, http=MagicMock(), state=state)

    state.record_finding.assert_called_once_with("sqli", "found it", True)
    assert json.loads(result) == {"recorded": True}


def test_dispatch_record_finding_rejects_non_boolean_success():
    """H18: a value that isn't a bool or a recognizable "true"/"false" string
    must be rejected cleanly, not stored unchecked and fed back into later
    runs as a misleading history entry."""
    state = MagicMock()
    call = {
        "function": {
            "name": "record_finding",
            "arguments": {"category": "sqli", "detail": "found it", "success": "maybe"},
        }
    }
    result = dispatch_tool_call(call, http=MagicMock(), state=state)

    state.record_finding.assert_not_called()
    assert "error" in json.loads(result)


def test_dispatch_http_request_rejects_method_outside_declared_enum():
    """H64: TOOL_SCHEMAS's method enum (GET/POST) is currently advisory
    only -- dispatch_tool_call passes args["method"] straight through with
    no allow-list check. Must be server-enforced, not just advisory."""
    http = MagicMock()
    state = MagicMock()
    state.recon_done = True  # even post-recon, an out-of-enum method must be rejected

    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "DELETE", "path": "/admin/users/1"},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert "error" in json.loads(result)


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


def test_dispatch_http_request_injection_shaped_get_blocked_before_recon():
    """K5: an injection-shaped GET (SQLi payload in params) is attack-class,
    rejected before any recon-class request has happened this round."""
    http = MagicMock()
    state = MagicMock()
    state.recon_done = False

    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "GET", "path": "/search", "params": {"q": "' OR '1'='1"}},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    parsed = json.loads(result)
    assert "error" in parsed
    assert "recon" in parsed["error"].lower()


def test_dispatch_http_request_post_is_attack_class_blocked_before_recon():
    http = MagicMock()
    state = MagicMock()
    state.recon_done = False

    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "POST", "path": "/admin/login", "data": {"username": "admin", "password": "x"}},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert "error" in json.loads(result)


def test_dispatch_http_request_plain_get_is_recon_class_and_marks_recon_done():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "ok"}
    state = MagicMock()
    state.recon_done = False

    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "GET", "path": "/", "params": None},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once()
    assert state.recon_done is True
    assert json.loads(result) == {"status_code": 200, "body": "ok"}


def test_dispatch_http_request_blind_sqli_and_keyword_blocked_before_recon():
    """Review-round fix: the indicator list originally had ' or ' but not
    ' and ', so a boolean-blind SQLi probe like 'id=1 AND 1=1' classified as
    recon-class -- bypassing the gate AND opening it for every later
    attack-class request this round. ' and ' must be a marker too."""
    http = MagicMock()
    state = MagicMock()
    state.recon_done = False

    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "GET", "path": "/product", "params": {"id": "1 AND 1=1"}},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert "error" in json.loads(result)
    assert state.recon_done is False


def test_dispatch_http_request_lowercase_get_is_not_attack_class():
    """Review-round fix: classification must not depend on method casing --
    a model emitting lowercase 'get' should still be treated as GET, not
    misclassified as a non-GET (attack-class) method."""
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "ok"}
    state = MagicMock()
    state.recon_done = False

    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "get", "path": "/", "params": None},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once()
    assert state.recon_done is True


def test_dispatch_http_request_attack_class_allowed_after_recon_done():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "ok"}
    state = MagicMock()
    state.recon_done = True

    call = {
        "function": {
            "name": "http_request",
            "arguments": {"method": "POST", "path": "/admin/login", "data": {"username": "admin", "password": "x"}},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once()
    assert json.loads(result) == {"status_code": 200, "body": "ok"}
