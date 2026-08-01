import json
from unittest.mock import MagicMock, patch

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


def test_dispatch_escalate_response_records_finding_on_successful_dispatch():
    """H20: escalate_response taking a real action must record it via
    state.record_finding so blue_memory.json/recall_past_findings actually
    accumulate history across runs, instead of record_finding being a
    permanent no-op with zero call sites outside its own unit test."""
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": '{"locked": "admin"}'}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "lock_account", "target": "admin"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    state.record_finding.assert_called_once_with(
        "lock_account", "lock_account on admin", True
    )


def test_dispatch_escalate_response_records_failed_finding_when_http_errors():
    http = MagicMock()
    http.request.return_value = {"error": "connection refused"}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "block_ip", "target": "10.0.0.5"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    state.record_finding.assert_called_once_with(
        "block_ip", "block_ip on 10.0.0.5", False
    )


def test_dispatch_escalate_response_rejected_target_does_not_record_finding():
    """The protected-infrastructure rejection path already logs an
    escalation_rejected event and never reaches http.request -- it should
    not also record a finding, since no action was actually taken."""
    http = MagicMock()
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "block_ip", "target": "127.0.0.1"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    state.record_finding.assert_not_called()


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


def test_dispatch_escalate_response_block_ip_rejects_loopback_target():
    """H3 regression test: escalate_response must not blindly forward
    whatever target the model produces for block_ip -- an indirect-prompt-
    injection-influenced decision to block loopback/infra must be rejected
    server-side (in blue_agent's own dispatch, not left solely to target's
    endpoint) rather than dispatched.
    """
    http = MagicMock()
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "block_ip", "target": "127.0.0.1"},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert json.loads(result) == {"error": "target is protected infrastructure, refusing to dispatch"}
    state.log_event.assert_called_once()
    logged = state.log_event.call_args[0][0]
    assert logged["phase"] == "escalation_rejected"


def test_dispatch_escalate_response_block_ip_rejects_infra_hostname_target():
    """H3 regression test, hostname-resolution branch: the loopback-literal
    test above never exercises _protected_block_ip_targets()'s hostname
    lookups (wazuh.manager/target/blue_agent), since 127.0.0.1 is caught
    by the earlier is_loopback check. Patch the resolved set directly to
    prove that branch itself rejects a matching target.
    """
    http = MagicMock()
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "block_ip", "target": "172.19.0.5"},
        }
    }
    with patch("blue_agent.tools._protected_block_ip_targets", return_value={"172.19.0.5"}):
        result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert json.loads(result) == {"error": "target is protected infrastructure, refusing to dispatch"}


def test_dispatch_escalate_response_block_ip_rejects_literal_infra_hostname_target():
    """H3 regression test: a model call naming an infra hostname directly
    (e.g. target="wazuh.manager", plausible since these hostnames appear in
    blue_agent's own system prompt/alert data) must be rejected even if
    DNS resolution of that hostname fails or isn't checked first -- not
    just its resolved IP.
    """
    http = MagicMock()
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "block_ip", "target": "wazuh.manager"},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert json.loads(result) == {"error": "target is protected infrastructure, refusing to dispatch"}


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
