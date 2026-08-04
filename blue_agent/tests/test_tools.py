import json
from unittest.mock import MagicMock, patch

from blue_agent.tools import TOOL_SCHEMAS, dispatch_tool_call


def test_tool_schemas_include_exactly_two_tools():
    names = {t["function"]["name"] for t in TOOL_SCHEMAS}
    assert names == {"escalate_response", "recall_past_findings"}


def test_dispatch_escalate_response_lock_account_posts_to_lock_account_endpoint():
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": '{"locked": "jsmith"}'}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "lock_account", "target": "jsmith"},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/lock-account", data={"username": "jsmith"}
    )
    state.log_event.assert_called_once()
    assert json.loads(result) == {"status_code": 200, "body": '{"locked": "jsmith"}'}


def test_dispatch_escalate_response_records_finding_on_successful_dispatch():
    """H20: escalate_response taking a real action must record it via
    state.record_finding so blue_memory.json/recall_past_findings actually
    accumulate history across runs, instead of record_finding being a
    permanent no-op with zero call sites outside its own unit test."""
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": '{"locked": "jsmith"}'}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "lock_account", "target": "jsmith"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    state.record_finding.assert_called_once_with(
        "lock_account", "lock_account on jsmith", True
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


def test_dispatch_escalate_response_records_failed_finding_on_non_2xx_status():
    """Reviewer-flagged gap: a non-2xx response (e.g. 403 from a bad
    internal-action token, or 500 from the target) never raises
    RequestException, so HttpTool.request returns it with no "error" key
    -- "error" not in result alone would misrecord this as success."""
    http = MagicMock()
    http.request.return_value = {"status_code": 403, "body": '{"error": "bad token"}'}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "kill_session", "target": "2"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    state.record_finding.assert_called_once_with(
        "kill_session", "kill_session on 2", False
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
            "arguments": {"action": "kill_session", "target": "2"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/kill-session", data={"user_id": "2"}
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
            "arguments": json.dumps({"action": "lock_account", "target": "jsmith"}),
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/lock-account", data={"username": "jsmith"}
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


def test_dispatch_escalate_response_lock_account_rejects_admin_target():
    """H51: a prompt-injected blue_agent must not be able to permanently
    lock out the admin account, which is also red's designed win path
    (admin login -> /admin/diagnostics). Rejected before dispatch, same
    pattern as block_ip's infra-denylist.
    """
    http = MagicMock()
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "lock_account", "target": "admin"},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert json.loads(result) == {"error": "target is a protected account, refusing to dispatch"}
    state.log_event.assert_called_once()
    logged = state.log_event.call_args[0][0]
    assert logged["phase"] == "escalation_rejected"
    assert logged["action"] == "lock_account"
    assert logged["target"] == "admin"
    state.record_finding.assert_not_called()


def test_dispatch_escalate_response_kill_session_rejects_admin_user_id():
    """H51, kill_session's equivalent of the lock_account admin-protection
    test above. kill_session targets by numeric user_id, not username --
    admin is seeded first in target/db.py's AUTOINCREMENT users table, so
    its user_id is deterministically "1" for any fresh deployment.
    """
    http = MagicMock()
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "kill_session", "target": "1"},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert json.loads(result) == {"error": "target is a protected account, refusing to dispatch"}
    state.record_finding.assert_not_called()


def test_dispatch_escalate_response_lock_account_accepts_non_admin_target():
    """No regression: a non-admin username must still dispatch normally."""
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "{}"}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "lock_account", "target": "jsmith"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/lock-account", data={"username": "jsmith"}
    )


def test_dispatch_escalate_response_kill_session_accepts_non_admin_user_id():
    """No regression: a non-admin numeric user_id must still dispatch normally."""
    http = MagicMock()
    http.request.return_value = {"status_code": 200, "body": "{}"}
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "kill_session", "target": "2"},
        }
    }
    dispatch_tool_call(call, http=http, state=state)

    http.request.assert_called_once_with(
        method="POST", path="/internal/kill-session", data={"user_id": "2"}
    )


def test_dispatch_escalate_response_lock_account_rejects_empty_username():
    """H23: target's server-side already rejects an empty/whitespace-only
    username (H13). Add the same class of check client-side in blue_agent
    as defense-in-depth, matching kill_session's existing numeric
    validation below.
    """
    http = MagicMock()
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "lock_account", "target": "   "},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert json.loads(result) == {"error": "username is required, refusing to dispatch"}


def test_dispatch_escalate_response_kill_session_rejects_non_numeric_user_id():
    """H23: kill_session's user_id is already validated numeric server-side
    (target/routes/internal.py's request.form.get(..., type=int)) -- add
    the same class of check client-side as defense-in-depth.
    """
    http = MagicMock()
    state = MagicMock()

    call = {
        "function": {
            "name": "escalate_response",
            "arguments": {"action": "kill_session", "target": "not-a-number"},
        }
    }
    result = dispatch_tool_call(call, http=http, state=state)

    http.request.assert_not_called()
    assert json.loads(result) == {"error": "user_id must be numeric, refusing to dispatch"}


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
