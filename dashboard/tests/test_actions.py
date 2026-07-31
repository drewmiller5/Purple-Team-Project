import json
from pathlib import Path

import responses

from dashboard.actions import RED_TEMPLATES, run_blue_action, run_red_action


@responses.activate
def test_run_red_action_sqli_template_hits_search_and_logs_event(tmp_path):
    responses.add(responses.GET, "http://target:5000/search", json={"results": []}, status=200)
    log_path = str(tmp_path / "events.jsonl")

    result = run_red_action("http://target:5000", template_name="sqli", event_log_path=log_path)

    assert result["status_code"] == 200
    logged = json.loads(Path(log_path).read_text().splitlines()[0])
    assert logged["side"] == "red"
    assert logged["actor"] == "human"
    assert logged["phase"] == "http_request"
    assert logged["request"]["path"] == RED_TEMPLATES["sqli"]["path"]


@responses.activate
def test_run_red_action_raw_request_hits_given_method_and_path(tmp_path):
    responses.add(responses.POST, "http://target:5000/admin/login", json={}, status=401)
    log_path = str(tmp_path / "events.jsonl")

    result = run_red_action(
        "http://target:5000",
        raw={"method": "POST", "path": "/admin/login", "data": {"username": "x", "password": "y"}},
        event_log_path=log_path,
    )

    assert result["status_code"] == 401
    logged = json.loads(Path(log_path).read_text().splitlines()[0])
    assert logged["request"]["path"] == "/admin/login"


def test_run_red_action_requires_template_or_raw(tmp_path):
    result = run_red_action("http://target:5000", event_log_path=str(tmp_path / "events.jsonl"))
    assert "error" in result


@responses.activate
def test_run_red_action_command_injection_hitting_diagnostics_sets_found_it(tmp_path):
    responses.add(responses.POST, "http://target:5000/admin/diagnostics", json={"output": "uid=0"}, status=200)
    log_path = str(tmp_path / "events.jsonl")

    result = run_red_action("http://target:5000", template_name="command_injection", event_log_path=log_path)

    assert result["found_it"] is True


@responses.activate
def test_run_red_action_sqli_does_not_set_found_it_even_on_200(tmp_path):
    # found_it mirrors the referee's own red-win shape (host access via
    # /admin/diagnostics specifically), not "any successful request."
    responses.add(responses.GET, "http://target:5000/search", json={"results": []}, status=200)
    log_path = str(tmp_path / "events.jsonl")

    result = run_red_action("http://target:5000", template_name="sqli", event_log_path=log_path)

    assert result["found_it"] is False


@responses.activate
def test_run_blue_action_block_ip_attaches_token_and_logs_event(tmp_path):
    responses.add(
        responses.POST, "http://target:5000/internal/block-ip",
        json={"blocked_ip": "10.0.0.5"}, status=200,
        match=[responses.matchers.header_matcher({"X-Internal-Action-Token": "secret-token"})],
    )
    log_path = str(tmp_path / "events.jsonl")

    result = run_blue_action(
        "http://target:5000", "secret-token", action="block_ip", target="10.0.0.5",
        event_log_path=log_path,
    )

    assert result["status_code"] == 200
    assert result["found_it"] is True
    logged = json.loads(Path(log_path).read_text().splitlines()[0])
    assert logged["side"] == "blue"
    assert logged["actor"] == "human"
    assert logged["phase"] == "escalation"
    assert logged["action"] == "block_ip"


@responses.activate
def test_run_blue_action_error_response_does_not_set_found_it(tmp_path):
    responses.add(responses.POST, "http://target:5000/internal/block-ip", json={"error": "bad ip"}, status=400)
    log_path = str(tmp_path / "events.jsonl")

    result = run_blue_action(
        "http://target:5000", "secret-token", action="block_ip", target="not-an-ip",
        event_log_path=log_path,
    )

    assert result["found_it"] is False


def test_run_blue_action_rejects_unknown_action(tmp_path):
    result = run_blue_action(
        "http://target:5000", "secret-token", action="not_real", target="x",
        event_log_path=str(tmp_path / "events.jsonl"),
    )
    assert "error" in result
