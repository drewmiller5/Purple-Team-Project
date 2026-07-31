import json
import threading
import time
from pathlib import Path

import pytest
import responses

from dashboard.actions import RED_TEMPLATES, run_blue_action, run_red_action
from target.app import create_app


@pytest.fixture
def live_target(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    server = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=15002, use_reloader=False),
        daemon=True,
    )
    server.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:15002"


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


def test_run_red_action_session_persists_cookie_across_bruteforce_then_command_injection(
    live_target, tmp_path
):
    # Proves the fix: a real login (bruteforce -> /admin/login) sets a
    # session cookie that must carry over to a later, separate
    # run_red_action call (command_injection -> /admin/diagnostics), which
    # is gated on session.get("role") == "admin" (target/routes/diagnostics.py).
    # Without a persistent session behind _do_request, this second call
    # always 403s and found_it can never be True for real operators.
    log_path = str(tmp_path / "events.jsonl")

    run_red_action(live_target, template_name="bruteforce", event_log_path=log_path)
    result = run_red_action(live_target, template_name="command_injection", event_log_path=log_path)

    assert result["status_code"] == 200
