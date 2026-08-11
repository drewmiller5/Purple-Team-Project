import json
from pathlib import Path
from unittest.mock import patch

import pytest

from dashboard.app import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENT_LOG_PATH", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("REFEREE_LOG_PATH", str(tmp_path / "assessments.jsonl"))
    monkeypatch.setenv("REFEREE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("TARGET_BASE_URL", "http://target:5000")
    monkeypatch.setenv("INTERNAL_ACTION_TOKEN", "secret-token")
    monkeypatch.setenv("ROUND_HELPER_TOKEN", "round-helper-secret")
    monkeypatch.setenv("ROUND_HELPER_URL", "http://round_helper:8090")
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setenv("ADVISOR_LOG_PATH", str(tmp_path / "advisor.jsonl"))
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "test-dashboard-token")
    # H55: separate scoped secrets per privilege domain, distinct from
    # DASHBOARD_AUTH_TOKEN (which only gates *viewing* the dashboard).
    # Each mutating action route additionally requires its own domain's
    # token via the X-Action-Token header, so a single leaked secret
    # doesn't grant all three capabilities (or the dashboard itself).
    monkeypatch.setenv("DASHBOARD_RED_ACTION_TOKEN", "test-red-action-token")
    monkeypatch.setenv("DASHBOARD_BLUE_ACTION_TOKEN", "test-blue-action-token")
    monkeypatch.setenv("DASHBOARD_INFRA_ACTION_TOKEN", "test-infra-action-token")
    return create_app()


AUTH = ("operator", "test-dashboard-token")
RED_ACTION_HEADERS = {"X-Action-Token": "test-red-action-token"}
BLUE_ACTION_HEADERS = {"X-Action-Token": "test-blue-action-token"}
INFRA_ACTION_HEADERS = {"X-Action-Token": "test-infra-action-token"}


def test_api_state_reports_latest_round_result(app):
    Path(app.config["REFEREE_LOG_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    with open(app.config["REFEREE_LOG_PATH"], "w") as f:
        f.write(json.dumps({"phase": "go_signal", "side": "white"}) + "\n")
        f.write(json.dumps({"phase": "round_over", "side": "white", "outcome": "blue", "elapsed_seconds": 12.5}) + "\n")

    response = app.test_client().get("/api/state", auth=AUTH)

    assert response.get_json()["latest_round_result"] == {"outcome": "blue", "elapsed_seconds": 12.5}


def test_api_state_latest_round_result_is_null_when_no_round_has_ended(app):
    response = app.test_client().get("/api/state", auth=AUTH)
    assert response.get_json()["latest_round_result"] is None


def test_api_state_excludes_reasoning_events_from_red_and_blue_ledgers(app):
    """H69: reasoning-only turns must not appear in the same ledger as real
    actions -- filtered server-side so the dashboard's per-team tabs and
    Combined Ledger never see them, even though the fix that decouples
    reasoning turns from the action budget means there can now be many
    more of them per round than real actions."""
    Path(app.config["EVENT_LOG_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    with open(app.config["EVENT_LOG_PATH"], "w") as f:
        f.write(json.dumps({"phase": "reasoning", "side": "red", "content": "thinking"}) + "\n")
        f.write(json.dumps({"phase": "finding", "side": "red", "category": "sqli"}) + "\n")
        f.write(json.dumps({"phase": "reasoning", "side": "blue", "content": "thinking"}) + "\n")

    data = app.test_client().get("/api/state", auth=AUTH).get_json()

    assert all(e["phase"] != "reasoning" for e in data["red_events"])
    assert all(e["phase"] != "reasoning" for e in data["blue_events"])
    assert any(e["phase"] == "finding" for e in data["red_events"])


def test_api_state_excludes_heartbeat_events_from_red_and_blue_ledgers(app):
    """H69 follow-up (independent review): blue's unconditional per-loop-pass
    heartbeat was never budget-capped in the first place, and reasoning turns
    no longer being capped means blue can now emit far more heartbeats per
    round too (it fires on every pass, including reasoning-only passes).
    Heartbeats add no ledger value on their own (the client already collapses
    runs of them) -- must be filtered the same way reasoning is."""
    Path(app.config["EVENT_LOG_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    with open(app.config["EVENT_LOG_PATH"], "w") as f:
        f.write(json.dumps({"phase": "heartbeat", "side": "blue"}) + "\n")
        f.write(json.dumps({"phase": "finding", "side": "blue", "category": "lock_account"}) + "\n")

    data = app.test_client().get("/api/state", auth=AUTH).get_json()

    assert all(e["phase"] != "heartbeat" for e in data["blue_events"])
    assert any(e["phase"] == "finding" for e in data["blue_events"])


def test_api_state_noise_flood_does_not_crowd_real_events_out_of_the_tail_window(app):
    """H69: neither reasoning nor heartbeat turns are budget-capped anymore,
    so a chatty round can log volumes of both far beyond any fixed raw-line
    read window (a flat constant sized against today's config values was
    itself flagged as fragile by review). The read must guarantee MAX_EVENTS
    real events are found regardless of how much noise precedes them, by
    scanning until enough are found rather than reading a fixed raw window
    and filtering what's left."""
    Path(app.config["EVENT_LOG_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    with open(app.config["EVENT_LOG_PATH"], "w") as f:
        f.write(json.dumps({"phase": "finding", "side": "red", "category": "sqli"}) + "\n")
        for i in range(6000):
            phase = "heartbeat" if i % 2 == 0 else "reasoning"
            f.write(json.dumps({"phase": phase, "side": "blue" if phase == "heartbeat" else "red"}) + "\n")

    data = app.test_client().get("/api/state", auth=AUTH).get_json()

    assert any(e["phase"] == "finding" for e in data["red_events"])


def test_round_clear_endpoint_clears_both_flag_files(app):
    """Real bug found live: this route was previously registered at
    /api/round/start (a copy-paste-shaped mislabel, zero test coverage) --
    it clears go.flag/stop.flag, it doesn't start anything. That path
    collided with the actual round-start feature's own /api/round/start
    once that got wired up, which is what surfaced this. Moved to
    /api/round/clear to match what it actually does."""
    state_dir = Path(app.config["REFEREE_STATE_DIR"])
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "go.flag").touch()
    (state_dir / "stop.flag").touch()

    response = app.test_client().post("/api/round/clear", auth=AUTH)

    assert response.status_code == 200
    assert response.get_json() == {"cleared": True}
    assert not (state_dir / "go.flag").exists()
    assert not (state_dir / "stop.flag").exists()


def test_round_stop_endpoint_touches_stop_flag(app):
    response = app.test_client().post("/api/round/stop", auth=AUTH)
    assert response.status_code == 200
    assert Path(app.config["REFEREE_STATE_DIR"], "stop.flag").exists()


def test_round_start_endpoint_calls_round_helper(app):
    with patch("dashboard.app.start_round", autospec=True) as mock_start:
        mock_start.return_value = {"started": ["referee", "red_agent", "blue_agent"]}
        response = app.test_client().post(
            "/api/round/start", auth=AUTH, headers=INFRA_ACTION_HEADERS
        )

    assert response.status_code == 200
    # H54: round_helper gets its own dedicated token, not target's
    # INTERNAL_ACTION_TOKEN -- a token leaked via target's RCE must not
    # reach round_helper's container-restart control plane.
    mock_start.assert_called_once_with("http://round_helper:8090", "round-helper-secret")


def test_red_action_endpoint_delegates_to_run_red_action(app):
    with patch("dashboard.app.run_red_action", autospec=True) as mock_run:
        mock_run.return_value = {"status_code": 200, "body": "ok"}
        response = app.test_client().post(
            "/api/red-action", json={"template_name": "sqli"}, auth=AUTH, headers=RED_ACTION_HEADERS
        )

    assert response.status_code == 200
    mock_run.assert_called_once()


def test_blue_action_endpoint_delegates_to_run_blue_action(app):
    with patch("dashboard.app.run_blue_action", autospec=True) as mock_run:
        mock_run.return_value = {"status_code": 200, "body": "ok"}
        response = app.test_client().post(
            "/api/blue-action",
            json={"action": "block_ip", "target": "10.0.0.5"},
            auth=AUTH,
            headers=BLUE_ACTION_HEADERS,
        )

    assert response.status_code == 200
    mock_run.assert_called_once()


def test_red_action_endpoint_rejects_missing_action_token(app):
    """H55: DASHBOARD_AUTH_TOKEN alone (view access) must not be enough
    to fire a red action -- the caller also needs the red-scoped secret."""
    with patch("dashboard.app.run_red_action", autospec=True) as mock_run:
        response = app.test_client().post("/api/red-action", json={"template_name": "sqli"}, auth=AUTH)

    assert response.status_code == 403
    mock_run.assert_not_called()


def test_red_action_endpoint_rejects_blue_scoped_token(app):
    """H55: a leaked blue-action token must not unlock red actions --
    the whole point of separating the three domains."""
    with patch("dashboard.app.run_red_action", autospec=True) as mock_run:
        response = app.test_client().post(
            "/api/red-action", json={"template_name": "sqli"}, auth=AUTH, headers=BLUE_ACTION_HEADERS
        )

    assert response.status_code == 403
    mock_run.assert_not_called()


def test_blue_action_endpoint_rejects_missing_action_token(app):
    with patch("dashboard.app.run_blue_action", autospec=True) as mock_run:
        response = app.test_client().post(
            "/api/blue-action", json={"action": "block_ip", "target": "10.0.0.5"}, auth=AUTH
        )

    assert response.status_code == 403
    mock_run.assert_not_called()


def test_blue_action_endpoint_rejects_red_scoped_token(app):
    with patch("dashboard.app.run_blue_action", autospec=True) as mock_run:
        response = app.test_client().post(
            "/api/blue-action",
            json={"action": "block_ip", "target": "10.0.0.5"},
            auth=AUTH,
            headers=RED_ACTION_HEADERS,
        )

    assert response.status_code == 403
    mock_run.assert_not_called()


def test_round_start_endpoint_rejects_missing_action_token(app):
    with patch("dashboard.app.start_round", autospec=True) as mock_start:
        response = app.test_client().post("/api/round/start", auth=AUTH)

    assert response.status_code == 403
    mock_start.assert_not_called()


def test_round_start_endpoint_rejects_red_scoped_token(app):
    """H55: the red/blue-action operator (or a leaked red/blue token)
    must not be able to reach round_helper's docker.sock-backed
    container-restart control plane -- that's the whole "infra control"
    domain the finding named."""
    with patch("dashboard.app.start_round", autospec=True) as mock_start:
        response = app.test_client().post(
            "/api/round/start", auth=AUTH, headers=RED_ACTION_HEADERS
        )

    assert response.status_code == 403
    mock_start.assert_not_called()


def test_advisor_endpoint_delegates_to_ask_advisor(app):
    with patch("dashboard.app.ask_advisor", autospec=True) as mock_ask:
        mock_ask.return_value = {"answer": "block it"}
        response = app.test_client().post("/api/advisor", json={"question": "what now?"}, auth=AUTH)

    assert response.status_code == 200
    assert response.get_json() == {"answer": "block it"}


_ACTION_ROUTE_HEADERS = {
    "/api/red-action": RED_ACTION_HEADERS,
    "/api/blue-action": BLUE_ACTION_HEADERS,
    "/api/advisor": {},
}


@pytest.mark.parametrize("route", ["/api/red-action", "/api/blue-action", "/api/advisor"])
@pytest.mark.parametrize("raw_body", ["null", "[]", '"x"', "42"])
def test_action_routes_reject_non_dict_json_body(app, route, raw_body):
    response = app.test_client().post(
        route,
        data=raw_body,
        content_type="application/json",
        auth=AUTH,
        headers=_ACTION_ROUTE_HEADERS[route],
    )
    assert response.status_code == 400


def test_protected_route_without_credentials_returns_401(app):
    response = app.test_client().get("/api/state")
    assert response.status_code == 401


def test_protected_route_with_wrong_credentials_returns_401(app):
    response = app.test_client().get("/api/state", auth=("operator", "wrong-token"))
    assert response.status_code == 401
