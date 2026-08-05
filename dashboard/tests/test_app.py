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
    monkeypatch.setenv("ROUND_HELPER_URL", "http://round_helper:8090")
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setenv("ADVISOR_LOG_PATH", str(tmp_path / "advisor.jsonl"))
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "test-dashboard-token")
    return create_app()


AUTH = ("operator", "test-dashboard-token")


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


def test_api_state_reasoning_flood_does_not_crowd_real_events_out_of_the_tail_window(app):
    """H69: reasoning turns are no longer budget-capped, so a chatty model can
    log far more of them per round than real actions. The tail read must not
    let a flood of reasoning lines push a real action event out of the
    window before filtering ever gets to see it."""
    Path(app.config["EVENT_LOG_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    with open(app.config["EVENT_LOG_PATH"], "w") as f:
        f.write(json.dumps({"phase": "finding", "side": "red", "category": "sqli"}) + "\n")
        for _ in range(1000):
            f.write(json.dumps({"phase": "reasoning", "side": "red", "content": "thinking"}) + "\n")

    data = app.test_client().get("/api/state", auth=AUTH).get_json()

    assert any(e["phase"] == "finding" for e in data["red_events"])


def test_round_stop_endpoint_touches_stop_flag(app):
    response = app.test_client().post("/api/round/stop", auth=AUTH)
    assert response.status_code == 200
    assert Path(app.config["REFEREE_STATE_DIR"], "stop.flag").exists()


def test_round_restart_endpoint_calls_round_helper(app):
    with patch("dashboard.app.restart_round", autospec=True) as mock_restart:
        mock_restart.return_value = {"restarted": ["referee", "red_agent", "blue_agent"]}
        response = app.test_client().post("/api/round/restart", auth=AUTH)

    assert response.status_code == 200
    mock_restart.assert_called_once_with("http://round_helper:8090", "secret-token")


def test_red_action_endpoint_delegates_to_run_red_action(app):
    with patch("dashboard.app.run_red_action", autospec=True) as mock_run:
        mock_run.return_value = {"status_code": 200, "body": "ok"}
        response = app.test_client().post("/api/red-action", json={"template_name": "sqli"}, auth=AUTH)

    assert response.status_code == 200
    mock_run.assert_called_once()


def test_blue_action_endpoint_delegates_to_run_blue_action(app):
    with patch("dashboard.app.run_blue_action", autospec=True) as mock_run:
        mock_run.return_value = {"status_code": 200, "body": "ok"}
        response = app.test_client().post("/api/blue-action", json={"action": "block_ip", "target": "10.0.0.5"}, auth=AUTH)

    assert response.status_code == 200
    mock_run.assert_called_once()


def test_advisor_endpoint_delegates_to_ask_advisor(app):
    with patch("dashboard.app.ask_advisor", autospec=True) as mock_ask:
        mock_ask.return_value = {"answer": "block it"}
        response = app.test_client().post("/api/advisor", json={"question": "what now?"}, auth=AUTH)

    assert response.status_code == 200
    assert response.get_json() == {"answer": "block it"}


@pytest.mark.parametrize("route", ["/api/red-action", "/api/blue-action", "/api/advisor"])
@pytest.mark.parametrize("raw_body", ["null", "[]", '"x"', "42"])
def test_action_routes_reject_non_dict_json_body(app, route, raw_body):
    response = app.test_client().post(route, data=raw_body, content_type="application/json", auth=AUTH)
    assert response.status_code == 400


def test_protected_route_without_credentials_returns_401(app):
    response = app.test_client().get("/api/state")
    assert response.status_code == 401


def test_protected_route_with_wrong_credentials_returns_401(app):
    response = app.test_client().get("/api/state", auth=("operator", "wrong-token"))
    assert response.status_code == 401
