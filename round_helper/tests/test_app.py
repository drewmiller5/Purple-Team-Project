import os
from unittest.mock import patch

from round_helper.app import create_app, ALLOWED_CONTAINERS

VALID_TOKEN = "test-token-123"


def _client():
    app = create_app()
    app.config["INTERNAL_ACTION_TOKEN"] = VALID_TOKEN
    return app.test_client()


def test_restart_round_runs_docker_start_for_exactly_the_allowlist():
    client = _client()
    with patch("round_helper.app.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        response = client.post(
            "/restart-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 200
    assert response.get_json() == {"restarted": ALLOWED_CONTAINERS}
    called_args = mock_run.call_args.args[0]
    assert called_args[:2] == ["docker", "start"]
    assert sorted(called_args[2:]) == sorted(ALLOWED_CONTAINERS)


def test_restart_round_returns_500_on_compose_failure():
    client = _client()
    with patch("round_helper.app.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "boom"
        response = client.post(
            "/restart-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 500
    assert "boom" in response.get_json()["error"]


def test_restart_round_returns_401_on_missing_token():
    client = _client()
    with patch("round_helper.app.subprocess.run") as mock_run:
        response = client.post("/restart-round")

    assert response.status_code == 401
    assert "error" in response.get_json()
    mock_run.assert_not_called()


def test_restart_round_returns_401_on_wrong_token():
    client = _client()
    with patch("round_helper.app.subprocess.run") as mock_run:
        response = client.post(
            "/restart-round",
            headers={"X-Internal-Action-Token": "wrong-token"}
        )

    assert response.status_code == 401
    assert "error" in response.get_json()
    mock_run.assert_not_called()


def test_no_other_routes_exist():
    client = _client()
    for method, path in [("POST", "/restart"), ("POST", "/stop"), ("GET", "/containers")]:
        response = client.open(path, method=method)
        assert response.status_code == 404
