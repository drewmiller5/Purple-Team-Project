import os
from unittest.mock import MagicMock, patch

import docker

from round_helper.app import create_app, ALLOWED_CONTAINERS

VALID_TOKEN = "test-token-123"


def _client():
    app = create_app()
    app.config["INTERNAL_ACTION_TOKEN"] = VALID_TOKEN
    return app.test_client()


def test_restart_round_starts_exactly_the_allowlist_via_docker_sdk():
    """Root-cause fix: round_helper's image never actually shipped the
    `docker` CLI binary (docker.io's apt package only installed dockerd),
    so subprocess.run(["docker", "start", ...]) always failed with
    FileNotFoundError, live-verified. The SDK talks to docker.sock
    directly -- no CLI binary dependency at all."""
    client = _client()
    mock_docker_client = MagicMock()
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/restart-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 200
    assert response.get_json() == {"restarted": ALLOWED_CONTAINERS}
    started_names = [call.args[0] for call in mock_docker_client.containers.get.call_args_list]
    assert sorted(started_names) == sorted(ALLOWED_CONTAINERS)
    assert mock_docker_client.containers.get.return_value.start.call_count == len(ALLOWED_CONTAINERS)


def test_restart_round_returns_500_on_docker_error():
    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.return_value.start.side_effect = docker.errors.APIError("boom")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/restart-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 500
    assert "boom" in response.get_json()["error"]


def test_restart_round_returns_500_when_a_container_is_not_found():
    """docker.errors.NotFound is a DockerException subclass -- a missing
    container (never built, wrong name) must surface as a clean 500, not
    an unhandled exception."""
    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.side_effect = docker.errors.NotFound("no such container")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/restart-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 500
    assert "error" in response.get_json()


def test_restart_round_returns_500_on_raw_connection_error():
    """Review-round fix: docker-py's per-request HTTP calls only wrap
    requests.exceptions.HTTPError into a DockerException -- a raw
    ConnectionError (daemon mid-restart, socket hiccup) is NOT a
    DockerException subclass and previously propagated unhandled,
    producing Flask's generic 500 page instead of this endpoint's
    {"error": ...} JSON contract. requests.exceptions.RequestException
    subclasses IOError/OSError, so widening the except to OSError covers it."""
    import requests

    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.return_value.start.side_effect = requests.exceptions.ConnectionError("socket hiccup")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/restart-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 500
    assert "error" in response.get_json()


def test_restart_round_returns_401_on_missing_token():
    client = _client()
    with patch("round_helper.app.docker.from_env") as mock_from_env:
        response = client.post("/restart-round")

    assert response.status_code == 401
    assert "error" in response.get_json()
    mock_from_env.assert_not_called()


def test_restart_round_returns_401_on_wrong_token():
    client = _client()
    with patch("round_helper.app.docker.from_env") as mock_from_env:
        response = client.post(
            "/restart-round",
            headers={"X-Internal-Action-Token": "wrong-token"}
        )

    assert response.status_code == 401
    assert "error" in response.get_json()
    mock_from_env.assert_not_called()


def test_no_other_routes_exist():
    client = _client()
    for method, path in [("POST", "/restart"), ("POST", "/stop"), ("GET", "/containers")]:
        response = client.open(path, method=method)
        assert response.status_code == 404
