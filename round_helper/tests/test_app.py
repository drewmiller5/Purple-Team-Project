import os
from unittest.mock import MagicMock, patch

import docker

from round_helper.app import create_app, ALLOWED_CONTAINERS, TARGET_CONTAINER

VALID_TOKEN = "test-token-123"


def _client():
    app = create_app()
    app.config["INTERNAL_ACTION_TOKEN"] = VALID_TOKEN
    return app.test_client()


def test_start_round_restarts_exactly_the_allowlist_via_docker_sdk():
    """docker.io's apt package never shipped the `docker` CLI binary
    (confirmed via dpkg -L docker.io, live-verified) -- the SDK talks to
    docker.sock directly, no CLI dependency. Uses container.restart(), not
    .start(): the user found that a plain `docker start` no-ops on an
    already-running container, so clicking this while a round is mid-flight
    did nothing. restart() forces a fresh process every time, whether the
    containers were running or already exited -- the whole point of a
    single "Start Round" action that always works."""
    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.return_value.exec_run.return_value = MagicMock(exit_code=0, output=b"")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/start-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 200
    assert response.get_json() == {"started": ALLOWED_CONTAINERS}
    get_calls = [call.args[0] for call in mock_docker_client.containers.get.call_args_list]
    assert set(ALLOWED_CONTAINERS).issubset(get_calls)
    assert mock_docker_client.containers.get.return_value.restart.call_count == len(ALLOWED_CONTAINERS)
    mock_docker_client.containers.get.return_value.start.assert_not_called()


def test_start_round_flushes_target_iptables_after_restarting_containers():
    """block_ip (target/routes/internal.py) inserts iptables DROP rules on
    target's INPUT/FORWARD chains with no expiry. target is never restarted
    between rounds (only referee/red/blue are), and red keeps the same
    container IP across restarts on the same network -- confirmed live: a
    single successful block_ip call in round 1 silently pre-blocked red in
    every round since (172.21.0.6 still DROP-blocked hours later). Flushing
    both chains here gives every round a fair, independent trial without
    touching agent memory (red/blue/white_memory.json stay untouched)."""
    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.return_value.exec_run.return_value = MagicMock(exit_code=0, output=b"")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/start-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 200
    get_calls = [call.args[0] for call in mock_docker_client.containers.get.call_args_list]
    assert TARGET_CONTAINER in get_calls
    exec_calls = [call.args[0] for call in mock_docker_client.containers.get.return_value.exec_run.call_args_list]
    assert ["iptables", "-F", "INPUT"] in exec_calls
    assert ["iptables", "-F", "FORWARD"] in exec_calls


def test_start_round_returns_500_when_iptables_flush_fails():
    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.return_value.exec_run.return_value = MagicMock(exit_code=1, output=b"iptables: command failed")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/start-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 500
    assert "error" in response.get_json()


def test_start_round_returns_500_on_docker_error():
    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.return_value.restart.side_effect = docker.errors.APIError("boom")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/start-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 500
    assert "boom" in response.get_json()["error"]


def test_start_round_returns_500_when_a_container_is_not_found():
    """docker.errors.NotFound is a DockerException subclass -- a missing
    container (never built, wrong name) must surface as a clean 500, not
    an unhandled exception."""
    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.side_effect = docker.errors.NotFound("no such container")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/start-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 500
    assert "error" in response.get_json()


def test_start_round_returns_500_on_raw_connection_error():
    """docker-py's per-request HTTP calls only wrap
    requests.exceptions.HTTPError into a DockerException -- a raw
    ConnectionError (daemon mid-restart, socket hiccup) is NOT a
    DockerException subclass. requests.exceptions.RequestException
    subclasses IOError/OSError, so widening the except to OSError covers it."""
    import requests

    client = _client()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.return_value.restart.side_effect = requests.exceptions.ConnectionError("socket hiccup")
    with patch("round_helper.app.docker.from_env", return_value=mock_docker_client):
        response = client.post(
            "/start-round",
            headers={"X-Internal-Action-Token": VALID_TOKEN}
        )

    assert response.status_code == 500
    assert "error" in response.get_json()


def test_start_round_returns_401_on_missing_token():
    client = _client()
    with patch("round_helper.app.docker.from_env") as mock_from_env:
        response = client.post("/start-round")

    assert response.status_code == 401
    assert "error" in response.get_json()
    mock_from_env.assert_not_called()


def test_start_round_returns_401_on_wrong_token():
    client = _client()
    with patch("round_helper.app.docker.from_env") as mock_from_env:
        response = client.post(
            "/start-round",
            headers={"X-Internal-Action-Token": "wrong-token"}
        )

    assert response.status_code == 401
    assert "error" in response.get_json()
    mock_from_env.assert_not_called()


def test_no_other_routes_exist():
    client = _client()
    for method, path in [("POST", "/restart"), ("POST", "/restart-round"), ("POST", "/stop"), ("GET", "/containers")]:
        response = client.open(path, method=method)
        assert response.status_code == 404
