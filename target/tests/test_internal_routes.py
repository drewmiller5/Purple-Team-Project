# target/tests/test_internal_routes.py
from unittest.mock import patch

from target.app import create_app
from target.db import get_connection

INTERNAL_ACTION_TOKEN = "test-internal-action-token"


def _make_app(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    app.config["INTERNAL_ACTION_TOKEN"] = INTERNAL_ACTION_TOKEN
    return app


def _make_client(tmp_path):
    return _make_app(tmp_path).test_client()


def _internal_post(client, path, data):
    return client.post(
        path,
        data=data,
        headers={"X-Internal-Action-Token": INTERNAL_ACTION_TOKEN},
    )


def test_internal_actions_require_the_configured_token(tmp_path):
    client = _make_client(tmp_path)

    for path, data in (
        ("/internal/lock-account", {"username": "admin"}),
        ("/internal/kill-session", {"user_id": "1"}),
        ("/internal/block-ip", {"source_ip": "198.51.100.9"}),
    ):
        missing = client.post(path, data=data)
        wrong = client.post(
            path,
            data=data,
            headers={"X-Internal-Action-Token": "wrong-token"},
        )

        assert missing.status_code == 403
        assert wrong.status_code == 403


def test_lock_account_blocks_future_login(tmp_path):
    client = _make_client(tmp_path)
    _internal_post(client, "/internal/lock-account", {"username": "admin"})

    response = client.post(
        "/admin/login", data={"username": "admin", "password": "admin123"}
    )
    assert b"Welcome" not in response.data
    assert b"blocked" in response.data.lower()


def test_kill_session_blocks_subsequent_admin_requests(tmp_path):
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    login_row = client.get("/admin/whoami").get_json()
    _internal_post(client, "/internal/kill-session", {"user_id": login_row["user_id"]})

    response = client.post("/admin/diagnostics", data={"host": "127.0.0.1"})
    assert response.status_code == 403


def test_unblocked_account_logs_in_normally(tmp_path):
    client = _make_client(tmp_path)
    response = client.post(
        "/admin/login", data={"username": "admin", "password": "admin123"}
    )
    assert b"Welcome" in response.data


def test_kill_session_rejects_missing_or_non_numeric_user_id(tmp_path):
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    # Missing user_id entirely.
    response = _internal_post(client, "/internal/kill-session", {})
    assert response.status_code == 400

    # Non-numeric user_id.
    response = _internal_post(client, "/internal/kill-session", {"user_id": "not-a-number"})
    assert response.status_code == 400

    # Confirm no NULL block row was inserted -- the admin session is still
    # live and diagnostics still succeeds (not silently "killed").
    diag_response = client.post("/admin/diagnostics", data={"host": "127.0.0.1"})
    assert diag_response.status_code != 403


def test_lock_account_does_not_duplicate_row_for_already_blocked_username(tmp_path):
    # Final-review fix (finding #5): bruteforce-guard.sh re-invokes
    # lock-account.sh on every subsequent matching event once the window
    # count is >=5, so a real brute-force burst dispatches multiple
    # /internal/lock-account POSTs for the same username. Live-verified:
    # 6 POSTs past threshold used to produce 6 identical ('admin', None)
    # rows. The endpoint must dedup instead of inserting every time.
    app = _make_app(tmp_path)
    client = app.test_client()

    first = _internal_post(client, "/internal/lock-account", {"username": "admin"})
    second = _internal_post(client, "/internal/lock-account", {"username": "admin"})

    assert first.status_code == 200
    assert second.status_code == 200

    conn = get_connection(app.config["DB_PATH"])
    rows = conn.execute(
        "SELECT COUNT(*) FROM blocked_users WHERE username = ?", ("admin",)
    ).fetchone()[0]
    conn.close()

    assert rows == 1


def test_block_ip_rejects_missing_source_ip(tmp_path):
    client = _make_client(tmp_path)
    response = _internal_post(client, "/internal/block-ip", {})
    assert response.status_code == 400


def test_block_ip_rejects_invalid_ip_format(tmp_path):
    client = _make_client(tmp_path)
    response = _internal_post(client, "/internal/block-ip", {"source_ip": "not-an-ip; rm -rf /"})
    assert response.status_code == 400


def test_block_ip_runs_iptables_drop_for_valid_ip(tmp_path):
    client = _make_client(tmp_path)
    with patch("target.routes.internal.subprocess.run") as mock_run:
        # Configure mock to report success (returncode=0).
        mock_run.return_value.returncode = 0
        response = _internal_post(client, "/internal/block-ip", {"source_ip": "172.19.0.5"})

    assert response.status_code == 200
    assert response.get_json() == {"blocked_ip": "172.19.0.5"}
    calls = [c.args[0] for c in mock_run.call_args_list]
    assert ["iptables", "-I", "INPUT", "-s", "172.19.0.5", "-j", "DROP"] in calls
    assert ["iptables", "-I", "FORWARD", "-s", "172.19.0.5", "-j", "DROP"] in calls


def test_block_ip_returns_500_when_iptables_fails(tmp_path):
    client = _make_client(tmp_path)
    with patch("target.routes.internal.subprocess.run") as mock_run:
        # Configure mock to report failure (returncode=1) on first call.
        mock_run.return_value.returncode = 1
        response = _internal_post(client, "/internal/block-ip", {"source_ip": "172.19.0.5"})

    assert response.status_code == 500
    response_data = response.get_json()
    assert "error" in response_data
    assert response_data["blocked_ip"] == "172.19.0.5"


def test_block_ip_rejects_resolved_infrastructure_addresses(tmp_path):
    client = _make_client(tmp_path)

    with patch(
        "target.routes.internal._protected_source_ips",
        return_value={"172.19.0.1", "172.19.0.2", "172.19.0.3", "172.19.0.4"},
    ), patch("target.routes.internal.subprocess.run") as mock_run:
        for source_ip in ("172.19.0.1", "172.19.0.2", "172.19.0.3", "172.19.0.4"):
            response = _internal_post(client, "/internal/block-ip", {"source_ip": source_ip})
            assert response.status_code == 403
            assert response.get_json()["error"] == "source_ip is protected infrastructure"

    mock_run.assert_not_called()
