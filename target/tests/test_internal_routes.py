# target/tests/test_internal_routes.py
from target.app import create_app
from target.db import get_connection


def _make_app(tmp_path):
    return create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )


def _make_client(tmp_path):
    return _make_app(tmp_path).test_client()


def test_lock_account_blocks_future_login(tmp_path):
    client = _make_client(tmp_path)
    client.post("/internal/lock-account", data={"username": "admin"})

    response = client.post(
        "/admin/login", data={"username": "admin", "password": "admin123"}
    )
    assert b"Welcome" not in response.data
    assert b"blocked" in response.data.lower()


def test_kill_session_blocks_subsequent_admin_requests(tmp_path):
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    login_row = client.get("/admin/whoami").get_json()
    client.post("/internal/kill-session", data={"user_id": login_row["user_id"]})

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
    response = client.post("/internal/kill-session", data={})
    assert response.status_code == 400

    # Non-numeric user_id.
    response = client.post("/internal/kill-session", data={"user_id": "not-a-number"})
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

    first = client.post("/internal/lock-account", data={"username": "admin"})
    second = client.post("/internal/lock-account", data={"username": "admin"})

    assert first.status_code == 200
    assert second.status_code == 200

    conn = get_connection(app.config["DB_PATH"])
    rows = conn.execute(
        "SELECT COUNT(*) FROM blocked_users WHERE username = ?", ("admin",)
    ).fetchone()[0]
    conn.close()

    assert rows == 1
