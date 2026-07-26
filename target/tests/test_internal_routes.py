# target/tests/test_internal_routes.py
from target.app import create_app


def _make_client(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    return app.test_client()


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
