# target/tests/test_admin_routes.py
from target.app import create_app


def _make_client(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    return app.test_client()


def test_login_rejects_wrong_password(tmp_path):
    client = _make_client(tmp_path)
    response = client.post("/admin/login", data={"username": "admin", "password": "wrong"})
    assert b"Invalid credentials" in response.data


def test_seeded_weak_admin_credentials_grant_access(tmp_path):
    """Seeded vulnerability regression test: default/weak admin creds
    work. Proves red_agent has a real, discoverable path in via
    credential guessing. If this fails, the seeded weak password was
    changed.
    """
    client = _make_client(tmp_path)
    response = client.post("/admin/login", data={"username": "admin", "password": "admin123"})
    assert b"Welcome, admin" in response.data
    assert b"Role: admin" in response.data


def test_no_lockout_after_repeated_failed_attempts(tmp_path):
    """Seeded vulnerability regression test: no brute-force protection."""
    client = _make_client(tmp_path)
    for _ in range(10):
        client.post("/admin/login", data={"username": "admin", "password": "wrong"})
    response = client.post("/admin/login", data={"username": "admin", "password": "admin123"})
    assert b"Welcome, admin" in response.data
