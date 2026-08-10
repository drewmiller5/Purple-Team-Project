# target/tests/test_admin_routes.py
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

from target.app import create_app

# The value SECRET_KEY was hardcoded to in source before it was randomized
# (H6). Used only to prove a cookie forged with this now-public value is
# rejected -- if this literal is ever reintroduced as the real key, this
# test starts failing "for the right reason."
_LEAKED_SECRET_KEY = "purple-lab-dev-key"


def _make_app(tmp_path):
    return create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )


def _make_client(tmp_path):
    return _make_app(tmp_path).test_client()


def _forge_session_cookie(secret_key, data):
    interface = SecureCookieSessionInterface()
    serializer = URLSafeTimedSerializer(
        secret_key,
        salt=interface.salt,
        serializer=interface.serializer,
        signer_kwargs=dict(
            key_derivation=interface.key_derivation,
            digest_method=interface.digest_method,
        ),
    )
    return serializer.dumps(data)


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


def test_generated_filler_accounts_cannot_authenticate(tmp_path):
    """Security fix: the ~100 generated filler users (target/db.py) exist
    for SQLi-discoverable dataset realism only -- they must never become a
    real, functional second login surface. Their credentials are also
    deterministically reproducible from committed source on a public repo,
    so if this route ever accepted them, anyone could log in as any of 100
    "employees" forever, regardless of hash cost."""
    from random import Random

    from target.db import _SEED, _generate_users

    client = _make_client(tmp_path)
    username, _password_hash, _role, plaintext = _generate_users(1, Random(_SEED))[0]

    response = client.post("/admin/login", data={"username": username, "password": plaintext})

    assert b"Invalid credentials" in response.data


def test_secret_key_is_not_hardcoded_across_app_instances(tmp_path):
    """H6 regression test: SECRET_KEY must be generated per app instance,
    not a fixed source-committed literal. Two separately created apps
    (simulating two process starts) must sign sessions differently.
    """
    app_a = _make_app(tmp_path)
    app_b = _make_app(tmp_path)
    assert app_a.config["SECRET_KEY"] != app_b.config["SECRET_KEY"]
    assert app_a.config["SECRET_KEY"] != _LEAKED_SECRET_KEY


def test_session_forged_with_leaked_secret_key_is_rejected(tmp_path):
    """H6 regression test: a session cookie forged with the old, now-public
    hardcoded SECRET_KEY value must not grant admin access. This is the
    exact zero-telemetry auth-bypass H6 describes -- forge a cookie,
    skip /admin/login entirely, hit an admin-only endpoint directly.
    """
    app = _make_app(tmp_path)
    client = app.test_client()
    forged = _forge_session_cookie(_LEAKED_SECRET_KEY, {"user_id": 1, "role": "admin"})
    client.set_cookie("session", forged)

    response = client.post("/admin/diagnostics", data={"host": "127.0.0.1"})

    assert response.status_code == 403
