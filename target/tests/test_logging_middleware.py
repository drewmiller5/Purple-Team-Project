import json

from flask import Flask, session

from target.logging_middleware import _redact_params, register_logging


def _make_app(log_path):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-key"
    register_logging(app, log_path=str(log_path))

    @app.route("/ping")
    def ping():
        return "pong"

    @app.route("/login", methods=["POST"])
    def login():
        return "ok"

    @app.route("/crash")
    def crash():
        raise RuntimeError("boom")

    @app.route("/set-session/<int:user_id>")
    def set_session(user_id):
        session["user_id"] = user_id
        return "ok"

    return app


def test_request_is_logged(tmp_path):
    log_path = tmp_path / "requests.jsonl"
    client = _make_app(log_path).test_client()

    response = client.get("/ping?foo=bar")

    assert response.status_code == 200
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["path"] == "/ping"
    assert entry["method"] == "GET"
    assert entry["query_params"] == {"foo": "bar"}
    assert entry["status_code"] == 200
    assert "duration_ms" in entry
    # srcip duplicates remote_addr under Wazuh's reserved field name so the
    # generic JSON decoder auto-populates it (Task 7 fix-round -- lets
    # firewall-drop Active Response read a real source IP).
    assert entry["srcip"] == entry["remote_addr"]
    # No session on this request -- user_id must be present but null, not
    # simply absent.
    assert entry["user_id"] is None


def test_password_param_is_redacted(tmp_path):
    log_path = tmp_path / "requests.jsonl"
    client = _make_app(log_path).test_client()

    client.post("/login", data={"username": "admin", "password": "admin123"})

    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["form_params"]["password"] == "[REDACTED]"
    assert entry["form_params"]["username"] == "admin"


def test_confirm_password_and_token_shaped_keys_are_redacted(tmp_path):
    log_path = tmp_path / "requests.jsonl"
    client = _make_app(log_path).test_client()

    client.post(
        "/login",
        data={
            "username": "admin",
            "confirm_password": "admin123",
            "access_token": "abc123",
        },
    )

    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["form_params"]["confirm_password"] == "[REDACTED]"
    assert entry["form_params"]["access_token"] == "[REDACTED]"
    assert entry["form_params"]["username"] == "admin"


def test_redact_params_redacts_nested_dict_values():
    params = {
        "username": "admin",
        "credentials": {"password": "admin123", "note": "keep"},
    }

    redacted = _redact_params(params)

    assert redacted["username"] == "admin"
    assert redacted["credentials"]["password"] == "[REDACTED]"
    assert redacted["credentials"]["note"] == "keep"


def test_redact_params_redacts_a_sensitive_named_key_even_when_its_value_is_a_dict():
    params = {
        "username": "admin",
        "password_data": {"old": "hunter2", "new": "hunter3"},
    }

    redacted = _redact_params(params)

    assert redacted["username"] == "admin"
    assert redacted["password_data"] == "[REDACTED]"


def test_redact_params_redacts_secret_shaped_keys():
    params = {"username": "admin", "client_secret": "abc123"}

    redacted = _redact_params(params)

    assert redacted["client_secret"] == "[REDACTED]"


def test_redact_params_redacts_dicts_nested_inside_a_list():
    params = {
        "username": "admin",
        "credentials": [{"password": "hunter2"}, {"password": "hunter3"}],
    }

    redacted = _redact_params(params)

    assert redacted["credentials"][0]["password"] == "[REDACTED]"
    assert redacted["credentials"][1]["password"] == "[REDACTED]"


def test_user_id_logged_from_active_session(tmp_path):
    log_path = tmp_path / "requests.jsonl"
    client = _make_app(log_path).test_client()

    # Setting session["user_id"] mutates the in-memory session for the rest
    # of *this* request too (teardown_request runs after the view), so the
    # /set-session request's own log line already reflects it.
    client.get("/set-session/42")
    # The test client's cookie jar carries the session cookie forward, so a
    # later request on the same client also logs the same user_id -- this
    # is the realistic "already logged in" case Active Response cares about.
    client.get("/ping")

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first_entry = json.loads(lines[0])
    second_entry = json.loads(lines[1])
    assert first_entry["user_id"] == 42
    assert second_entry["user_id"] == 42


def test_unhandled_exception_is_still_logged(tmp_path):
    log_path = tmp_path / "requests.jsonl"
    client = _make_app(log_path).test_client()

    response = client.get("/crash")

    # Flask's default (non-debug, non-testing) exception handling converts
    # the unhandled exception into a 500 response for the caller...
    assert response.status_code == 500

    # ...and the logging hook (teardown_request) must still have fired,
    # even though after_request is skipped on the exception path.
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["path"] == "/crash"
    assert entry["method"] == "GET"
    assert entry["status_code"] == 500
    assert "duration_ms" in entry
