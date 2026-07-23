import json

from flask import Flask

from target.logging_middleware import register_logging


def _make_app(log_path):
    app = Flask(__name__)
    register_logging(app, log_path=str(log_path))

    @app.route("/ping")
    def ping():
        return "pong"

    @app.route("/login", methods=["POST"])
    def login():
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


def test_password_param_is_redacted(tmp_path):
    log_path = tmp_path / "requests.jsonl"
    client = _make_app(log_path).test_client()

    client.post("/login", data={"username": "admin", "password": "admin123"})

    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["form_params"]["password"] == "[REDACTED]"
    assert entry["form_params"]["username"] == "admin"
