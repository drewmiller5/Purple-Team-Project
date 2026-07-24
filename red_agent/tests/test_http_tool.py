# red_agent/tests/test_http_tool.py
import threading
import time

import pytest

from red_agent.http_tool import HttpTool
from target.app import create_app


@pytest.fixture
def live_target(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    server = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=15000, use_reloader=False),
        daemon=True,
    )
    server.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:15000"


def test_get_request_returns_status_and_body(live_target):
    tool = HttpTool(live_target)
    result = tool.request("GET", "/")
    assert result["status_code"] == 200
    assert "Meridian Logistics" in result["body"]


def test_post_request_sends_form_data(live_target):
    tool = HttpTool(live_target)
    result = tool.request(
        "POST", "/admin/login", data={"username": "admin", "password": "admin123"}
    )
    assert result["status_code"] == 200
    assert "Welcome, admin" in result["body"]


def test_session_persists_cookies_across_requests(live_target):
    tool = HttpTool(live_target)
    tool.request("POST", "/admin/login", data={"username": "admin", "password": "admin123"})
    result = tool.request("POST", "/admin/diagnostics", data={"host": "127.0.0.1"})
    # Proves the admin session cookie from the first request carried over
    # to the second — /admin/diagnostics would 403 without it.
    assert result["status_code"] == 200


def test_body_is_truncated_and_flagged_when_long(live_target):
    tool = HttpTool(live_target)
    result = tool.request("GET", "/search", params={"q": "a" * 5000})
    assert len(result["body"]) <= 2000
    assert result["body_truncated"] is True


def test_connection_error_returns_error_dict():
    tool = HttpTool("http://127.0.0.1:1", timeout=1.0)
    result = tool.request("GET", "/")
    assert "error" in result
