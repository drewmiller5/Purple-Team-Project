import threading
import time

import pytest

from blue_agent.http_tool import HttpTool
from target.app import create_app


@pytest.fixture
def live_target(tmp_path, monkeypatch):
    monkeypatch.setenv("INTERNAL_ACTION_TOKEN", "test-internal-action-token")
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    server = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=15001, use_reloader=False),
        daemon=True,
    )
    server.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:15001"


def test_post_request_hits_block_ip_endpoint(live_target):
    tool = HttpTool(live_target)
    result = tool.request("POST", "/internal/block-ip", data={"source_ip": "10.0.0.5"})
    assert result["status_code"] in (200, 400)  # 400 in this pytest env if iptables isn't on PATH


def test_connection_error_returns_error_dict():
    tool = HttpTool("http://127.0.0.1:1", timeout=1.0)
    result = tool.request("GET", "/")
    assert "error" in result
