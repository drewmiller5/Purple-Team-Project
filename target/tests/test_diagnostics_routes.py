# target/tests/test_diagnostics_routes.py
import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from target.app import create_app


def _make_client(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    return app.test_client()


def test_diagnostics_requires_admin_session(tmp_path):
    client = _make_client(tmp_path)
    response = client.post("/admin/diagnostics", data={"host": "127.0.0.1"})
    assert response.status_code == 403


def test_diagnostics_runs_ping_for_authenticated_admin(tmp_path):
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})
    response = client.post("/admin/diagnostics", data={"host": "127.0.0.1"})
    assert response.status_code == 200


@pytest.mark.skipif(
    os.name == "nt",
    reason="relies on POSIX shell `;` command-separator behavior via shell=True; "
    "doesn't hold under Windows cmd.exe. Passes in the lab's real Linux/container "
    "environment.",
)
def test_seeded_command_injection_in_diagnostics(tmp_path):
    """Seeded vulnerability regression test: /admin/diagnostics shells out
    to `ping` with unsanitized input via shell=True, allowing arbitrary
    command execution once authenticated as admin. This is red_agent's
    escalation path from app-level access to host-level access. If this
    fails, the injection was sanitized and this vuln needs re-seeding.
    """
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})
    response = client.post(
        "/admin/diagnostics",
        data={"host": "127.0.0.1; echo PWNED_MARKER_7f3a"},
    )
    assert b"PWNED_MARKER_7f3a" in response.data


def _mock_timed_out_process(pid=12345):
    """A Popen mock whose first .communicate() call times out, matching
    the real subprocess.run(timeout=...)-then-reap sequence our route
    code follows on a timeout path."""
    mock_process = MagicMock()
    mock_process.pid = pid
    mock_process.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd="ping -c 1 host", timeout=5),
        ("", ""),
    ]
    return mock_process


def test_diagnostics_timeout_returns_clean_json_error_not_500(tmp_path):
    """H10: subprocess.TimeoutExpired must not become an uncaught 500 --
    the route should catch it and return the same jsonify({"error": ...})
    shape every other route in this file uses."""
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    mock_process = _mock_timed_out_process()
    with patch("target.routes.diagnostics.subprocess.Popen", return_value=mock_process):
        response = client.post(
            "/admin/diagnostics",
            data={"host": "127.0.0.1; sleep 600"},
        )

    assert response.status_code != 500
    assert response.status_code == 504
    body = response.get_json()
    assert body is not None
    assert "error" in body


def test_diagnostics_timeout_kills_whole_process_group_not_just_child(tmp_path):
    """H58: shell=True means timeout must kill the process GROUP (via
    os.killpg on the group id), not just process.kill() on the immediate
    /bin/sh child -- otherwise an injected grandchild (e.g. `sleep 600`)
    is reparented to PID 1 and survives as an orphan after we've already
    responded. Mocked per this project's known real-time-sleep-in-tests
    gotcha (brain/Gotchas.md) -- no real process is spawned here."""
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    # os.getpgid/os.killpg/signal.SIGKILL are POSIX-only and don't exist
    # on this dev machine's os/signal modules at all (target runs on
    # Linux in Docker per docker-compose.yml) -- create=True lets the
    # mock stand in for an attribute that isn't there to begin with.
    sentinel_sigkill = object()
    mock_process = _mock_timed_out_process(pid=12345)
    with (
        patch("target.routes.diagnostics.subprocess.Popen", return_value=mock_process),
        patch("target.routes.diagnostics.os.getpgid", return_value=999, create=True) as mock_getpgid,
        patch("target.routes.diagnostics.os.killpg", create=True) as mock_killpg,
        patch("target.routes.diagnostics.os.name", "posix"),
        patch("target.routes.diagnostics.signal.SIGKILL", sentinel_sigkill, create=True),
    ):
        response = client.post(
            "/admin/diagnostics",
            data={"host": "127.0.0.1; sleep 600"},
        )

    assert response.status_code == 504
    mock_getpgid.assert_called_once_with(12345)
    mock_killpg.assert_called_once_with(999, sentinel_sigkill)
    # The group was killed, not just the immediate child process.
    mock_process.kill.assert_not_called()
