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
    shape every other route in this file uses. os.getpgid/os.killpg are
    mocked (not left to run for real against a fabricated pid) so this
    test's outcome doesn't depend on the host OS's os.name -- on a real
    POSIX host an unmocked os.getpgid(12345) would raise
    ProcessLookupError for a pid that doesn't exist, which is exactly the
    unguarded-cleanup gap this test (plus the dedicated test below) now
    covers."""
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    mock_process = _mock_timed_out_process()
    with (
        patch("target.routes.diagnostics.subprocess.Popen", return_value=mock_process),
        patch("target.routes.diagnostics.os.getpgid", return_value=999, create=True),
        patch("target.routes.diagnostics.os.killpg", create=True),
        patch("target.routes.diagnostics.os.name", "posix"),
        patch("target.routes.diagnostics.signal.SIGKILL", object(), create=True),
    ):
        response = client.post(
            "/admin/diagnostics",
            data={"host": "127.0.0.1; sleep 600"},
        )

    assert response.status_code != 500
    assert response.status_code == 504
    body = response.get_json()
    assert body is not None
    assert "error" in body


def test_diagnostics_timeout_cleanup_survives_process_already_gone(tmp_path):
    """Reviewer-flagged gap: os.getpgid/os.killpg were not guarded against
    their own failure. If the timed-out process already exited/was
    reaped between the timeout firing and the cleanup running,
    os.getpgid raises ProcessLookupError -- unguarded, that exception
    propagates past the intended jsonify(...), 504 response and becomes
    an uncaught 500, the exact outcome H10 exists to prevent."""
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    mock_process = _mock_timed_out_process()
    with (
        patch("target.routes.diagnostics.subprocess.Popen", return_value=mock_process),
        patch("target.routes.diagnostics.os.getpgid", side_effect=ProcessLookupError, create=True),
        patch("target.routes.diagnostics.os.killpg", create=True),
        patch("target.routes.diagnostics.os.name", "posix"),
    ):
        response = client.post(
            "/admin/diagnostics",
            data={"host": "127.0.0.1; sleep 600"},
        )

    assert response.status_code == 504
    body = response.get_json()
    assert body is not None
    assert "error" in body


def _write_fake_stat(proc_dir, pid, ppid, comm="proc"):
    """Write a real /proc/<pid>/stat-shaped file (pid, (comm), state,
    ppid, ... per `man proc`) so _descendant_pids can be tested against
    an actual parent-child tree on disk, not a mocked-open() shim."""
    pid_dir = proc_dir / str(pid)
    pid_dir.mkdir(parents=True, exist_ok=True)
    (pid_dir / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 0\n")


def test_descendant_pids_finds_setsid_escaped_grandchildren(tmp_path):
    """H67: setsid() gives a process a new session/process-group id but
    does NOT change its PPid -- so a self-daemonizing injected command
    (`setsid sleep 600 &`) escapes os.killpg's process-GROUP kill while
    remaining fully visible via the real parent-child tree in /proc.
    Walking that tree (not process-group membership) must still find it,
    and any further descendants spawned underneath it too."""
    from target.routes.diagnostics import _descendant_pids

    proc_dir = tmp_path / "proc"
    _write_fake_stat(proc_dir, pid=100, ppid=1, comm="sh")
    _write_fake_stat(proc_dir, pid=101, ppid=100, comm="ping")
    _write_fake_stat(proc_dir, pid=102, ppid=100, comm="setsid")
    _write_fake_stat(proc_dir, pid=103, ppid=102, comm="sleep")
    _write_fake_stat(proc_dir, pid=999, ppid=1, comm="unrelated")

    found = _descendant_pids(100, proc_dir=str(proc_dir))

    assert set(found) == {101, 102, 103}


def test_descendant_pids_missing_proc_dir_returns_empty(tmp_path):
    """Non-Linux POSIX hosts (e.g. macOS) have no /proc at all -- must
    degrade to an empty list, not raise, so the pgid kill still runs."""
    from target.routes.diagnostics import _descendant_pids

    assert _descendant_pids(100, proc_dir=str(tmp_path / "does-not-exist")) == []


def test_descendant_pids_skips_malformed_stat_file(tmp_path):
    """Reviewer-flagged gap: a stat file read back truncated/malformed
    mid-exit (procfs race) must be skipped, not raise ValueError/
    IndexError out of _descendant_pids and crash the whole timeout
    handler over one unparseable pid."""
    from target.routes.diagnostics import _descendant_pids

    proc_dir = tmp_path / "proc"
    _write_fake_stat(proc_dir, pid=100, ppid=1, comm="sh")
    _write_fake_stat(proc_dir, pid=101, ppid=100, comm="ping")
    malformed_dir = proc_dir / "102"
    malformed_dir.mkdir(parents=True)
    (malformed_dir / "stat").write_text("truncated garbage, no closing paren")

    found = _descendant_pids(100, proc_dir=str(proc_dir))

    assert found == [101]


def test_diagnostics_timeout_kills_setsid_escaped_descendants(tmp_path):
    """H67: the process-group kill alone misses a setsid-escaped
    descendant. The route must also walk and individually SIGKILL the
    real descendant tree so a detached grandchild can't outlive the
    response."""
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    sentinel_sigkill = object()
    mock_process = _mock_timed_out_process(pid=12345)
    with (
        patch("target.routes.diagnostics.subprocess.Popen", return_value=mock_process),
        patch("target.routes.diagnostics.os.getpgid", return_value=999, create=True),
        patch("target.routes.diagnostics.os.killpg", create=True),
        patch("target.routes.diagnostics.os.kill", create=True) as mock_kill,
        patch(
            "target.routes.diagnostics._descendant_pids",
            return_value=[54321, 54322],
        ) as mock_descendants,
        patch("target.routes.diagnostics.os.name", "posix"),
        patch("target.routes.diagnostics.signal.SIGKILL", sentinel_sigkill, create=True),
    ):
        response = client.post(
            "/admin/diagnostics",
            data={"host": "127.0.0.1; setsid sleep 600 &"},
        )

    assert response.status_code == 504
    mock_descendants.assert_called_once_with(12345)
    mock_kill.assert_any_call(54321, sentinel_sigkill)
    mock_kill.assert_any_call(54322, sentinel_sigkill)


def test_diagnostics_timeout_descendant_kill_survives_already_gone_pid(tmp_path):
    """A descendant found via /proc can still exit/get reaped between the
    listing and the kill -- os.kill's ProcessLookupError/PermissionError
    per-pid must not propagate past the intended 504 response."""
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    mock_process = _mock_timed_out_process(pid=12345)
    with (
        patch("target.routes.diagnostics.subprocess.Popen", return_value=mock_process),
        patch("target.routes.diagnostics.os.getpgid", return_value=999, create=True),
        patch("target.routes.diagnostics.os.killpg", create=True),
        patch(
            "target.routes.diagnostics.os.kill",
            side_effect=ProcessLookupError,
            create=True,
        ),
        patch(
            "target.routes.diagnostics._descendant_pids",
            return_value=[54321],
        ),
        patch("target.routes.diagnostics.os.name", "posix"),
        patch("target.routes.diagnostics.signal.SIGKILL", object(), create=True),
    ):
        response = client.post(
            "/admin/diagnostics",
            data={"host": "127.0.0.1; setsid sleep 600 &"},
        )

    assert response.status_code == 504
    body = response.get_json()
    assert body is not None
    assert "error" in body


def test_diagnostics_timeout_non_posix_kill_survives_process_already_gone(tmp_path):
    """Reviewer-flagged regression: the non-POSIX (os.name != 'posix')
    branch calls process.kill() directly. If the process already
    exited/was reaped between the timeout firing and the cleanup
    running, that raises ProcessLookupError/PermissionError -- must not
    propagate past the intended 504 response, same guarantee the POSIX
    branch already has."""
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    mock_process = _mock_timed_out_process(pid=12345)
    mock_process.kill.side_effect = ProcessLookupError
    with (
        patch("target.routes.diagnostics.subprocess.Popen", return_value=mock_process),
        patch("target.routes.diagnostics.os.name", "nt"),
    ):
        response = client.post(
            "/admin/diagnostics",
            data={"host": "127.0.0.1; sleep 600"},
        )

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
