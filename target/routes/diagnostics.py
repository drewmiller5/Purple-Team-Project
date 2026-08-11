# target/routes/diagnostics.py
import os
import signal
import subprocess

from flask import Blueprint, current_app, jsonify, request, session

from target.db import get_connection, is_blocked

diagnostics_bp = Blueprint("diagnostics", __name__, url_prefix="/admin")

PING_TIMEOUT_SECONDS = 5


def _descendant_pids(root_pid, proc_dir="/proc"):
    """Every PID whose real parent-child chain traces back to root_pid,
    walked via /proc/<pid>/stat rather than process-group membership.
    setsid() gives a process a new session/pgid but does NOT change its
    PPid (H67) -- os.killpg alone misses a self-daemonizing injected
    command for exactly that reason, so the timeout handler also needs
    this to reach anything that detached from the group but is still a
    real descendant. Returns [] on any host without /proc (e.g. macOS)
    or if /proc isn't readable -- degrades to the pgid-only kill.

    Does NOT close double-fork daemonization (a child that forks, exits
    its immediate parent, and gets reparented to PID 1 before this runs
    breaks the ppid chain back to root_pid) -- see H80.
    """
    try:
        entries = os.listdir(proc_dir)
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        return []

    children = {}
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc_dir, entry, "stat")) as f:
                stat = f.read()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        try:
            # Format per `man proc`: "pid (comm) state ppid ...". comm
            # can itself contain spaces/parens, so split on the last ')'.
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
        except (IndexError, ValueError):
            # A stat file read back truncated/malformed mid-exit (procfs
            # race) must not crash the whole timeout handler over one
            # unparseable pid -- skip it, same as a pid that vanished
            # before open() above.
            continue
        children.setdefault(ppid, []).append(int(entry))

    descendants = []
    frontier = [root_pid]
    while frontier:
        kids = children.get(frontier.pop(), [])
        descendants.extend(kids)
        frontier.extend(kids)
    return descendants


@diagnostics_bp.route("/diagnostics", methods=["POST"])
def carrier_connectivity_check():
    if session.get("role") != "admin":
        return jsonify({"error": "admin session required"}), 403

    conn = get_connection(current_app.config["DB_PATH"])
    blocked = is_blocked(conn, user_id=session.get("user_id"))
    conn.close()
    if blocked:
        return jsonify({"error": "account is locked"}), 403

    host = request.form.get("host", "")

    # Intentionally vulnerable: unsanitized shell interpolation via
    # shell=True. Seeded OS command injection for the Phase 1 target
    # range — the deliberate escalation path from authenticated app
    # access to host-level command execution. Never build subprocess
    # calls this way outside a deliberately vulnerable lab.
    #
    # start_new_session=True makes the shell (and anything it launches,
    # e.g. an injected `; sleep 600`) leader of its own process group,
    # so a timeout can kill the whole group instead of just the
    # immediate /bin/sh -- otherwise injected grandchildren get
    # reparented to PID 1 and keep running after we've already
    # responded (H58). We use Popen directly (not subprocess.run's
    # built-in timeout) because run() only ever kills the immediate
    # child on TimeoutExpired, with no hook to target the group instead.
    process = subprocess.Popen(
        f"ping -c 1 {host}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=PING_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        # H10: return a clean JSON error instead of an uncaught 500. The
        # kill itself must not be able to raise past this point -- the
        # process may have already exited/been reaped between the
        # timeout firing and here (ProcessLookupError), or the group id
        # may otherwise be gone (PermissionError under a hardened
        # container) -- either way the goal ("make sure nothing from
        # this request is left running") already holds, so swallow it.
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            # H67: os.killpg only reaches processes still in the
            # original process group. An injected command that calls
            # `setsid` detaches into a new session/pgid without
            # changing its PPid, escaping the group kill above while
            # remaining a real descendant -- walk and kill that tree
            # too, one pid at a time so one already-gone pid doesn't
            # block killing the rest.
            for descendant_pid in _descendant_pids(process.pid):
                try:
                    os.kill(descendant_pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        else:
            try:
                process.kill()
            except (ProcessLookupError, PermissionError):
                pass
        process.communicate()  # reap, avoid a zombie
        return jsonify({"error": "diagnostics command timed out"}), 504

    return jsonify({"output": stdout + stderr})
