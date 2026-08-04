# target/routes/diagnostics.py
import os
import signal
import subprocess

from flask import Blueprint, current_app, jsonify, request, session

from target.db import get_connection, is_blocked

diagnostics_bp = Blueprint("diagnostics", __name__, url_prefix="/admin")

PING_TIMEOUT_SECONDS = 5


@diagnostics_bp.route("/diagnostics", methods=["POST"])
def carrier_connectivity_check():
    if session.get("role") != "admin":
        return jsonify({"error": "admin session required"}), 403

    conn = get_connection(current_app.config["DB_PATH"])
    blocked = is_blocked(conn, user_id=session.get("user_id"))
    conn.close()
    if blocked:
        return jsonify({"error": "session killed"}), 403

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
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            else:
                process.kill()
        except (ProcessLookupError, PermissionError):
            pass
        process.communicate()  # reap, avoid a zombie
        return jsonify({"error": "diagnostics command timed out"}), 504

    return jsonify({"output": stdout + stderr})
