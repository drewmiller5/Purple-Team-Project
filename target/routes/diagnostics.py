# target/routes/diagnostics.py
import subprocess

from flask import Blueprint, current_app, jsonify, request, session

from target.db import get_connection, is_blocked

diagnostics_bp = Blueprint("diagnostics", __name__, url_prefix="/admin")


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
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return jsonify({"output": result.stdout + result.stderr})
