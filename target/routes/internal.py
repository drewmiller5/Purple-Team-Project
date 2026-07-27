# target/routes/internal.py
from flask import Blueprint, current_app, jsonify, request

from target.db import get_connection, is_blocked

internal_bp = Blueprint("internal", __name__, url_prefix="/internal")


@internal_bp.route("/lock-account", methods=["POST"])
def lock_account():
    username = request.form.get("username", "")
    conn = get_connection(current_app.config["DB_PATH"])
    # Final-review fix (finding #5): bruteforce-guard.sh re-invokes this
    # endpoint on every subsequent matching event once the window count is
    # >=5, so a real brute-force burst dispatches multiple lock-account
    # POSTs for the same username -- live-verified to produce duplicate
    # ('admin', None) rows before this check existed. Skip the insert (but
    # still return 200 -- the caller's desired end state, "this account is
    # blocked", already holds) if already blocked.
    if not is_blocked(conn, username=username):
        conn.execute("INSERT INTO blocked_users (username) VALUES (?)", (username,))
        conn.commit()
    conn.close()
    return jsonify({"locked": username}), 200


@internal_bp.route("/kill-session", methods=["POST"])
def kill_session():
    user_id = request.form.get("user_id", type=int)
    if user_id is None:
        return jsonify({"error": "user_id is required and must be numeric"}), 400
    conn = get_connection(current_app.config["DB_PATH"])
    conn.execute("INSERT INTO blocked_users (user_id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"killed_session_for": user_id}), 200
