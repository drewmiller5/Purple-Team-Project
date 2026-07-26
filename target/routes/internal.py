# target/routes/internal.py
from flask import Blueprint, current_app, jsonify, request

from target.db import get_connection

internal_bp = Blueprint("internal", __name__, url_prefix="/internal")


@internal_bp.route("/lock-account", methods=["POST"])
def lock_account():
    username = request.form.get("username", "")
    conn = get_connection(current_app.config["DB_PATH"])
    conn.execute("INSERT INTO blocked_users (username) VALUES (?)", (username,))
    conn.commit()
    conn.close()
    return jsonify({"locked": username}), 200


@internal_bp.route("/kill-session", methods=["POST"])
def kill_session():
    user_id = request.form.get("user_id", type=int)
    conn = get_connection(current_app.config["DB_PATH"])
    conn.execute("INSERT INTO blocked_users (user_id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"killed_session_for": user_id}), 200
