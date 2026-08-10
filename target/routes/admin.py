# target/routes/admin.py
from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template,
    request,
    session,
)
from werkzeug.security import check_password_hash

from target.db import get_connection, is_blocked

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("admin_login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_connection(current_app.config["DB_PATH"])
    if is_blocked(conn, username=username):
        conn.close()
        return render_template("admin_login.html", error="Account blocked")

    # synthetic = 0: dataset-volume filler users (target/db.py's ~100
    # generated accounts) must never authenticate here -- they exist only
    # for SQLi-discoverable realism in /search results.
    row = conn.execute(
        "SELECT id, password_hash, role FROM users WHERE username = ? AND synthetic = 0",
        (username,),
    ).fetchone()
    conn.close()

    # Intentionally vulnerable: no rate limiting or lockout on failed
    # attempts. Combined with a weak seeded password, this makes the
    # admin panel brute-forceable — the seeded vuln for Phase 1.
    if row is None or not check_password_hash(row["password_hash"], password):
        return render_template("admin_login.html", error="Invalid credentials")

    session["user_id"] = row["id"]
    session["role"] = row["role"]
    return render_template("admin_welcome.html", username=username, role=row["role"])


@admin_bp.route("/whoami")
def whoami():
    return jsonify({"user_id": session.get("user_id"), "role": session.get("role")})
