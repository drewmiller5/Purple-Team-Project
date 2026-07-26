# target/routes/admin.py
from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template_string,
    request,
    session,
)
from werkzeug.security import check_password_hash

from target.db import get_connection, is_blocked

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

LOGIN_FORM = """
<h1>Meridian Logistics — Staff Portal</h1>
<form method="post">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Log in</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_FORM, error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_connection(current_app.config["DB_PATH"])
    if is_blocked(conn, username=username):
        conn.close()
        return render_template_string(LOGIN_FORM, error="Account blocked")

    row = conn.execute(
        "SELECT id, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    # Intentionally vulnerable: no rate limiting or lockout on failed
    # attempts. Combined with a weak seeded password, this makes the
    # admin panel brute-forceable — the seeded vuln for Phase 1.
    if row is None or not check_password_hash(row["password_hash"], password):
        return render_template_string(LOGIN_FORM, error="Invalid credentials")

    session["user_id"] = row["id"]
    session["role"] = row["role"]
    return f"<h1>Welcome, {username}</h1><p>Role: {row['role']}</p>"


@admin_bp.route("/whoami")
def whoami():
    return jsonify({"user_id": session.get("user_id"), "role": session.get("role")})
