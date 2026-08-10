# target/routes/public.py
from flask import Blueprint, current_app, render_template, request

from target.db import get_connection

public_bp = Blueprint("public", __name__)


@public_bp.route("/")
def home():
    return render_template("home.html")


@public_bp.route("/search")
def search():
    q = request.args.get("q", "")
    if not q:
        return render_template("search.html", q=q, results=[])

    conn = get_connection(current_app.config["DB_PATH"])
    # Intentionally vulnerable: seeded SQLi for the Phase 1 target range.
    # Never build queries this way outside a deliberately vulnerable lab.
    query = (
        "SELECT tracking_number, origin, destination, status "
        f"FROM shipments WHERE tracking_number LIKE '%{q}%' "
        f"OR origin LIKE '%{q}%' OR destination LIKE '%{q}%'"
    )
    cursor = conn.execute(query)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return render_template("search.html", q=q, results=results)
