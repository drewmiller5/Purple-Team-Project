# target/routes/public.py
from flask import Blueprint, current_app, render_template_string, request

from target.db import get_connection

public_bp = Blueprint("public", __name__)

SEARCH_TEMPLATE = """
<h1>Meridian Logistics — Shipment Lookup</h1>
<form method="get">
  <input type="text" name="q" value="{{ q }}" placeholder="Tracking # or city">
  <button type="submit">Search</button>
</form>
<ul>
{% for row in results %}
  <li>{{ row }}</li>
{% endfor %}
</ul>
"""


@public_bp.route("/")
def home():
    return (
        "<h1>Meridian Logistics</h1>"
        "<p>Freight you can track. <a href='/search'>Search shipments</a></p>"
    )


@public_bp.route("/search")
def search():
    q = request.args.get("q", "")
    if not q:
        return render_template_string(SEARCH_TEMPLATE, q=q, results=[])

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
    return render_template_string(SEARCH_TEMPLATE, q=q, results=results)
