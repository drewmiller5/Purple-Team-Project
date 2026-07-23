# target/routes/documents.py
from flask import Blueprint, current_app, jsonify

from target.db import get_connection

documents_bp = Blueprint("documents", __name__, url_prefix="/documents")


@documents_bp.route("/<int:doc_id>")
def get_document(doc_id):
    conn = get_connection(current_app.config["DB_PATH"])
    row = conn.execute(
        "SELECT id, owner_id, title, content, confidential FROM documents WHERE id = ?",
        (doc_id,),
    ).fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "not found"}), 404

    # Intentionally vulnerable: no ownership/auth check. Any visitor can
    # read any document, including confidential=1 rows, by guessing
    # sequential IDs. Seeded IDOR vuln for Phase 1.
    return jsonify(
        {
            "id": row["id"],
            "title": row["title"],
            "content": row["content"],
            "confidential": bool(row["confidential"]),
        }
    )
