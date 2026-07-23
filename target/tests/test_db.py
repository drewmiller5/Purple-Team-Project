# target/tests/test_db.py
from werkzeug.security import generate_password_hash

from target.db import get_connection, init_db, seed_db


def test_init_db_creates_tables(tmp_path):
    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    conn = get_connection(str(db_path))
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    conn.close()
    assert {"users", "shipments", "documents"}.issubset(tables)


def test_seed_db_creates_expected_rows(tmp_path):
    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    seed_db(str(db_path), generate_password_hash)
    conn = get_connection(str(db_path))
    user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    shipment_count = conn.execute("SELECT COUNT(*) AS c FROM shipments").fetchone()["c"]
    doc_count = conn.execute("SELECT COUNT(*) AS c FROM documents").fetchone()["c"]
    conn.close()
    assert user_count == 2
    assert shipment_count == 3
    assert doc_count == 3


def test_seed_db_is_idempotent(tmp_path):
    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    seed_db(str(db_path), generate_password_hash)
    seed_db(str(db_path), generate_password_hash)
    conn = get_connection(str(db_path))
    user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    conn.close()
    assert user_count == 2
