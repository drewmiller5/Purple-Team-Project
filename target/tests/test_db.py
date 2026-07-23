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

    # Assert users
    users = conn.execute("SELECT username, password_hash, role FROM users ORDER BY id").fetchall()
    assert len(users) == 2
    assert users[0]["username"] == "admin"
    assert users[0]["role"] == "admin"
    assert users[0]["password_hash"] != ""
    assert users[0]["password_hash"] != "admin123"  # hash should differ from plaintext
    assert users[1]["username"] == "jsmith"
    assert users[1]["role"] == "staff"
    assert users[1]["password_hash"] != ""
    assert users[1]["password_hash"] != "Sunshine2024!"  # hash should differ from plaintext

    # Assert shipments
    shipments = conn.execute(
        "SELECT tracking_number, origin, destination, status FROM shipments ORDER BY id"
    ).fetchall()
    assert len(shipments) == 3
    assert shipments[0]["tracking_number"] == "MER10023"
    assert shipments[0]["origin"] == "Baltimore, MD"
    assert shipments[0]["destination"] == "Charlotte, NC"
    assert shipments[0]["status"] == "In Transit"
    assert shipments[1]["tracking_number"] == "MER10024"
    assert shipments[1]["origin"] == "Norfolk, VA"
    assert shipments[1]["destination"] == "Atlanta, GA"
    assert shipments[1]["status"] == "Delivered"
    assert shipments[2]["tracking_number"] == "MER10025"
    assert shipments[2]["origin"] == "Charlotte, NC"
    assert shipments[2]["destination"] == "Miami, FL"
    assert shipments[2]["status"] == "Delayed"

    # Assert documents
    documents = conn.execute(
        "SELECT owner_id, title, confidential FROM documents ORDER BY id"
    ).fetchall()
    assert len(documents) == 3
    assert documents[0]["owner_id"] == 1
    assert documents[0]["title"] == "Q3 Vendor Contract Rates"
    assert documents[0]["confidential"] == 1
    assert documents[1]["owner_id"] == 2
    assert documents[1]["title"] == "Warehouse Safety Bulletin"
    assert documents[1]["confidential"] == 0
    assert documents[2]["owner_id"] == 1
    assert documents[2]["title"] == "Employee Directory Export"
    assert documents[2]["confidential"] == 1

    conn.close()


def test_seed_db_is_idempotent(tmp_path):
    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    seed_db(str(db_path), generate_password_hash)
    seed_db(str(db_path), generate_password_hash)
    conn = get_connection(str(db_path))
    user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    conn.close()
    assert user_count == 2
