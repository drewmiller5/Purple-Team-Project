# target/tests/test_db.py
import random

from werkzeug.security import generate_password_hash

from target.db import (
    SHIPMENT_COUNT,
    USER_COUNT,
    _classify_password,
    _generate_shipments,
    _generate_users,
    get_connection,
    init_db,
    seed_db,
)


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

    # Assert the original pinned users -- admin MUST stay user id 1 and
    # jsmith id 2, exact creds unchanged: test_internal_routes.py hardcodes
    # user_id "1" for admin, and multiple test files log in as
    # admin/admin123 directly.
    users = conn.execute("SELECT username, password_hash, role FROM users ORDER BY id").fetchall()
    assert len(users) == 2 + USER_COUNT
    assert users[0]["username"] == "admin"
    assert users[0]["role"] == "admin"
    assert users[0]["password_hash"] != ""
    assert users[0]["password_hash"] != "admin123"  # hash should differ from plaintext
    assert users[1]["username"] == "jsmith"
    assert users[1]["role"] == "staff"
    assert users[1]["password_hash"] != ""
    assert users[1]["password_hash"] != "Sunshine2024!"  # hash should differ from plaintext
    # Generated usernames are unique (no accidental collisions/duplicates).
    all_usernames = [u["username"] for u in users]
    assert len(all_usernames) == len(set(all_usernames))

    # Assert the original pinned shipments -- test_public_routes.py's
    # SQLi regression test and Charlotte-search test depend on these exact
    # tracking numbers/cities/statuses.
    shipments = conn.execute(
        "SELECT tracking_number, origin, destination, status FROM shipments ORDER BY id"
    ).fetchall()
    assert len(shipments) == 3 + SHIPMENT_COUNT
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
    all_tracking_numbers = [s["tracking_number"] for s in shipments]
    assert len(all_tracking_numbers) == len(set(all_tracking_numbers))

    # Assert documents (unchanged by this pass -- data-volume scope was
    # users/shipments only).
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


def test_generate_users_have_unique_usernames_and_mixed_password_strength(tmp_path):
    users = _generate_users(USER_COUNT, random.Random(42))

    assert len(users) == USER_COUNT
    usernames = [u[0] for u in users]
    assert len(usernames) == len(set(usernames))

    # Realistic corporate hygiene: some weak, some strong, not uniform.
    plaintexts = [u[3] for u in users]
    strengths = {_classify_password(p) for p in plaintexts}
    assert "weak" in strengths
    assert "strong" in strengths

    roles = {u[2] for u in users}
    assert roles  # at least one role assigned
    assert "admin" not in roles  # generated users are never a second admin


def test_generated_users_are_never_stored_as_plaintext():
    users = _generate_users(20, random.Random(3))
    for username, password_hash, _role, plaintext in users:
        assert password_hash != plaintext
        assert plaintext not in password_hash
        assert password_hash.startswith("pbkdf2:")


def test_seed_db_never_stores_a_plaintext_password(tmp_path):
    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    seed_db(str(db_path), generate_password_hash)
    conn = get_connection(str(db_path))
    rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    conn.close()

    known_plaintexts = {"admin123", "Sunshine2024!"}
    for row in rows:
        assert row["password_hash"] not in known_plaintexts
        assert not any(pw in row["password_hash"] for pw in known_plaintexts)
        # every stored hash carries a method prefix -- never a bare/plain string
        assert row["password_hash"].split(":")[0] in {"scrypt", "pbkdf2"}


def test_generate_shipments_are_unique_and_global(tmp_path):
    shipments = _generate_shipments(SHIPMENT_COUNT, start_number=10026, rng=random.Random(7))

    assert len(shipments) == SHIPMENT_COUNT
    tracking_numbers = [s[0] for s in shipments]
    assert len(tracking_numbers) == len(set(tracking_numbers))
    assert all(n.startswith("MER1") for n in tracking_numbers)

    countries_mentioned = {s[1] for s in shipments} | {s[2] for s in shipments}
    # Global routes: not every origin/destination is a US city (US cities
    # in this dataset are always "City, ST" -- two-letter state code).
    us_only = all(len(loc.split(", ")[-1]) == 2 for loc in countries_mentioned)
    assert not us_only

    valid_statuses = {"In Transit", "Delivered", "Delayed", "Customs Hold"}
    assert {s[3] for s in shipments} <= valid_statuses


def test_seed_db_is_idempotent(tmp_path):
    db_path = tmp_path / "test.db"
    init_db(str(db_path))
    seed_db(str(db_path), generate_password_hash)
    seed_db(str(db_path), generate_password_hash)
    conn = get_connection(str(db_path))
    user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    conn.close()
    assert user_count == 2 + USER_COUNT
