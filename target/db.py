# target/db.py
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS shipments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tracking_number TEXT NOT NULL,
    origin TEXT NOT NULL,
    destination TEXT NOT NULL,
    status TEXT NOT NULL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    confidential INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (owner_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS blocked_users (
    username TEXT, user_id INTEGER
);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    conn = get_connection(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def is_blocked(conn, username: str = None, user_id: int = None) -> bool:
    if username is not None:
        row = conn.execute(
            "SELECT 1 FROM blocked_users WHERE username = ?", (username,)
        ).fetchone()
        return row is not None
    if user_id is not None:
        row = conn.execute(
            "SELECT 1 FROM blocked_users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row is not None
    return False


def seed_db(db_path: str, password_hash_fn) -> None:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] > 0:
        conn.close()
        return

    cur.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("admin", password_hash_fn("admin123"), "admin"),
    )
    cur.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("jsmith", password_hash_fn("Sunshine2024!"), "staff"),
    )

    cur.executemany(
        "INSERT INTO shipments (tracking_number, origin, destination, status, notes) "
        "VALUES (?, ?, ?, ?, ?)",
        [
            ("MER10023", "Baltimore, MD", "Charlotte, NC", "In Transit", "Standard freight"),
            ("MER10024", "Norfolk, VA", "Atlanta, GA", "Delivered", "Signed by receiving dock"),
            ("MER10025", "Charlotte, NC", "Miami, FL", "Delayed", "Weather delay, ETA updated"),
        ],
    )

    cur.execute(
        "INSERT INTO documents (owner_id, title, content, confidential) VALUES (?, ?, ?, ?)",
        (1, "Q3 Vendor Contract Rates",
         "Vendor rate sheet: negotiated freight rates for Q3, internal use only.", 1),
    )
    cur.execute(
        "INSERT INTO documents (owner_id, title, content, confidential) VALUES (?, ?, ?, ?)",
        (2, "Warehouse Safety Bulletin",
         "Reminder: forklift certification renewals due end of month.", 0),
    )
    cur.execute(
        "INSERT INTO documents (owner_id, title, content, confidential) VALUES (?, ?, ?, ?)",
        (1, "Employee Directory Export",
         "admin: admin@meridianlogistics.example, jsmith: j.smith@meridianlogistics.example", 1),
    )

    conn.commit()
    conn.close()
