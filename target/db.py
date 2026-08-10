# target/db.py
import random
import sqlite3
import string

from werkzeug.security import generate_password_hash

# Fixed seed: every fresh clone gets the identical 100-user/100-shipment
# dataset, not a different random one per machine.
_SEED = 20260809

USER_COUNT = 100
SHIPMENT_COUNT = 100

_FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Carlos", "Maria", "Wei", "Aisha",
    "Liam", "Olivia", "Noah", "Emma", "Ravi", "Priya", "Kenji", "Yuki",
    "Ahmed", "Fatima", "Diego", "Sofia", "Lucas", "Isabella", "Mateus", "Camila",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
    "Taylor", "Moore", "Jackson", "Martin", "Chen", "Wang", "Kumar", "Singh",
    "Kim", "Park", "Nguyen", "Tran", "Silva", "Santos", "Mueller", "Schmidt",
    "Osei", "Mensah", "Khan", "Ali", "Rossi", "Bianchi", "Dubois", "Bernard",
]
_STAFF_ROLES = (
    ["staff"] * 6 + ["dispatcher"] * 3 + ["warehouse"] * 3
    + ["driver"] * 2 + ["customer service"] * 2 + ["manager"] * 1
)

# Realistic corporate password hygiene: some staff genuinely use one of
# these. Deliberately weak by real-world convention (short, or missing a
# character class), not seeded as an exploitable *vulnerability* like the
# admin account -- there's no auth path here these unlock beyond role
# display. Purely data-volume realism.
_WEAK_PASSWORDS = [
    "password1", "Password123", "welcome1", "Summer2024", "123456789",
    "qwerty123", "letmein1", "Winter2025", "iloveyou1", "monkey123",
    "football7", "dragon22",
]

_US_LOCATIONS = [
    "Baltimore, MD", "Charlotte, NC", "Norfolk, VA", "Atlanta, GA", "Miami, FL",
    "Houston, TX", "Chicago, IL", "Los Angeles, CA", "Seattle, WA", "Newark, NJ",
    "Savannah, GA", "Memphis, TN", "Dallas, TX", "Phoenix, AZ", "Denver, CO",
]
_INTL_LOCATIONS = [
    "Rotterdam, Netherlands", "Hamburg, Germany", "Shanghai, China", "Singapore",
    "Tokyo, Japan", "Busan, South Korea", "Mumbai, India", "Dubai, United Arab Emirates",
    "Santos, Brazil", "Manzanillo, Mexico", "Durban, South Africa", "Sydney, Australia",
    "Antwerp, Belgium", "Ho Chi Minh City, Vietnam", "Nairobi, Kenya",
]
_ALL_LOCATIONS = _US_LOCATIONS + _INTL_LOCATIONS

_STATUS_WEIGHTS = (
    ["In Transit"] * 4 + ["Delivered"] * 4 + ["Delayed"] * 2 + ["Customs Hold"] * 1
)
_NOTES_BY_STATUS = {
    "In Transit": "En route, on schedule",
    "Delivered": "Signed by receiving dock",
    "Delayed": "Weather delay, ETA updated",
    "Customs Hold": "Awaiting customs clearance",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    -- Dataset-volume filler rows (target/db.py's ~100 generated users), not
    -- real accounts -- /admin/login must never authenticate them (they
    -- exist only for SQLi-discoverable realism in /search results).
    synthetic INTEGER NOT NULL DEFAULT 0
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

-- H11: cheap hardening against the check-then-insert race in
-- /internal/lock-account (not live today -- single-threaded dev server --
-- but free to add). SQLite treats NULLs as distinct under UNIQUE, so the
-- many NULL-username rows /internal/kill-session inserts are unaffected.
CREATE UNIQUE INDEX IF NOT EXISTS idx_blocked_users_username ON blocked_users (username);
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


def _classify_password(password: str) -> str:
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    if len(password) >= 12 and has_upper and has_lower and has_digit and has_special:
        return "strong"
    return "weak"


def _generate_password(rng: random.Random) -> str:
    if rng.random() < 0.35:
        return rng.choice(_WEAK_PASSWORDS)
    specials = "!@#$%^&*"
    alphabet = string.ascii_letters + string.digits + specials
    required = [
        rng.choice(string.ascii_uppercase),
        rng.choice(string.ascii_lowercase),
        rng.choice(string.digits),
        rng.choice(specials),
    ]
    rest = [rng.choice(alphabet) for _ in range(16 - len(required))]
    chars = required + rest
    rng.shuffle(chars)
    return "".join(chars)


# Real PBKDF2 hashing (salted, one-way -- never plaintext), but far fewer
# iterations than the app's production default (scrypt, ~0.1s/call). Safe
# to keep cheap regardless of hash cost: /admin/login rejects every
# synthetic=1 row outright (see seed_db below and target/routes/admin.py),
# so these 100 filler accounts have no functional login surface at all --
# the deterministic seed means their plaintext credentials are reproducible
# from committed source anyway, so hash cost was never what protected them.
# Every test file spins up a fresh app (and re-seeds the DB) per test, so
# hashing 100 passwords at production cost turned the whole suite's runtime
# from ~19s to ~8.5 minutes. admin/jsmith keep the caller's real
# password_hash_fn unchanged -- those two are what the seeded
# vulnerability and its regression tests actually target.
_BULK_HASH_METHOD = "pbkdf2:sha256:8000"


def _generate_users(n: int, rng: random.Random) -> list:
    used_usernames = {"admin", "jsmith"}
    users = []
    for _ in range(n):
        first = rng.choice(_FIRST_NAMES)
        last = rng.choice(_LAST_NAMES)
        base = f"{first[0].lower()}{last.lower()}"
        username = base
        suffix = 1
        while username in used_usernames:
            suffix += 1
            username = f"{base}{suffix}"
        used_usernames.add(username)
        role = rng.choice(_STAFF_ROLES)
        plaintext = _generate_password(rng)
        password_hash = generate_password_hash(plaintext, method=_BULK_HASH_METHOD)
        users.append((username, password_hash, role, plaintext))
    return users


def _generate_shipments(n: int, start_number: int, rng: random.Random) -> list:
    shipments = []
    for i in range(n):
        origin = rng.choice(_ALL_LOCATIONS)
        destination = rng.choice(_ALL_LOCATIONS)
        while destination == origin:
            destination = rng.choice(_ALL_LOCATIONS)
        status = rng.choice(_STATUS_WEIGHTS)
        tracking_number = f"MER{start_number + i}"
        shipments.append((tracking_number, origin, destination, status, _NOTES_BY_STATUS[status]))
    return shipments


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

    rng = random.Random(_SEED)
    generated_users = _generate_users(USER_COUNT, rng)
    cur.executemany(
        "INSERT INTO users (username, password_hash, role, synthetic) VALUES (?, ?, ?, 1)",
        [(username, password_hash, role) for username, password_hash, role, _ in generated_users],
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
    cur.executemany(
        "INSERT INTO shipments (tracking_number, origin, destination, status, notes) "
        "VALUES (?, ?, ?, ?, ?)",
        _generate_shipments(SHIPMENT_COUNT, start_number=10026, rng=rng),
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
