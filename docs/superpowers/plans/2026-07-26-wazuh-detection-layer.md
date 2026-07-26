# Wazuh/Sigma Detection Layer (Plan 3a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up real Wazuh detection (manager + indexer + dashboard + agent) watching `target`, author real Sigma-format rules for all 4 seeded vulns, convert them to Wazuh's native rule format, and wire native Active Response (real IP ban, plus new app-level lock-account/kill-session endpoints) so each seeded vuln produces a real, verified detection-and-response chain.

**Architecture:** Wazuh's official single-node Docker deployment (manager + indexer + dashboard, vendored from upstream) joins `lab-net` so it can receive `target`'s Wazuh-agent traffic without breaking `lab-net`'s egress-block guarantee (container-to-container traffic on an `internal: true` network is unaffected — only routes to the outside world are blocked). `target` already writes every request to `target/logs/requests.jsonl` as JSON ( `target/logging_middleware.py`) — Wazuh's `json` log format auto-flattens those keys to `data.<key>` fields, so no custom decoder is needed, only custom rules matching on `data.path`, `data.form_params`, `data.query_params`, `data.status_code`. `blue_agent` and the referee are explicitly **out of scope** for this plan (Plan 3b, later) — this plan's deliverable is a working detection-and-response pipeline that a human can trigger and observe end to end.

**Tech Stack:** Wazuh 4.9.x (official `wazuh-docker` single-node deployment, vendored), Sigma (YAML rules) + `sigma-cli` with the Wazuh backend for conversion, Flask (target's existing app), Docker Compose, pytest.

## Global Constraints

- `lab-net` stays `internal: true` / fully egress-blocked — nothing in this plan may weaken that. Wazuh manager/indexer join `lab-net` (container-to-container only); only `wazuh-dashboard` also joins `agent-net` (to publish its port to the host), and `target` is never attached to `agent-net`.
- Zero cost — Wazuh, Sigma, and `sigma-cli` are all free/open-source. No API keys, no paid services.
- TDD for every Python change: failing test → minimal implementation → passing test → commit, exactly like Plan 1/Plan 2.
- Follow existing repo conventions: one `requirements.txt` at repo root, one Dockerfile per service, tests colocated under each package's `tests/` directory, container names prefixed `purple-lab-*`.
- No changes to `red_agent/` or `shared/` in this plan — both are already merged and tested; this plan only adds new services and modifies `target/` to add two new endpoints.

---

## ⚠️ Time-budget note

**Task 1 is the long pole.** Standing up Wazuh's manager + indexer + dashboard for the first time — image pulls (multi-GB), TLS cert generation, and the indexer's bootstrap/cluster-init — commonly takes 20-40 minutes of real wall-clock time even on a fast connection, most of it waiting, not typing commands. Start Task 1 first and let it run; do not context-switch away from it expecting a quick check-in. If you're time-boxed tonight, get through Task 1-3 (Wazuh up + agent enrolled + web logs flowing) first — that alone is a demoable, testable detection pipeline. Tasks 4-8 (rules, conversion, Active Response, endpoints, verification) can follow once that foundation is confirmed solid.

---

### Task 1: Vendor and stand up Wazuh single-node, standalone

Stand up Wazuh completely on its own first — before touching this project's `docker-compose.yml` — so any problems are isolated to "does Wazuh itself work" and not tangled up with this project's networking.

**Files:**
- Create: `wazuh/` (vendored copy of upstream `wazuh-docker`'s `single-node/` deployment)

- [ ] **Step 1: Clone the official Wazuh Docker deployment at a pinned tag**

```powershell
git clone --branch v4.9.2 --depth 1 https://github.com/wazuh/wazuh-docker.git wazuh-src
```

If `v4.9.2` no longer exists when you run this, check https://github.com/wazuh/wazuh-docker/releases for the latest `v4.x.x` tag and substitute it here — pin to whatever specific tag you use, don't clone `main`.

- [ ] **Step 2: Vendor the single-node config into this repo**

```powershell
New-Item -ItemType Directory -Force wazuh
Copy-Item -Recurse wazuh-src/single-node/* wazuh/
Remove-Item -Recurse -Force wazuh-src
```

- [ ] **Step 3: Generate TLS certificates**

```powershell
cd wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
cd ..
```

Expected: a `wazuh/config/wazuh_indexer_ssl_certs/` directory populated with cert/key files.

- [ ] **Step 4: Bring the stack up standalone**

```powershell
cd wazuh
docker compose up -d
docker compose ps
cd ..
```

Expected: `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard` all `Up` (indexer may take a few minutes to report healthy — this is the bootstrap wait mentioned above).

- [ ] **Step 5: Confirm the dashboard is reachable**

```powershell
curl -k https://localhost:443 -o NUL -w "%{http_code}`n"
```

Expected: `200`. Log in at `https://localhost` with the default `admin` credentials from `wazuh/config/wazuh_indexer_ssl_certs/` (or the deployment's documented default — confirm in `wazuh/.env` before you skip this) to visually confirm the dashboard loads.

- [ ] **Step 6: Tear down (will be re-integrated into the main compose file in Task 2)**

```powershell
cd wazuh
docker compose down
cd ..
```

- [ ] **Step 7: Commit**

```bash
git add wazuh/
git commit -m "chore: vendor official Wazuh single-node deployment, verified standalone"
```

---

### Task 2: Integrate Wazuh into the project's docker-compose.yml

**Files:**
- Modify: `docker-compose.yml` (add `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard` services, reusing configs from `wazuh/`)

**Interfaces:**
- Produces: `purple-lab-wazuh-manager` reachable at `wazuh.manager:1514`/`1515` from `lab-net`, consumed by Task 3's agent enrollment.

- [ ] **Step 1: Add the Wazuh services**

Append to `docker-compose.yml`'s `services:` block (keep `target` and `red_agent` exactly as they are):

```yaml
  wazuh.indexer:
    image: wazuh/wazuh-indexer:4.9.2
    container_name: purple-lab-wazuh-indexer
    hostname: wazuh.indexer
    networks:
      - lab-net
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
    volumes:
      - wazuh-indexer-data:/var/lib/wazuh-indexer
      - ./wazuh/config/wazuh_indexer_ssl_certs/:/usr/share/wazuh-indexer/certs/
      - ./wazuh/config/wazuh_indexer/wazuh.indexer.yml:/usr/share/wazuh-indexer/opensearch.yml
      - ./wazuh/config/wazuh_indexer/internal_users.yml:/usr/share/wazuh-indexer/opensearch-security/internal_users.yml

  wazuh.manager:
    image: wazuh/wazuh-manager:4.9.2
    container_name: purple-lab-wazuh-manager
    hostname: wazuh.manager
    networks:
      - lab-net
    depends_on:
      - wazuh.indexer
    ports:
      - "1514:1514"
      - "1515:1515"
    volumes:
      - wazuh-manager-config:/var/ossec/etc
      - wazuh-manager-rules:/var/ossec/ruleset/rules
      - ./wazuh/config/wazuh_indexer_ssl_certs/:/etc/ssl/root-ca-manager
      - ./wazuh/config/wazuh_cluster/wazuh_manager.conf:/wazuh-config-mount/etc/ossec.conf

  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.9.2
    container_name: purple-lab-wazuh-dashboard
    hostname: wazuh.dashboard
    networks:
      - lab-net
      - agent-net
    depends_on:
      - wazuh.indexer
      - wazuh.manager
    ports:
      - "443:5601"
    volumes:
      - ./wazuh/config/wazuh_indexer_ssl_certs/:/usr/share/wazuh-dashboard/certs
      - ./wazuh/config/wazuh_dashboard/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
      - ./wazuh/config/wazuh_dashboard/wazuh.yml:/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

Note `wazuh.dashboard` is the *only* Wazuh service on `agent-net` — that's what lets you view it from the host browser without giving `target` (which never joins `agent-net`) any new reachability. `wazuh.manager` and `wazuh.indexer` stay `lab-net`-only, matching how they only need to talk to `target`'s agent and each other.

- [ ] **Step 2: Add the new volumes**

```yaml
volumes:
  target-logs:
  event-log:
  red-memory:
  wazuh-indexer-data:
  wazuh-manager-config:
  wazuh-manager-rules:
```

- [ ] **Step 3: Bring the integrated stack up and verify**

```powershell
docker compose up -d wazuh.indexer wazuh.manager wazuh.dashboard
docker compose ps
curl -k https://localhost:443 -o NUL -w "%{http_code}`n"
```

Expected: all three `Up`, dashboard returns `200`, same as Task 1's standalone check.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml
git commit -m "feat: integrate Wazuh manager/indexer/dashboard into project compose"
```

---

### Task 3: Enroll a Wazuh agent on `target`, ship web-layer logs

**Files:**
- Modify: `target/Dockerfile` (install `wazuh-agent`)
- Create: `wazuh/agent/ossec.conf` (agent config: enrollment + `localfile` pointed at `requests.jsonl`)
- Modify: `docker-compose.yml` (mount agent config into `target`, add `WAZUH_MANAGER` env var)

**Interfaces:**
- Consumes: `target/logs/requests.jsonl` (already produced by `target/logging_middleware.py`, one JSON object per line: `timestamp`, `remote_addr`, `method`, `path`, `query_params`, `form_params`, `status_code`, `duration_ms`).
- Produces: alerts in Wazuh with fields `data.path`, `data.remote_addr`, `data.method`, `data.query_params.*`, `data.form_params.*`, `data.status_code` — consumed by Task 4's Sigma rules.

- [ ] **Step 1: Add the agent config**

```xml
<!-- wazuh/agent/ossec.conf -->
<ossec_config>
  <client>
    <server>
      <address>wazuh.manager</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <localfile>
    <log_format>json</log_format>
    <location>/app/target/logs/requests.jsonl</location>
  </localfile>
</ossec_config>
```

`log_format json` is what makes every top-level key in `requests.jsonl` (`path`, `remote_addr`, `form_params`, etc.) available to rules as `data.<key>` with zero custom decoder work.

- [ ] **Step 2: Install the agent in target's Dockerfile**

```dockerfile
# target/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping curl gnupg apt-transport-https lsb-release \
    && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y --no-install-recommends wazuh-agent=4.9.2-1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY target/ target/
COPY shared/ shared/
COPY wazuh/agent/ossec.conf /var/ossec/etc/ossec.conf
COPY target/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONPATH=/app
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 3: Write the entrypoint that enrolls the agent, starts it, then starts Flask**

```bash
#!/bin/sh
# target/entrypoint.sh
set -e

/var/ossec/bin/agent-auth -m "${WAZUH_MANAGER:-wazuh.manager}"
/var/ossec/bin/wazuh-control start

exec python -m target.app
```

- [ ] **Step 4: Wire the manager address into docker-compose.yml's `target` service**

```yaml
  target:
    build:
      context: .
      dockerfile: target/Dockerfile
    container_name: purple-lab-target
    ports:
      - "5000:5000"
    networks:
      - lab-net
    depends_on:
      - wazuh.manager
    environment:
      - WAZUH_MANAGER=wazuh.manager
    volumes:
      - target-logs:/app/target/logs
      - event-log:/app/shared_logs
```

- [ ] **Step 5: Rebuild and verify agent enrollment**

```powershell
docker compose up --build -d target
docker exec purple-lab-wazuh-manager /var/ossec/bin/agent_control -l
```

Expected: one agent listed with status `Active`.

- [ ] **Step 6: Generate a real request and confirm it reaches Wazuh**

```powershell
curl http://localhost:5000/search?q=test
```

Then in the Wazuh dashboard (or via `docker exec purple-lab-wazuh-manager tail -f /var/ossec/logs/archives/archives.json`), confirm an entry appears with `data.path` = `/search` and `data.query_params.q` = `test`.

- [ ] **Step 7: Commit**

```bash
git add target/Dockerfile target/entrypoint.sh wazuh/agent/ossec.conf docker-compose.yml
git commit -m "feat: enroll Wazuh agent on target, ship web-layer logs as JSON"
```

---

### Task 4: Author Sigma rules for all 4 seeded vulns

**Files:**
- Create: `docs/sigma-rules/sqli-search.yml`
- Create: `docs/sigma-rules/bruteforce-admin-login.yml`
- Create: `docs/sigma-rules/idor-documents.yml`
- Create: `docs/sigma-rules/command-injection-diagnostics.yml`

- [ ] **Step 1: SQLi on `/search`**

```yaml
# docs/sigma-rules/sqli-search.yml
title: SQL Injection Attempt on /search
id: 8f6a6b1e-1c3a-4e6a-9b5a-1a2b3c4d5e6f
status: experimental
description: Detects classic SQLi payloads in the q parameter of the target's search endpoint.
logsource:
  category: webserver
  product: purple-lab-target
detection:
  selection:
    data.path: "/search"
    data.query_params.q|contains:
      - "' OR '1'='1"
      - "' OR 1=1"
      - "--"
      - "UNION SELECT"
  condition: selection
level: high
tags:
  - attack.initial_access
  - attack.t1190
```

- [ ] **Step 2: Brute-force on `/admin/login`**

```yaml
# docs/sigma-rules/bruteforce-admin-login.yml
title: Repeated Failed Admin Login Attempts
id: 3d2e1f0a-4b5c-6d7e-8f9a-0b1c2d3e4f5a
status: experimental
description: >
  Detects 5+ failed POSTs to /admin/login from the same source IP within
  a short window -- target has no built-in lockout, this is the only
  defense against the seeded weak-credential vuln.
logsource:
  category: webserver
  product: purple-lab-target
detection:
  selection:
    data.path: "/admin/login"
    data.method: "POST"
    data.status_code: 200
    data.form_params.username|exists: true
  timeframe: 2m
  condition: selection | count(data.remote_addr) by data.remote_addr >= 5
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

- [ ] **Step 3: IDOR on `/documents/<id>`**

```yaml
# docs/sigma-rules/idor-documents.yml
title: Sequential Document ID Probing (IDOR)
id: 5c4d3e2f-1a0b-9c8d-7e6f-5a4b3c2d1e0f
status: experimental
description: Detects rapid sequential access to /documents/<id> from one source, indicative of ID enumeration.
logsource:
  category: webserver
  product: purple-lab-target
detection:
  selection:
    data.path|re: '^/documents/\d+$'
    data.method: "GET"
  timeframe: 1m
  condition: selection | count(data.path) by data.remote_addr >= 5
level: medium
tags:
  - attack.discovery
  - attack.t1213
```

- [ ] **Step 4: Command injection on `/admin/diagnostics`**

```yaml
# docs/sigma-rules/command-injection-diagnostics.yml
title: OS Command Injection Attempt on /admin/diagnostics
id: 7a8b9c0d-2e3f-4a5b-6c7d-8e9f0a1b2c3d
status: experimental
description: Detects shell metacharacters in the host parameter of the diagnostics ping feature -- the seeded escalation path to host access.
logsource:
  category: webserver
  product: purple-lab-target
detection:
  selection:
    data.path: "/admin/diagnostics"
    data.method: "POST"
    data.form_params.host|contains:
      - ";"
      - "|"
      - "&&"
      - "$("
      - "`"
  condition: selection
level: critical
tags:
  - attack.execution
  - attack.t1059
```

- [ ] **Step 5: Commit**

```bash
git add docs/sigma-rules/
git commit -m "docs: author Sigma detection rules for all 4 seeded vulns"
```

---

### Task 5: Convert Sigma rules to Wazuh, load into the manager

**Files:**
- Create: `wazuh-rules/target_rules.xml` (generated, then committed)
- Modify: `docker-compose.yml` (mount `wazuh-rules/` into `wazuh.manager`)

- [ ] **Step 1: Install sigma-cli with the Wazuh backend**

```powershell
pip install sigma-cli pysigma-backend-wazuh
```

- [ ] **Step 2: Convert all 4 rules into one Wazuh ruleset file**

```powershell
sigma convert -t wazuh --without-pipeline docs/sigma-rules/*.yml -o wazuh-rules/target_rules.xml
```

- [ ] **Step 3: Confirm the generated file has 4 distinct rule IDs and inspect it**

Open `wazuh-rules/target_rules.xml` and confirm it contains one `<rule id="...">` block per Sigma file, each with `<field name="data.path">` (and equivalents) matching what you wrote in Task 4. If `sigma-cli`'s field mapping produced anything unexpected (e.g. it didn't preserve the `data.` prefix), hand-edit the generated XML to correct field paths before proceeding -- this is the fidelity risk flagged in the design spec, and catching it here is exactly why this step exists as its own checkpoint rather than being folded into Step 2.

- [ ] **Step 4: Mount the ruleset into the manager and reload**

Add to `wazuh.manager`'s `volumes:` in `docker-compose.yml`:

```yaml
      - ./wazuh-rules/target_rules.xml:/var/ossec/etc/rules/target_rules.xml
```

```powershell
docker compose up -d wazuh.manager
docker exec purple-lab-wazuh-manager /var/ossec/bin/wazuh-control restart
```

- [ ] **Step 5: Verify each rule fires**

```powershell
curl "http://localhost:5000/search?q=1' OR '1'='1"
```

Check `docker exec purple-lab-wazuh-manager tail -20 /var/ossec/logs/alerts/alerts.json` for an alert referencing the SQLi rule's ID. Repeat with a raw `curl` hitting `/admin/diagnostics` with a `;`-containing `host` value to confirm the command-injection rule also fires (skip triggering brute-force/IDOR here -- those need Task 8's full verification pass with real repeated requests).

- [ ] **Step 6: Commit**

```bash
git add wazuh-rules/ docker-compose.yml
git commit -m "feat: convert Sigma rules to Wazuh XML, load into manager, verify SQLi + command-injection rules fire"
```

---

### Task 6: Add lock-account and kill-session endpoints on target

Both AR actions need somewhere real to act. `target` currently has no server-side session/lockout state at all (Flask's `session` is just a signed cookie -- there's nothing today to revoke). This task adds a minimal blocklist table both endpoints share: `lock-account` blocks future logins for a username, `kill-session` blocks the current session by blocking the already-authenticated user's id.

**Files:**
- Create: `target/routes/internal.py`
- Modify: `target/db.py` (add `blocked_users` table)
- Modify: `target/routes/admin.py` (check block state on login + on admin-session routes)
- Modify: `target/app.py` (register new blueprint)
- Test: `target/tests/test_internal_routes.py`

**Interfaces:**
- Consumes: `target.db.get_connection` (existing).
- Produces: `POST /internal/lock-account` (body: `username`), `POST /internal/kill-session` (body: `user_id`) -- both return `200` and write a block row. Consumed by Task 7's Active Response scripts. Also produces `target.db.is_blocked(conn, username=None, user_id=None) -> bool`, consumed by `admin.py`'s login check and `diagnostics.py`'s admin-session check.

- [ ] **Step 1: Write the failing tests**

```python
# target/tests/test_internal_routes.py
from target.app import create_app


def _make_client(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    return app.test_client()


def test_lock_account_blocks_future_login(tmp_path):
    client = _make_client(tmp_path)
    client.post("/internal/lock-account", data={"username": "admin"})

    response = client.post(
        "/admin/login", data={"username": "admin", "password": "admin123"}
    )
    assert b"Welcome" not in response.data
    assert b"blocked" in response.data.lower()


def test_kill_session_blocks_subsequent_admin_requests(tmp_path):
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    login_row = client.get("/admin/whoami").get_json()
    client.post("/internal/kill-session", data={"user_id": login_row["user_id"]})

    response = client.post("/admin/diagnostics", data={"host": "127.0.0.1"})
    assert response.status_code == 403


def test_unblocked_account_logs_in_normally(tmp_path):
    client = _make_client(tmp_path)
    response = client.post(
        "/admin/login", data={"username": "admin", "password": "admin123"}
    )
    assert b"Welcome" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest target/tests/test_internal_routes.py -v`
Expected: FAIL -- `/internal/lock-account` and `/internal/kill-session` don't exist yet (404), and `/admin/whoami` doesn't exist yet either.

- [ ] **Step 3: Add the `blocked_users` table and helper**

```python
# target/db.py -- add alongside existing init_db/seed_db/get_connection
def init_db(db_path: str) -> None:
    conn = get_connection(db_path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE,
            password_hash TEXT, role TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS blocked_users (
            username TEXT, user_id INTEGER
        )"""
    )
    # ... existing documents table creation stays as-is
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
```

(Merge this into the existing `init_db`/`get_connection` in `target/db.py` rather than duplicating -- keep the existing `users`/`documents` table creation statements exactly as they are, just add the `blocked_users` table and the new `is_blocked` function alongside them.)

- [ ] **Step 4: Write the internal routes**

```python
# target/routes/internal.py
from flask import Blueprint, current_app, jsonify, request

from target.db import get_connection

internal_bp = Blueprint("internal", __name__, url_prefix="/internal")


@internal_bp.route("/lock-account", methods=["POST"])
def lock_account():
    username = request.form.get("username", "")
    conn = get_connection(current_app.config["DB_PATH"])
    conn.execute("INSERT INTO blocked_users (username) VALUES (?)", (username,))
    conn.commit()
    conn.close()
    return jsonify({"locked": username}), 200


@internal_bp.route("/kill-session", methods=["POST"])
def kill_session():
    user_id = request.form.get("user_id", type=int)
    conn = get_connection(current_app.config["DB_PATH"])
    conn.execute("INSERT INTO blocked_users (user_id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"killed_session_for": user_id}), 200
```

- [ ] **Step 5: Enforce blocks in `admin.py`, add `/admin/whoami`**

```python
# target/routes/admin.py -- modify login(), add whoami()
from target.db import get_connection, is_blocked  # add is_blocked to the import

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

    if row is None or not check_password_hash(row["password_hash"], password):
        return render_template_string(LOGIN_FORM, error="Invalid credentials")

    session["user_id"] = row["id"]
    session["role"] = row["role"]
    return f"<h1>Welcome, {username}</h1><p>Role: {row['role']}</p>"


@admin_bp.route("/whoami")
def whoami():
    return jsonify({"user_id": session.get("user_id"), "role": session.get("role")})
```

Add `jsonify` to the existing `from flask import ...` line in `admin.py`.

- [ ] **Step 6: Enforce the kill-session block in `diagnostics.py`**

```python
# target/routes/diagnostics.py -- modify carrier_connectivity_check()'s guard
from target.db import get_connection, is_blocked  # add import

@diagnostics_bp.route("/diagnostics", methods=["POST"])
def carrier_connectivity_check():
    if session.get("role") != "admin":
        return jsonify({"error": "admin session required"}), 403

    conn = get_connection(current_app.config["DB_PATH"])
    blocked = is_blocked(conn, user_id=session.get("user_id"))
    conn.close()
    if blocked:
        return jsonify({"error": "session killed"}), 403

    host = request.form.get("host", "")
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=5,
    )
    return jsonify({"output": result.stdout + result.stderr})
```

- [ ] **Step 7: Register the blueprint**

In `target/app.py`, add `from target.routes.internal import internal_bp` next to the other route imports, and `app.register_blueprint(internal_bp)` next to the other registrations.

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest target/tests/test_internal_routes.py -v`
Expected: 3 passed.

- [ ] **Step 9: Run the full suite to confirm no regressions**

Run: `pytest -v`
Expected: all prior tests (32 from Plans 1-2) plus these 3 -- 35 total, all passing.

- [ ] **Step 10: Commit**

```bash
git add target/routes/internal.py target/db.py target/routes/admin.py target/routes/diagnostics.py target/app.py target/tests/test_internal_routes.py
git commit -m "feat: add lock-account/kill-session internal endpoints with blocklist enforcement"
```

---

### Task 7: Wire Wazuh Active Response

**Files:**
- Create: `wazuh/active-response/lock-account.sh`
- Create: `wazuh/active-response/kill-session.sh`
- Modify: `docker-compose.yml` (`target` needs `NET_ADMIN`; mount AR scripts into `wazuh.manager`)
- Modify: `wazuh/config/wazuh_cluster/wazuh_manager.conf` (from Task 1's vendored copy -- add `<active-response>` blocks)

- [ ] **Step 1: Grant target NET_ADMIN for real firewall-level response**

Add to `target`'s service definition in `docker-compose.yml`:

```yaml
    cap_add:
      - NET_ADMIN
```

- [ ] **Step 2: Write the lock-account Active Response script**

```bash
#!/bin/sh
# wazuh/active-response/lock-account.sh
# Reads Wazuh's AR JSON payload from stdin, extracts the username from the
# alert's data.form_params.username field, and calls target's internal
# lock-account endpoint. Wazuh AR scripts always receive their trigger
# payload on stdin as a single JSON line.
read -r INPUT_JSON
USERNAME=$(echo "$INPUT_JSON" | grep -o '"username":"[^"]*"' | cut -d'"' -f4)

curl -s -X POST http://target:5000/internal/lock-account -d "username=${USERNAME}"
```

- [ ] **Step 3: Write the kill-session Active Response script**

```bash
#!/bin/sh
# wazuh/active-response/kill-session.sh
read -r INPUT_JSON
USER_ID=$(echo "$INPUT_JSON" | grep -o '"user_id":[0-9]*' | cut -d':' -f2)

curl -s -X POST http://target:5000/internal/kill-session -d "user_id=${USER_ID}"
```

- [ ] **Step 4: Mount the scripts and NET_ADMIN into the manager's active-response config**

Add to `wazuh.manager`'s `volumes:` in `docker-compose.yml`:

```yaml
      - ./wazuh/active-response/lock-account.sh:/var/ossec/active-response/bin/lock-account.sh
      - ./wazuh/active-response/kill-session.sh:/var/ossec/active-response/bin/kill-session.sh
```

- [ ] **Step 5: Bind responses to rules in the manager config**

In `wazuh/config/wazuh_cluster/wazuh_manager.conf`, add inside `<ossec_config>`:

```xml
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  <command>
    <name>lock-account</name>
    <executable>lock-account.sh</executable>
  </command>
  <command>
    <name>kill-session</name>
    <executable>kill-session.sh</executable>
  </command>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100001,100003,100004</rules_id>
    <timeout>600</timeout>
  </active-response>
  <active-response>
    <command>lock-account</command>
    <location>local</location>
    <rules_id>100002</rules_id>
  </active-response>
  <active-response>
    <command>kill-session</command>
    <location>local</location>
    <rules_id>100004</rules_id>
  </active-response>
```

The four `rules_id` values (`100001`-`100004`) must match the actual generated rule IDs in `wazuh-rules/target_rules.xml` from Task 5 -- open that file and substitute the real IDs sigma-cli assigned (they won't necessarily be exactly `100001`-`100004`; check and correct before proceeding). `firewall-drop` fires on SQLi (100001), IDOR (100003), and command-injection (100004) -- an IP-level ban is the right reflex for all three. `lock-account` fires only on brute-force (100002). `kill-session` fires on command-injection (100004) alongside the IP ban, since that's the point where an authenticated admin session is actively being used maliciously.

- [ ] **Step 6: Restart the manager**

```powershell
docker compose up -d wazuh.manager
docker exec purple-lab-wazuh-manager /var/ossec/bin/wazuh-control restart
```

- [ ] **Step 7: Commit**

```bash
git add wazuh/active-response/ docker-compose.yml wazuh/config/wazuh_cluster/wazuh_manager.conf
git commit -m "feat: wire Wazuh Active Response -- firewall-drop, lock-account, kill-session"
```

---

### Task 8: End-to-end manual verification (all 4 vulns, detection + response)

Not automated -- same pattern as Plan 1 Task 7 / Plan 2 Task 11. This is the deliverable that proves the whole chain works, not just its pieces in isolation.

- [ ] **Step 1: Bring the full stack up**

```powershell
docker compose up --build -d
docker compose ps
```

Expected: `target`, `wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard` all `Up`. (`red_agent` can stay down for this verification -- it's not needed to test detection.)

- [ ] **Step 2: SQLi → firewall-drop**

```powershell
curl "http://localhost:5000/search?q=1' OR '1'='1"
```

Check `docker exec purple-lab-wazuh-manager tail -20 /var/ossec/logs/alerts/alerts.json` for the SQLi rule firing, then confirm the IP was actually dropped:

```powershell
docker exec purple-lab-target iptables -L -n
```

Expected: a `DROP` rule referencing the source IP.

- [ ] **Step 3: Brute-force → lock-account**

```powershell
1..6 | ForEach-Object { curl -X POST http://localhost:5000/admin/login -d "username=admin&password=wrong$_" }
curl -X POST http://localhost:5000/admin/login -d "username=admin&password=admin123"
```

Expected: the final (correct-credentials) login is rejected with "Account blocked" -- proves `lock-account` AR fired before the real credentials were even tried.

- [ ] **Step 4: IDOR → firewall-drop**

```powershell
1..6 | ForEach-Object { curl "http://localhost:5000/documents/$_" }
```

Check alerts.json for the IDOR rule firing and `iptables -L -n` for the resulting drop.

- [ ] **Step 5: Command injection → firewall-drop + kill-session**

```powershell
curl -X POST http://localhost:5000/admin/login -d "username=admin&password=admin123" -c cookies.txt
curl -X POST http://localhost:5000/admin/diagnostics -b cookies.txt -d "host=127.0.0.1; echo PWNED"
curl -X POST http://localhost:5000/admin/diagnostics -b cookies.txt -d "host=127.0.0.1"
```

Expected: the first diagnostics call succeeds (proving the vuln still works pre-detection), the second call (after Wazuh has had a moment to alert and fire AR) returns `403` with `"session killed"` -- proving `kill-session` fired on the same session that triggered the injection.

- [ ] **Step 6: Tear down**

```powershell
docker compose down
```

- [ ] **Step 7: Update the term paper note**

Append a dated entry to `work/school/Term Paper - AI Cyber Offense-Defense Synopsis.md` in the vault: confirm Plan 3a (Wazuh/Sigma detection layer) is built and verified, summarize what fired for each of the 4 vulns, and note that Plan 3b (`blue_agent` + referee) is next. Same style as the existing Plan 1/Plan 2 entries in that file.

---

## Self-Review Notes

- **Spec coverage:** Wazuh stack (§3, §4 of the spec) → Tasks 1-3. Sigma rules + conversion (§4, §6) → Tasks 4-5. Native Active Response (§3, §4) → Task 7, including the two app-level endpoints Task 6 builds for it. Manual end-to-end verification (§7 of the spec) → Task 8. `blue_agent`/referee/devcontainer/provider-swap are explicitly out of scope per the spec's plan-splitting note and are not touched anywhere in this plan.
- **Placeholder scan:** none found — every step has a runnable command or complete code. The one open variable (exact rule IDs in Task 7 Step 5) is flagged explicitly as something to check and correct against Task 5's real output, not left vague.
- **Type consistency:** `is_blocked(conn, username=None, user_id=None)` signature in Task 6 Step 3 matches its call sites in Step 5 (`admin.py`) and Step 6 (`diagnostics.py`). `requests.jsonl` field names used in Task 4's Sigma rules (`path`, `method`, `status_code`, `query_params`, `form_params`, `remote_addr`) match exactly what `target/logging_middleware.py` actually writes.
