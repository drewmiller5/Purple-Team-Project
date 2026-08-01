# Plan 3C Phase 1 (Hunt) -- Code Review: target/

Scope: `target/` only (Flask app under attack, seeded vulnerabilities, and
`/internal/*` defensive endpoints). Known findings K1-K6 from the ledger are
not repeated here. Format: `Severity | Summary | File:line | Suggested fix`.

---

**HIGH** | `/internal/*` endpoints have no application-layer authentication or
caller verification, so any actor reachable on the network -- not just
`blue_agent` -- can lock out the admin account, permanently block the admin's
diagnostics access, or install arbitrary `iptables DROP` rules for any IPv4
address. | `target/routes/internal.py:12-65` | Confirmed reachable beyond
`blue_agent`: `docker-compose.yml` places `target`, `red_agent`, and
`blue_agent` on the same `lab-net` network and both agent services are
configured with `TARGET_BASE_URL=http://target:5000` (docker-compose.yml:59,
83); `target`'s port is also published `5000:5000` to the host
(docker-compose.yml:10-11). Nothing in `internal.py` checks a shared secret,
header, or source, unlike `admin.py`/`diagnostics.py` which gate on
`session.get("role")`. Concretely: a POST to `/internal/block-ip` with
`source_ip` set to the Wazuh manager's or `blue_agent`'s own container IP
would DROP its traffic, turning a defensive action into a self-inflicted DoS
if triggered by an adversarial or buggy caller. Suggested fix: require a
shared internal token/header (e.g., checked against an env var) on all three
routes in this blueprint, or restrict by source IP at the app layer as a
defense-in-depth measure beyond docker network segmentation.

---

**MEDIUM** | `subprocess.run(..., timeout=5)` in `/admin/diagnostics` is not
wrapped in a `try/except`, so a non-responding host raises an uncaught
`subprocess.TimeoutExpired` after the 5s timeout, returning a generic Flask
500 error instead of the endpoint's normal `{"output": ...}` JSON contract.
| `target/routes/diagnostics.py:29-36` | This is plausible in-scenario: a host
already DROPped via `/internal/block-ip` (see finding above, or a legitimate
blue action) will blackhole ICMP, so a subsequent `/admin/diagnostics` ping
against that same host hangs for the full 5s and then 500s ungracefully.
`target/tests/test_diagnostics_routes.py` only covers the happy path and the
injection path -- no test exercises a hanging/unreachable host. Suggested
fix: catch `subprocess.TimeoutExpired` (and ideally `FileNotFoundError`) and
return a structured JSON error (e.g., 504 `{"error": "host did not respond"}`)
so callers (including `blue_agent`'s tool-call loop) get a parseable
response instead of an HTML error page.

---

**MEDIUM (ambiguous)** | The check-then-insert pattern in
`/internal/lock-account` is not atomic, and `blocked_users` has no `UNIQUE`
constraint, so two near-simultaneous POSTs for the same username could both
observe `is_blocked() == False` before either commits, reproducing the
duplicate-row bug the existing "final-review fix" comment says is already
closed. | `target/routes/internal.py:23-25` (race), `target/db.py:30-32`
(no UNIQUE constraint) | This is genuinely ambiguous rather than a live bug
today: `target/entrypoint.sh:23` runs `python -m target.app`, and
`target/app.py:41`'s `flask_app.run(host="0.0.0.0", port=5000)` does not pass
`threaded=True`, so Werkzeug's dev server processes one request at a time by
default -- the race window may not be reachable in the current deployment.
However, `target/logging_middleware.py:11-15`'s own module-level lock and
comment ("Flask's dev/threaded server can handle requests on multiple
threads simultaneously") explicitly documents an assumption of concurrent
request handling elsewhere in the same codebase, so the two files disagree
on whether concurrency is in-scope. If threading or multiple workers are
ever enabled (a plausible future change, e.g. to fix the diagnostics-hang
finding above without blocking other requests), `lock-account` regresses to
the exact duplicate-row bug it claims to fix, with no test covering the
concurrent case (`test_lock_account_does_not_duplicate_row_for_already_blocked_username`
in `target/tests/test_internal_routes.py:67-89` only tests two sequential
calls). Suggested fix: add a `UNIQUE` constraint on `blocked_users.username`
(nullable-safe via a partial index, or a dedicated not-null username table)
and/or wrap the check+insert in a transaction/lock, matching the log
writer's own pattern.

---

**MEDIUM (ambiguous)** | `/internal/kill-session` does not kill a specific
session -- it permanently blocks the account's `user_id` from
`/admin/diagnostics` in every future login, with no unblock path anywhere in
the app, because there is no session store or logout route to actually
invalidate a cookie. | `target/routes/internal.py:30-39` (write path),
`target/routes/diagnostics.py:13-20` (only read path that checks it) | Only
`diagnostics.py` calls `is_blocked(conn, user_id=...)`; `admin.py`'s login
only checks `is_blocked(conn, username=...)` (`target/routes/admin.py:36`).
So a "killed" admin can log back in immediately and use every other endpoint
(e.g. `/admin/whoami`) normally -- only `/admin/diagnostics` stays blocked,
forever, for that account. This may be intentional given the app has no
concept of a distinct session identifier to revoke more narrowly (matching
the AR script's actual capability), but the endpoint's name and the
docstring in `target/logging_middleware.py:78-83` ("parse it out of the
alert JSON to know which session to kill") imply a narrower, reversible
action than what actually happens. Flagging as ambiguous per review scope --
worth a design call on whether "kill-session" should (a) be renamed to
reflect its real permanent, account-wide scope, or (b) gain an actual
unblock/logout mechanism.

---

**LOW** | `/internal/lock-account` accepts and permanently stores an
empty-string username with no validation, unlike `/internal/kill-session`
which validates presence/type via `request.form.get("user_id", type=int)`.
| `target/routes/internal.py:14` (no validation before use), contrast with
`target/routes/internal.py:32-34` | A POST with no `username` field (or an
empty one) silently inserts `("", NULL)` into `blocked_users` forever, with
no test covering this input. Suggested fix: mirror `kill_session`'s pattern
-- return 400 if `username` is missing or empty before calling `is_blocked`.

---

**LOW** | `_redact_params` only redacts a field literally named `password`
(case-insensitive exact match) in form/query args; it does not cover JSON
request bodies (none of the current routes use JSON, so currently moot) or
related field names such as `confirm_password`, `new_password`, or `token`.
| `target/logging_middleware.py:18-22` | Not exploitable against any route
that exists today, but brittle if a future endpoint adds a differently-named
credential field or accepts JSON -- it would be logged in plaintext to
`requests.jsonl` with no test to catch the regression. Suggested fix:
redact by substring/regex (e.g., any key containing `password`, `token`,
`secret`) and extend `_redact_params` (or a JSON-body equivalent) to cover
`request.get_json(silent=True)` if any endpoint ever accepts JSON.

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 1     |
| MEDIUM   | 3 (2 flagged ambiguous)|
| LOW      | 2     |

No CRITICAL findings identified in `target/` beyond the already-known,
intentionally-seeded vulnerabilities (SQLi, IDOR, command injection, weak
creds, no lockout) tracked as K1-K6 or called out as deliberate in the
source comments.
