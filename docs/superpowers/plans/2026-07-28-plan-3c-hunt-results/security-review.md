# Plan 3C — Phase 1 (Hunt): Security Review Findings

Scope reviewed: `target/`, `red_agent/`, `blue_agent/`, `referee/`, `shared/`
(plus the root `docker-compose.yml` that wires those five components
together, read incidentally while tracing network/auth boundaries).
Known findings K1–K6 from the ledger are **not** repeated here.

Analysis only — no files were modified.

---

## New findings

### F1 — Unauthenticated internal admin-action endpoints, reachable by the untrusted agent and the host network

- **Component:** target (`target/routes/internal.py`)
- **Severity:** High
- **Summary:** `/internal/lock-account`, `/internal/kill-session`, and
  `/internal/block-ip` have **no authentication, API key, or caller
  restriction whatsoever** — any POST that reaches the Flask app can lock an
  arbitrary username, kill an arbitrary user's session, or (via `iptables`,
  which the container runs with `NET_ADMIN`) firewall an arbitrary IP. These
  routes are designed to be called only by Wazuh Active Response scripts and
  by `blue_agent`'s `escalate_response` tool, but nothing in the code
  enforces that. Two independent paths make this exploitable, not just
  theoretical:
  1. `docker-compose.yml` publishes the target's port 5000 straight to the
     host (`ports: "5000:5000"`), so anything that can reach the host can
     call these endpoints directly, with no session/cookie required.
  2. `red_agent`'s `http_request` tool (`red_agent/tools.py`) takes an
     arbitrary `path` string with no allow-list — the same network path
     `red_agent` uses for legitimate recon also reaches `/internal/*` on the
     same Flask app/port. A red-agent model turn (intentionally or via
     prompt injection embedded in a document/response it reads) could call
     `POST /internal/block-ip` with `blue_agent`'s or `wazuh.manager`'s IP,
     or `POST /internal/lock-account` with `admin`, causing a self-inflicted
     denial of service against the exercise's own detection/response
     pipeline — indistinguishable in the event log from a legitimate
     escalation blue_agent took.
- **File:line:** `target/routes/internal.py:12-39` (lock_account,
  kill_session), `target/routes/internal.py:42-65` (block_ip);
  `docker-compose.yml:10-11` (published port); `red_agent/tools.py:8-20`
  (unrestricted `path` field)
- **Suggested fix:** Require a shared secret/internal-only header
  (validated against an env var only `blue_agent`/Wazuh containers know) on
  the `/internal/*` blueprint, and/or move it to a network-isolated
  listener not reachable via the public port 5000. At minimum, don't
  publish target's port to the host in the compose file if it isn't needed
  for grading/observability.

### F2 — Hardcoded Flask `SECRET_KEY` allows session forgery, bypassing the intended brute-force gate entirely

- **Component:** target (`target/app.py`)
- **Severity:** High (ambiguous — see note)
- **Summary:** `app.config["SECRET_KEY"] = "purple-lab-dev-key"` is a fixed,
  source-committed string. Flask signs session cookies with this key via
  `itsdangerous`. Because the key is public (checked into the repo, visible
  to anyone with source access — including, notably, an LLM red-agent that
  might read source via some future tool, or any human reviewer), an
  attacker can forge a session cookie with `role=admin` / any `user_id`
  using standard tooling (e.g. `flask-unsign`) and hit
  `/admin/diagnostics` (command injection) or any session-gated route
  directly — with **zero** interaction with the login form, the seeded weak
  password, or the intentional brute-force vuln. This is a different, more
  direct bypass than the one the code's own comments describe as the
  "intended" Phase 1 vuln.
- **File:line:** `target/app.py:21`
- **Suggested fix:** Generate a random `SECRET_KEY` per deployment (e.g.
  from `os.urandom`/env var at container start) even in a lab, if the
  intent is for the brute-force path to be the only intended way in. If
  bypassing entirely via key knowledge is considered acceptable/in-scope for
  the exercise, document it explicitly as a second intentional vuln rather
  than leaving it implicit.
- **Note:** Flagging as ambiguous rather than dropping — the comment
  ("sandboxed lab target, not production") suggests the team already
  accepted *some* relaxation here, but nothing calls out this specific
  bypass path, so it may not be an intended/known difficulty shortcut.

### F3 — Hardcoded credentials for Wazuh indexer/API/dashboard in `docker-compose.yml`

- **Component:** infrastructure (`docker-compose.yml`), touches `target`'s
  dependency stack
- **Severity:** Medium (ambiguous)
- **Summary:** Plaintext, hardcoded credentials checked into version
  control: `INDEXER_PASSWORD=SecretPassword`, `API_PASSWORD=MyS3cr37P450r.*-`,
  `DASHBOARD_USERNAME=kibanaserver` / `DASHBOARD_PASSWORD=kibanaserver`.
  The Wazuh manager's API (port 55000) and the dashboard (port 443) are
  both published to the host. `kibanaserver`/`kibanaserver` in particular is
  a well-known default credential pair.
- **File:line:** `docker-compose.yml:201-208` (wazuh.manager env),
  `docker-compose.yml:260-266` (wazuh.dashboard env), published ports at
  `docker-compose.yml:194-198` and `:257-258`.
- **Suggested fix:** Move to `.env` (git-ignored) or Docker secrets; rotate
  if this repo/branch is or becomes public. Flagging as ambiguous because
  these match Wazuh's own published quickstart demo credentials, so may be
  an intentional "matches upstream lab docs" choice rather than an
  oversight — worth a explicit Triage call either way since the values are
  live in a repo that gets pushed.

### F4 — SSRF/network-boundary note: agent HTTP tools trust `base_url` string concatenation, not a real URL join (informational, not exploitable today)

- **Component:** red_agent, blue_agent (`red_agent/http_tool.py`,
  `blue_agent/http_tool.py`)
- **Severity:** Low / Informational
- **Summary:** `HttpTool.request` builds the request URL via plain string
  concatenation (`f"{self.base_url}{path...}"`), not `urllib.parse.urljoin`.
  This is actually the *safer* choice — a `urljoin`-based implementation
  would let a model-supplied absolute `path` (e.g.
  `http://evil.example/`) silently redirect the request off-host, which
  would be a real SSRF given the `path` argument is fully model-controlled
  (`red_agent/tools.py`, `blue_agent/tools.py`) and the agent containers sit
  on `agent-net` (non-internal, reaches `host.docker.internal` for Ollama).
  Recording this as informational so a future refactor doesn't
  "fix" the string-concat into a `urljoin` call without noticing that
  regresses this into a real SSRF.
- **File:line:** `red_agent/http_tool.py:11-13`,
  `blue_agent/http_tool.py:10-11`
- **Suggested fix:** None required now. If ever refactored to use
  `urljoin`/`requests` URL handling, add an explicit check that the
  resolved URL's scheme+host still matches `base_url`'s before sending.

---

## Reviewed and consciously not flagged (by design, already labeled in-source)

These are pre-existing, explicitly-commented "seeded" vulnerabilities in
`target/` that are the intended attack surface for `red_agent` to discover
during a round — not bugs. Listed here for completeness per the "honest and
complete" instruction, not as new findings:

- SQL injection via string-formatted `LIKE` query — `target/routes/public.py:39-43`
- OS command injection via `shell=True` ping — `target/routes/diagnostics.py:29-35`
- IDOR on `/documents/<id>` (no ownership/auth check) — `target/routes/documents.py:21-31`
- No rate limiting / lockout on `/admin/login`, weak seeded passwords
  (`admin123`, `Sunshine2024!`) — `target/routes/admin.py:46-50`,
  `target/db.py:71-78`

## Areas checked with no findings

- `shared/event_log.py`, `shared/memory.py` — file I/O is atomic
  (temp-file + `os.replace`), paths are config-driven not user-input driven,
  no injection/traversal vector found.
- `referee/monitor.py`, `referee/loop.py` — pure event-log analysis, no
  network exposure (referee has no `networks:` entry by design), no auth
  surface to review.
- `target/routes/documents.py`, `admin.py` templates — `render_template_string`
  calls use Flask's default Jinja autoescaping (filename=None → autoescape
  on), so `{{ q }}` / `{{ error }}` are not reflected-XSS vectors.
- `requirements.txt` — unpinned but narrow (`Flask>=3.0,<4.0`,
  `requests<3.0,>=2.31`); no `npm audit`-equivalent tooling in this Python
  repo; no obviously-vulnerable pin observed.
- `red_agent/ollama_client.py`, `blue_agent/ollama_client.py` — no secrets,
  straightforward POST to configured Ollama host.
