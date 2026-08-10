# Purple Team AI Lab

IT567 term paper project — testing whether a low-stakes, autonomous AI
red-team agent can beat a blue-team agent with first-mover advantage,
per Garfinkel & Dafoe's offense-defense theory.

Phase 1 (this repo, in progress): the target range and shared
infrastructure. Red and blue agents are Plans 2 and 3.

See `docs/design.md` for the full spec.

## Local dev

    pipenv install --dev
    pipenv run pytest

## Run the target app locally (without Docker)

    pipenv run python -m target.app

## Run in Docker (isolated network)

### Quickstart

    pipenv run python scripts/bootstrap.py

Generates `.env` with random secrets if it doesn't exist yet (including
syncing the Wazuh indexer's bcrypt password hashes into
`wazuh/config/wazuh_indexer/internal_users.yml` -- a plain env var alone
isn't enough for those two), brings the stack up, and prints a copy-paste
credentials block for every login surface (target's seeded staff creds, the
round-control dashboard, and Wazuh). Also saves that block to
`QUICKSTART_CREDENTIALS.md` (gitignored) for later reference. Safe to
re-run -- it never touches an `.env` that already exists.

### Manual setup

Requires `INTERNAL_ACTION_TOKEN` set (shared secret authenticating `target`'s
internal defensive endpoints against `blue_agent` and Wazuh's active-response
scripts; no default, the stack fails closed without it), `ROUND_HELPER_TOKEN`
set (round_helper's own dedicated secret for its docker.sock-backed
container-restart control plane, distinct from `INTERNAL_ACTION_TOKEN`; also
no default), and `DASHBOARD_AUTH_TOKEN` set (password for the dashboard's
HTTP Basic Auth, username hardcoded as `operator`; also no default). Copy
`.env.example` to
`.env` and fill in random values, or export them directly:

    cp .env.example .env   # then edit .env
    docker compose up --build

### Dashboard (host port 8080)

The human-operable dashboard is served on `http://localhost:8080`, behind
reusable plaintext HTTP Basic Auth (no TLS). That's an acceptable trade-off
for a local, single-operator lab -- it grants real attack-firing and
container-restart capability -- but the port should never be bound to a
routable or non-localhost interface.

### Target app (host port 5000) -- the attack surface itself

`target` is reachable at `http://localhost:5000` (bound to `127.0.0.1`
only) via a small forwarding-only `target-relay` container, so a human
operator can browse to it and manually try the four seeded vulnerabilities
below, not just watch `red_agent` do it automatically. No auth in front of
it -- that's intentional, it's the thing being attacked. `target` itself
never has a published port or a non-internal network of its own (that
would give it real internet egress, which this project's design
explicitly forbids -- see `docker-compose.yml`'s `target-host-net`
comment); the relay is the only thing that touches a non-internal network,
and it has no application code, credentials, or data of its own to
compromise. Same `127.0.0.1`-under-"mirrored"-WSL2-networking caveat below
applies here too, with a worse consequence if it ever occurs -- unlike the
Wazuh services, nothing gates access to `target` at all.

## Security notes

- The Wazuh indexer/API/dashboard credentials are no longer the upstream
  [`wazuh-docker`](https://github.com/wazuh/wazuh-docker) demo defaults
  (`SecretPassword`, `kibanaserver`/`kibanaserver`) -- they're rotated,
  externally-supplied values read from `.env` (`WAZUH_INDEXER_PASSWORD`,
  `WAZUH_API_PASSWORD`, `WAZUH_DASHBOARD_PASSWORD`; see `.env.example` and
  `wazuh/README.md`), and the manager/dashboard host ports still published
  (1514, 1515, 514, 443) are bound to `127.0.0.1` only, not all interfaces.
  The raw indexer API (9200) and manager API (55000) are no longer
  published to the host at all -- debugging convenience only (curl/
  Postman), not something the experiment needs, and observed live to
  silently and inconsistently drop their loopback binding across Docker
  Desktop engine restarts; removed rather than chased.
  Agent enrollment additionally requires a pre-shared key
  (`wazuh/config/wazuh_cluster/authd.pass`, generated locally, gitignored).
  `red_agent` is not attached to `wazuh-net` (the network `wazuh.manager`/
  `wazuh.indexer`/`wazuh.dashboard` share) -- only `target` is, multi-homed
  for agent enrollment. This closes findings H7 and H48, and closes H53's
  hostname/DNS-based access (raw-IP access to `wazuh.dashboard` from
  `agent-net`/`lab-net` remains open -- believed to be a general Docker
  `ports:` publishing behavior, not this platform specifically; see
  `docker-compose.yml`'s `wazuh.dashboard` `networks:` comment). H52
  (partial -- see below) is also open. See
  `docs/ledger/plans/2026-07-28-plan-3c-findings-ledger.md` for full detail.
  Caveat: `127.0.0.1`-only binding can behave inconsistently under Docker
  Desktop/WSL2's networking modes (e.g. "mirrored" WSL2 networking has had
  reports of loopback-bound ports being reachable from elsewhere on the
  LAN) -- if there's any doubt the binding is actually restrictive on your
  setup, verify from another device on the LAN rather than assuming.
- No TLS termination on `target`, `purple_dashboard`, or `round_helper`
  (H52) is still open -- low risk for a genuinely local-only deployment,
  documented as a known gap rather than fixed here.
- `target/app.py`'s four seeded vulnerabilities (below) are intentional --
  that's the point of the lab. Findings that were *not* intentional (a
  hardcoded Flask session key, unsanitized alert data reaching the blue
  agent's LLM context) are fixed; see the findings ledger for the full,
  transparently-tracked list of what's fixed vs. still open.

## What's built (Phase 1: Target Range + Core Infrastructure)

- `target/` — Flask app with four intentionally-seeded vulnerabilities:
  SQLi in `/search`, weak/default admin creds + no lockout on
  `/admin/login`, IDOR on `/documents/<id>`, and OS command injection on
  `/admin/diagnostics` (the designed win-path escalation). Every seeded
  vuln has a regression test proving it's exploitable.
- `wazuh-rules/target_rules.xml` — the Wazuh detection rules for the
  vulnerabilities above; see `docs/detection-rules.md` for a readable
  writeup of what each rule does and why two of them are intentionally
  defined but never fire (Wazuh's own correlation limitation, worked
  around at the Active Response layer instead).
- `shared/memory.py`, `shared/event_log.py` — the persistence layer the
  red and blue agents (Plans 2 and 3) will both build on.
- `scripts/capture_checkpoint.py` — snapshots memory + event log into
  `archive/vN/`, committed to git as the visible learning-curve record.
- `docker-compose.yml` — isolated bridge network, no internet egress.

Next: Plan 2 (red agent) and Plan 3 (blue agent), per `docs/design.md`.

**Note:** Docker runtime verification (build, run, network isolation) is deferred until Docker is installed locally.

## Future work

- **Try a stronger/newer model.** `red_agent`/`blue_agent` both run on
  `OLLAMA_MODEL` (env var, defaults to `qwen2.5:7b` -- no code change
  needed to swap it, see `.env.example`). The paper's own results and
  this repo's current round-timing constants (`RED_MAX_ITERATIONS`,
  `BLUE_MAX_ITERATIONS`, the referee's 900s round budget) were tuned
  against qwen2.5:7b's observed pace, so a bigger model isn't a drop-in
  swap -- it'd need its own re-tuning pass, not just an env var change.
  Worth trying regardless: giving the agents a genuinely current model
  (browse [ollama.com/search](https://ollama.com/search) for what's
  available; `qwen3:30b` looks like a good next step) is a natural way to
  see whether the offense-defense balance this project studies shifts as
  the underlying model gets stronger -- modern problems deserve a shot
  against modern models, not just whatever was current when the lab was
  first built.
