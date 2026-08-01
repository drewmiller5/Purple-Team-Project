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

Requires `INTERNAL_ACTION_TOKEN` set (shared secret authenticating `target`'s
internal defensive endpoints against `blue_agent` and Wazuh's active-response
scripts; no default, the stack fails closed without it) and
`DASHBOARD_AUTH_TOKEN` set (password for the dashboard's HTTP Basic Auth,
username hardcoded as `operator`; also no default). Copy `.env.example` to
`.env` and fill in random values, or export them directly:

    cp .env.example .env   # then edit .env
    docker compose up --build

### Dashboard (host port 8080)

The human-operable dashboard is served on `http://localhost:8080`, behind
reusable plaintext HTTP Basic Auth (no TLS). That's an acceptable trade-off
for a local, single-operator lab -- it grants real attack-firing and
container-restart capability -- but the port should never be bound to a
routable or non-localhost interface.

## Security notes

- The Wazuh indexer/API/dashboard credentials in `docker-compose.yml`
  (`SecretPassword`, `kibanaserver`/`kibanaserver`, etc.) are upstream
  [`wazuh-docker`](https://github.com/wazuh/wazuh-docker)'s own documented
  single-node demo defaults, not a leak of a real secret -- same rationale as
  `wazuh/config/wazuh_indexer_ssl_certs/README.md` for the TLS certs in that
  directory. Left as-is (not rotated) for this publish; rotating them and
  segmenting `red_agent` off the SIEM's own management network is tracked as
  finding H7 in `docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md`,
  worked in public post-publish along with the rest of that ledger.
- `target/app.py`'s three seeded vulnerabilities (below) are intentional --
  that's the point of the lab. Findings that were *not* intentional (a
  hardcoded Flask session key, unsanitized alert data reaching the blue
  agent's LLM context) are fixed; see the findings ledger for the full,
  transparently-tracked list of what's fixed vs. still open.

## What's built (Phase 1: Target Range + Core Infrastructure)

- `target/` — Flask app with three intentionally-seeded vulnerabilities:
  SQLi in `/search`, weak/default admin creds + no lockout on
  `/admin/login`, and IDOR on `/documents/<id>`. Every seeded vuln has a
  regression test proving it's exploitable.
- `shared/memory.py`, `shared/event_log.py` — the persistence layer the
  red and blue agents (Plans 2 and 3) will both build on.
- `scripts/capture_checkpoint.py` — snapshots memory + event log into
  `archive/vN/`, committed to git as the visible learning-curve record.
- `docker-compose.yml` — isolated bridge network, no internet egress.

Next: Plan 2 (red agent) and Plan 3 (blue agent), per `docs/design.md`.

**Note:** Docker runtime verification (build, run, network isolation) is deferred until Docker is installed locally.
