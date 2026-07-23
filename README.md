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

    docker compose up --build

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
