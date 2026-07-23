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
