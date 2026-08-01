# Plan 3D: Interactive Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `purple_dashboard` from a read-only observability view into a full interactive control surface -- a human can watch, manually attack as red, manually defend as blue, ask a purple-team advisor, and start/restart rounds -- built on a real visual design pass.

**Architecture:** `purple_dashboard` moves off its isolated `dashboard-net` onto `lab-net` (to reach `target`) and `agent-net` (to reach Ollama and the new `round_helper`). A new minimal `round_helper` service is the only container with `docker.sock` access, exposing exactly one capability (restart `referee`/`red_agent`/`blue_agent` by hardcoded allowlist). Manual actions reuse `target`'s existing endpoints (`/search`, `/admin/login`, `/documents/<id>`, `/admin/diagnostics`, `/internal/*`) exactly as `red_agent`/`blue_agent` already do, tagging events `actor: "human"` so `referee/monitor.py`'s win conditions can exclude them.

**Tech Stack:** Python 3.11, Flask, pytest, `requests`, Docker Compose, vanilla JS (no build toolchain).

## Global Constraints

- Single-file-per-concern Flask app, no new frontend build toolchain (no npm/webpack) -- the page template stays a Python string rendered via `render_template_string`, split into its own module for readability.
- Dark theme stays; existing red/blue/white color coding stays as the semantic color system for the three teams.
- TDD for every Python code change: failing test first, minimal implementation, passing test. Docker Compose/config changes use direct verification (`docker compose config`, live container checks) per this project's established convention.
- Every manual action a human takes must log to the same shared `events.jsonl` as agent actions, with `actor: "human"` added, so both render identically in the existing feeds and are distinguishable only by that tag.
- `round_helper`'s restart capability is scoped to exactly three hardcoded container names (`referee`, `red_agent`, `blue_agent`) -- no generic "restart any container" capability, ever.
- The purple advisor is read-only by construction: it returns text only, never calls a tool, endpoint, or agent action.
- Failures (target/Ollama/round_helper unreachable) are surfaced inline in the UI, never swallowed -- matches this project's standing "don't cheat anything" rule.

---

## File Structure

- `referee/monitor.py` (modify) -- add `actor == "human"` exclusion to the three win-condition functions.
- `round_helper/app.py` (create) -- the restart-helper Flask service.
- `round_helper/Dockerfile` (create)
- `round_helper/tests/test_app.py` (create)
- `dashboard/round_control.py` (create) -- go.flag/stop.flag touch/clear + call to `round_helper`.
- `dashboard/actions.py` (create) -- manual red/blue action dispatch (HTTP calls to `target`, event logging).
- `dashboard/advisor.py` (create) -- Ollama-backed advisor query + advisor log.
- `dashboard/page.py` (create) -- the HTML/CSS/JS template string, extracted out of `app.py`.
- `dashboard/app.py` (modify) -- Flask routes wiring the above modules together; `/api/state` extended with round-result banner data.
- `dashboard/tests/test_actions.py`, `dashboard/tests/test_round_control.py`, `dashboard/tests/test_advisor.py`, `dashboard/tests/test_app.py` (create)
- `docker-compose.yml` (modify) -- add `round_helper` service; move `purple_dashboard` onto `lab-net`+`agent-net`; mount `referee-state` read-write for dashboard; add `INTERNAL_ACTION_TOKEN`/`ROUND_HELPER_URL`/`OLLAMA_HOST`/`OLLAMA_MODEL` env to dashboard.

---

### Task 1: Docker Compose wiring

**Files:**
- Modify: `docker-compose.yml`

**Interfaces:**
- Produces: `round_helper` service reachable at `http://round_helper:8090` from `purple_dashboard`; `purple_dashboard` reachable on `lab-net` (to `target:5000`) and `agent-net` (to `host.docker.internal:11434` and `round_helper`); `referee-state` volume mounted read-write (not `:ro`) for `purple_dashboard`.

- [ ] **Step 1: Add the `round_helper` service**

Add this service block to `docker-compose.yml` (after `purple_dashboard`, before `wazuh.indexer`):

```yaml
  round_helper:
    build:
      context: .
      dockerfile: round_helper/Dockerfile
    container_name: purple-lab-round-helper
    networks:
      - agent-net
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - COMPOSE_PROJECT_DIR=/app
```

- [ ] **Step 2: Move `purple_dashboard` onto `lab-net` + `agent-net`, mount state read-write, add env**

Replace the existing `purple_dashboard` service block with:

```yaml
  purple_dashboard:
    build:
      context: .
      dockerfile: dashboard/Dockerfile
    container_name: purple-lab-dashboard
    restart: unless-stopped
    # Moved off the isolated dashboard-net onto lab-net (reach target) and
    # agent-net (reach Ollama + round_helper) -- Plan 3D's whole point is
    # letting a human act, not just observe. Disclosed, deliberate change
    # to the isolation posture built in the read-only version of this
    # service.
    networks:
      - lab-net
      - agent-net
    ports:
      - "8080:8080"
    environment:
      - EVENT_LOG_PATH=/app/shared_logs/events.jsonl
      - REFEREE_LOG_PATH=/app/referee_logs/referee_assessments.jsonl
      - REFEREE_STATE_DIR=/app/referee_state
      - TARGET_BASE_URL=http://target:5000
      - INTERNAL_ACTION_TOKEN=${INTERNAL_ACTION_TOKEN:?set INTERNAL_ACTION_TOKEN before starting the lab}
      - ROUND_HELPER_URL=http://round_helper:8090
      - OLLAMA_HOST=http://host.docker.internal:11434
      - OLLAMA_MODEL=${OLLAMA_MODEL:-qwen2.5:7b}
      - ADVISOR_LOG_PATH=/app/referee_logs/advisor_log.jsonl
    volumes:
      - event-log:/app/shared_logs
      - referee-logs:/app/referee_logs
      # No longer :ro -- manual round control needs to touch/clear
      # go.flag/stop.flag.
      - referee-state:/app/referee_state
```

- [ ] **Step 3: Validate the compose file**

Run: `docker compose config --quiet`
Expected: no output, exit code 0 (validates YAML syntax and variable interpolation without starting anything).

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml
git commit -m "infra: wire round_helper service and open dashboard to lab-net/agent-net"
```

---

### Task 2: `referee/monitor.py` actor filter

**Files:**
- Modify: `referee/monitor.py`
- Test: `referee/tests/test_monitor.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `has_blue_heartbeat`, `blue_decisive_win`, `red_decisive_win`, `red_has_host_access` all ignore events where `e.get("actor") == "human"`, so a human manually reproducing a win-condition pattern can never end an autonomous round.

- [ ] **Step 1: Write the failing tests**

Add to `referee/tests/test_monitor.py`:

```python
def test_has_blue_heartbeat_ignores_human_actor_events():
    events = [{"side": "blue", "actor": "human", "phase": "heartbeat"}]
    assert has_blue_heartbeat(events) is False


def test_blue_decisive_win_ignores_human_actor_red_requests():
    events = [{"side": "blue", "phase": "heartbeat"}]
    events += [
        {"side": "red", "actor": "human", "phase": "http_request", "response": {"status_code": 403}}
        for _ in range(3)
    ]
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_red_decisive_win_ignores_human_actor_host_access():
    from datetime import datetime, timezone
    events = [
        {"side": "blue", "phase": "heartbeat", "timestamp": "2026-01-01T00:00:00+00:00"},
        {
            "side": "red", "actor": "human", "phase": "http_request",
            "request": {"path": "/admin/diagnostics"}, "response": {"status_code": 200},
        },
    ]
    now = datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc)
    assert red_decisive_win(events, now, stale_seconds=1) is False
```

Add the needed imports at the top of the test file if not already present: `from referee.monitor import has_blue_heartbeat, blue_decisive_win, red_decisive_win`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest referee/tests/test_monitor.py -k human_actor -v`
Expected: all 3 FAIL (human-tagged events currently count toward win conditions).

- [ ] **Step 3: Implement the filter**

In `referee/monitor.py`, add a helper and use it everywhere `events` is scanned:

```python
def _agent_events(events: list) -> list:
    """Exclude human-tagged events from autonomous win-condition scans --
    a human manually reproducing a win-condition pattern during a live
    round must never silently end that round."""
    return [e for e in events if e.get("actor") != "human"]
```

Then update each function to filter first:

```python
def has_blue_heartbeat(events: list) -> bool:
    return any(e.get("side") == "blue" for e in _agent_events(events))


def red_has_host_access(events: list) -> bool:
    return any(
        e.get("side") == "red"
        and e.get("phase") == "http_request"
        and e.get("request", {}).get("path") == "/admin/diagnostics"
        and e.get("response", {}).get("status_code") == 200
        for e in _agent_events(events)
    )
```

In `blue_decisive_win`, change `red_requests = [e for e in events if ...]` to filter `_agent_events(events)` instead of `events`, and change the internal `has_blue_heartbeat(events)` call to pass `events` unchanged (it already filters internally now).

In `red_decisive_win`, change the `blue_timestamps` comprehension to iterate `_agent_events(events)` instead of `events`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest referee/tests/test_monitor.py -v`
Expected: all tests PASS, including the 3 new ones and every pre-existing test (regression check).

- [ ] **Step 5: Commit**

```bash
git add referee/monitor.py referee/tests/test_monitor.py
git commit -m "feat: exclude human-actor events from referee win conditions"
```

---

### Task 3: `round_helper` service

**Files:**
- Create: `round_helper/app.py`
- Create: `round_helper/Dockerfile`
- Test: `round_helper/tests/test_app.py`

**Interfaces:**
- Produces: `POST /restart-round` -- runs `docker start <container names>` via `subprocess.run` against the 3 already-built, already-configured containers (they exist and just exited; this revives them, it does not rebuild or recreate anything, so it needs no compose file or build context inside this container -- only the mounted socket). Returns `{"restarted": [...]}` (200) on success or `{"error": ...}` (500) on failure. No other route exists.

- [ ] **Step 1: Write the failing tests**

Create `round_helper/tests/__init__.py` (empty) and `round_helper/tests/test_app.py`:

```python
from unittest.mock import patch

from round_helper.app import create_app, ALLOWED_CONTAINERS


def _client():
    return create_app().test_client()


def test_restart_round_runs_docker_start_for_exactly_the_allowlist():
    client = _client()
    with patch("round_helper.app.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        response = client.post("/restart-round")

    assert response.status_code == 200
    assert response.get_json() == {"restarted": ALLOWED_CONTAINERS}
    called_args = mock_run.call_args.args[0]
    assert called_args[:2] == ["docker", "start"]
    assert sorted(called_args[2:]) == sorted(ALLOWED_CONTAINERS)


def test_restart_round_returns_500_on_compose_failure():
    client = _client()
    with patch("round_helper.app.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "boom"
        response = client.post("/restart-round")

    assert response.status_code == 500
    assert "boom" in response.get_json()["error"]


def test_no_other_routes_exist():
    client = _client()
    for method, path in [("POST", "/restart"), ("POST", "/stop"), ("GET", "/containers")]:
        response = client.open(path, method=method)
        assert response.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest round_helper/tests/test_app.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'round_helper.app'`.

- [ ] **Step 3: Implement the service**

Create `round_helper/app.py`:

```python
import subprocess

from flask import Flask, jsonify

# Real container names (docker-compose.yml's container_name: values), not
# compose service names -- `docker start` operates on the container, and
# these containers already exist (built once by `docker compose up`); this
# revives them, it never builds or recreates anything, so it needs no
# compose file or build context inside this container, only the socket.
ALLOWED_CONTAINERS = ["purple-lab-referee", "purple-lab-red", "purple-lab-blue"]


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/restart-round", methods=["POST"])
    def restart_round():
        result = subprocess.run(
            ["docker", "start", *ALLOWED_CONTAINERS],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return jsonify({"error": result.stderr or "docker start failed"}), 500
        return jsonify({"restarted": ALLOWED_CONTAINERS})

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8090)
```

Create `round_helper/tests/__init__.py` and `round_helper/__init__.py` (both empty).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest round_helper/tests/test_app.py -v`
Expected: all 3 PASS.

- [ ] **Step 5: Write the Dockerfile**

Create `round_helper/Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask
COPY round_helper/ round_helper/
CMD ["python", "-m", "round_helper.app"]
```

- [ ] **Step 6: Commit**

```bash
git add round_helper/
git commit -m "feat: add round_helper service (scoped container-restart capability)"
```

---

### Task 4: `dashboard/round_control.py`

**Files:**
- Create: `dashboard/round_control.py`
- Test: `dashboard/tests/test_round_control.py`

**Interfaces:**
- Consumes: nothing from other new modules.
- Produces: `clear_flags(state_dir: str)`, `stop_round(state_dir: str) -> dict`, `restart_round(helper_url: str) -> dict` -- `restart_round` POSTs to `{helper_url}/restart-round` and returns its JSON, or `{"error": ...}` if unreachable.

- [ ] **Step 1: Write the failing tests**

Create `dashboard/tests/__init__.py` (empty) and `dashboard/tests/test_round_control.py`:

```python
from pathlib import Path
from unittest.mock import patch

import requests

from dashboard.round_control import clear_flags, restart_round, stop_round


def test_clear_flags_removes_both_flag_files(tmp_path):
    (tmp_path / "go.flag").touch()
    (tmp_path / "stop.flag").touch()

    clear_flags(str(tmp_path))

    assert not (tmp_path / "go.flag").exists()
    assert not (tmp_path / "stop.flag").exists()


def test_clear_flags_is_safe_when_files_absent(tmp_path):
    clear_flags(str(tmp_path))  # must not raise


def test_stop_round_touches_stop_flag(tmp_path):
    result = stop_round(str(tmp_path))

    assert (tmp_path / "stop.flag").exists()
    assert result == {"stopped": True}


def test_restart_round_posts_to_helper_and_returns_its_response():
    with patch("dashboard.round_control.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"restarted": ["purple-lab-referee", "purple-lab-red", "purple-lab-blue"]}
        result = restart_round("http://round_helper:8090")

    mock_post.assert_called_once_with("http://round_helper:8090/restart-round", timeout=60)
    assert result == {"restarted": ["purple-lab-referee", "purple-lab-red", "purple-lab-blue"]}


def test_restart_round_surfaces_connection_errors_instead_of_raising():
    with patch("dashboard.round_control.requests.post", side_effect=requests.RequestException("down")):
        result = restart_round("http://round_helper:8090")

    assert result == {"error": "down"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest dashboard/tests/test_round_control.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dashboard.round_control'`.

- [ ] **Step 3: Implement**

Create `dashboard/round_control.py`:

```python
from pathlib import Path

import requests


def clear_flags(state_dir: str) -> None:
    Path(state_dir, "go.flag").unlink(missing_ok=True)
    Path(state_dir, "stop.flag").unlink(missing_ok=True)


def stop_round(state_dir: str) -> dict:
    Path(state_dir, "stop.flag").touch()
    return {"stopped": True}


def restart_round(helper_url: str) -> dict:
    try:
        response = requests.post(f"{helper_url}/restart-round", timeout=60)
    except requests.RequestException as exc:
        return {"error": str(exc)}
    return response.json()
```

Create `dashboard/__init__.py` (empty, if not already present).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest dashboard/tests/test_round_control.py -v`
Expected: all 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add dashboard/round_control.py dashboard/tests/test_round_control.py dashboard/__init__.py dashboard/tests/__init__.py
git commit -m "feat: dashboard round control (flag clear/stop + round_helper client)"
```

---

### Task 5: `dashboard/actions.py` -- manual red + blue actions

**Files:**
- Create: `dashboard/actions.py`
- Test: `dashboard/tests/test_actions.py`

**Interfaces:**
- Consumes: `shared/event_log.py::log_event(log_path, event)` (already exists in the repo).
- Produces: `RED_TEMPLATES: dict[str, dict]` (template name -> `{method, path, params, data}`), `run_red_action(target_base_url, template_name=None, raw=None, event_log_path=...) -> dict`, `run_blue_action(target_base_url, internal_action_token, action, target, event_log_path=...) -> dict`. Both log a `{"side": ..., "actor": "human", ...}` event, add a `found_it: bool` key to the returned result (the base spec's cosmetic "found it" detector -- true when *this* human action reproduced a win-condition-shaped result: red reaching `/admin/diagnostics` with a 200, or blue's action getting a non-error response), and return the result dict.

- [ ] **Step 1: Write the failing tests**

Create `dashboard/tests/test_actions.py`:

```python
import json
from pathlib import Path

import responses

from dashboard.actions import RED_TEMPLATES, run_blue_action, run_red_action


@responses.activate
def test_run_red_action_sqli_template_hits_search_and_logs_event(tmp_path):
    responses.add(responses.GET, "http://target:5000/search", json={"results": []}, status=200)
    log_path = str(tmp_path / "events.jsonl")

    result = run_red_action("http://target:5000", template_name="sqli", event_log_path=log_path)

    assert result["status_code"] == 200
    logged = json.loads(Path(log_path).read_text().splitlines()[0])
    assert logged["side"] == "red"
    assert logged["actor"] == "human"
    assert logged["phase"] == "http_request"
    assert logged["request"]["path"] == RED_TEMPLATES["sqli"]["path"]


@responses.activate
def test_run_red_action_raw_request_hits_given_method_and_path(tmp_path):
    responses.add(responses.POST, "http://target:5000/admin/login", json={}, status=401)
    log_path = str(tmp_path / "events.jsonl")

    result = run_red_action(
        "http://target:5000",
        raw={"method": "POST", "path": "/admin/login", "data": {"username": "x", "password": "y"}},
        event_log_path=log_path,
    )

    assert result["status_code"] == 401
    logged = json.loads(Path(log_path).read_text().splitlines()[0])
    assert logged["request"]["path"] == "/admin/login"


def test_run_red_action_requires_template_or_raw(tmp_path):
    result = run_red_action("http://target:5000", event_log_path=str(tmp_path / "events.jsonl"))
    assert "error" in result


@responses.activate
def test_run_red_action_command_injection_hitting_diagnostics_sets_found_it(tmp_path):
    responses.add(responses.POST, "http://target:5000/admin/diagnostics", json={"output": "uid=0"}, status=200)
    log_path = str(tmp_path / "events.jsonl")

    result = run_red_action("http://target:5000", template_name="command_injection", event_log_path=log_path)

    assert result["found_it"] is True


@responses.activate
def test_run_red_action_sqli_does_not_set_found_it_even_on_200(tmp_path):
    # found_it mirrors the referee's own red-win shape (host access via
    # /admin/diagnostics specifically), not "any successful request."
    responses.add(responses.GET, "http://target:5000/search", json={"results": []}, status=200)
    log_path = str(tmp_path / "events.jsonl")

    result = run_red_action("http://target:5000", template_name="sqli", event_log_path=log_path)

    assert result["found_it"] is False


@responses.activate
def test_run_blue_action_block_ip_attaches_token_and_logs_event(tmp_path):
    responses.add(
        responses.POST, "http://target:5000/internal/block-ip",
        json={"blocked_ip": "10.0.0.5"}, status=200,
        match=[responses.matchers.header_matcher({"X-Internal-Action-Token": "secret-token"})],
    )
    log_path = str(tmp_path / "events.jsonl")

    result = run_blue_action(
        "http://target:5000", "secret-token", action="block_ip", target="10.0.0.5",
        event_log_path=log_path,
    )

    assert result["status_code"] == 200
    assert result["found_it"] is True
    logged = json.loads(Path(log_path).read_text().splitlines()[0])
    assert logged["side"] == "blue"
    assert logged["actor"] == "human"
    assert logged["phase"] == "escalation"
    assert logged["action"] == "block_ip"


@responses.activate
def test_run_blue_action_error_response_does_not_set_found_it(tmp_path):
    responses.add(responses.POST, "http://target:5000/internal/block-ip", json={"error": "bad ip"}, status=400)
    log_path = str(tmp_path / "events.jsonl")

    result = run_blue_action(
        "http://target:5000", "secret-token", action="block_ip", target="not-an-ip",
        event_log_path=log_path,
    )

    assert result["found_it"] is False


def test_run_blue_action_rejects_unknown_action(tmp_path):
    result = run_blue_action(
        "http://target:5000", "secret-token", action="not_real", target="x",
        event_log_path=str(tmp_path / "events.jsonl"),
    )
    assert "error" in result
```

Add `responses` to the project's test dependencies if not already present (check `requirements.txt`/`Pipfile`; if `responses` isn't listed, add it alongside the existing `pytest`/`requests` entries -- it's a standard HTTP-mocking library, already implied by this project's own test conventions of not hitting real network calls in unit tests).

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest dashboard/tests/test_actions.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dashboard.actions'`.

- [ ] **Step 3: Implement**

Create `dashboard/actions.py`:

```python
import requests

from shared.event_log import log_event

RED_TEMPLATES = {
    "sqli": {
        "method": "GET", "path": "/search",
        "params": {"q": "' OR '1'='1"}, "data": None,
    },
    "bruteforce": {
        "method": "POST", "path": "/admin/login",
        "params": None, "data": {"username": "admin", "password": "admin123"},
    },
    "idor": {
        "method": "GET", "path": "/documents/1",
        "params": None, "data": None,
    },
    "command_injection": {
        "method": "POST", "path": "/admin/diagnostics",
        "params": None, "data": {"host": "8.8.8.8; id"},
    },
}

BLUE_ACTION_ENDPOINTS = {
    "lock_account": ("/internal/lock-account", "username"),
    "kill_session": ("/internal/kill-session", "user_id"),
    "block_ip": ("/internal/block-ip", "source_ip"),
}


def _do_request(base_url: str, method: str, path: str, params=None, data=None, headers=None) -> dict:
    url = f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
    try:
        resp = requests.request(method.upper(), url, params=params, data=data,
                                 headers=headers or {}, timeout=10.0)
    except requests.RequestException as exc:
        return {"error": str(exc)}
    return {
        "status_code": resp.status_code,
        "body": resp.text[:2000],
    }


def run_red_action(target_base_url: str, template_name: str = None, raw: dict = None,
                    event_log_path: str = None) -> dict:
    if template_name:
        tpl = RED_TEMPLATES.get(template_name)
        if tpl is None:
            return {"error": f"unknown template {template_name}"}
        method, path, params, data = tpl["method"], tpl["path"], tpl["params"], tpl["data"]
    elif raw:
        method, path = raw["method"], raw["path"]
        params, data = raw.get("params"), raw.get("data")
    else:
        return {"error": "template_name or raw is required"}

    result = _do_request(target_base_url, method, path, params=params, data=data)
    # Cosmetic "found it" detector (base spec): mirrors referee/monitor.py's
    # own red_has_host_access shape (path == /admin/diagnostics, status 200)
    # so a human reproducing that exact pattern gets the same signal an
    # autonomous red win would produce -- but this never touches stop.flag
    # or round state, purely a UI toast trigger.
    result["found_it"] = path == "/admin/diagnostics" and result.get("status_code") == 200
    log_event(event_log_path, {
        "side": "red", "actor": "human", "phase": "http_request",
        "request": {"method": method, "path": path, "params": params, "data": data},
        "response": result,
    })
    return result


def run_blue_action(target_base_url: str, internal_action_token: str, action: str, target: str,
                     event_log_path: str = None) -> dict:
    endpoint = BLUE_ACTION_ENDPOINTS.get(action)
    if endpoint is None:
        return {"error": f"unknown action {action}"}
    path, field = endpoint

    result = _do_request(
        target_base_url, "POST", path, data={field: target},
        headers={"X-Internal-Action-Token": internal_action_token},
    )
    # Cosmetic "found it" for blue: this action actually succeeded against
    # target (the same "escalation landed" shape blue_agent's own decisive
    # win is built from), not just "a response came back."
    status = result.get("status_code")
    result["found_it"] = status is not None and 200 <= status < 300
    log_event(event_log_path, {
        "side": "blue", "actor": "human", "phase": "escalation",
        "action": action, "target": target, "response": result,
    })
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest dashboard/tests/test_actions.py -v`
Expected: all 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add dashboard/actions.py dashboard/tests/test_actions.py requirements.txt
git commit -m "feat: dashboard manual red/blue action dispatch"
```

---

### Task 6: `dashboard/advisor.py`

**Files:**
- Create: `dashboard/advisor.py`
- Test: `dashboard/tests/test_advisor.py`

**Interfaces:**
- Consumes: `shared/event_log.py::read_events(log_path)`.
- Produces: `ask_advisor(ollama_host, ollama_model, question, event_log_path, advisor_log_path) -> dict` returning `{"answer": str}` or `{"error": str}`; every call appends `{"question": ..., "answer": ...}` to `advisor_log_path` (never to `referee_log_path` -- advisory text must never be mistaken for a referee verdict).

- [ ] **Step 1: Write the failing tests**

Create `dashboard/tests/test_advisor.py`:

```python
import json
from pathlib import Path

import responses

from dashboard.advisor import ask_advisor


@responses.activate
def test_ask_advisor_returns_model_answer_and_logs_it(tmp_path):
    responses.add(
        responses.POST, "http://ollama:11434/api/chat",
        json={"message": {"content": "Try blocking the source IP."}}, status=200,
    )
    event_log = str(tmp_path / "events.jsonl")
    advisor_log = str(tmp_path / "advisor.jsonl")
    Path(event_log).write_text('{"side": "red", "phase": "http_request"}\n')

    result = ask_advisor("http://ollama:11434", "qwen2.5:7b", "What should blue do?", event_log, advisor_log)

    assert result == {"answer": "Try blocking the source IP."}
    logged = json.loads(Path(advisor_log).read_text().splitlines()[0])
    assert logged == {"question": "What should blue do?", "answer": "Try blocking the source IP."}


@responses.activate
def test_ask_advisor_surfaces_ollama_errors_instead_of_swallowing(tmp_path):
    responses.add(responses.POST, "http://ollama:11434/api/chat", status=500)
    event_log = str(tmp_path / "events.jsonl")
    advisor_log = str(tmp_path / "advisor.jsonl")

    result = ask_advisor("http://ollama:11434", "qwen2.5:7b", "hi", event_log, advisor_log)

    assert "error" in result
    assert not Path(advisor_log).exists()


def test_ask_advisor_never_writes_to_referee_log(tmp_path):
    # Regression guard: advisor_log_path and referee_log_path must stay
    # separate files -- this test just asserts the function signature has
    # no referee_log_path parameter at all (a TypeError here means someone
    # tried to reuse the referee's own log for advisory text).
    import inspect
    assert "referee_log_path" not in inspect.signature(ask_advisor).parameters
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest dashboard/tests/test_advisor.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dashboard.advisor'`.

- [ ] **Step 3: Implement**

Create `dashboard/advisor.py`:

```python
import json
from pathlib import Path

import requests

from shared.event_log import read_events

ADVISOR_SYSTEM_PROMPT = (
    "You are a purple-team advisor observing a live red-vs-blue security "
    "exercise. Answer the operator's question using the recent event log "
    "context provided. You are advisory only -- you never take actions, "
    "you only explain and suggest."
)


def ask_advisor(ollama_host: str, ollama_model: str, question: str,
                 event_log_path: str, advisor_log_path: str) -> dict:
    recent_events = read_events(event_log_path)[-30:]
    context = json.dumps(recent_events)

    try:
        resp = requests.post(
            f"{ollama_host}/api/chat",
            json={
                "model": ollama_model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": ADVISOR_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Recent events:\n{context}\n\nQuestion: {question}"},
                ],
            },
            timeout=30.0,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {"error": str(exc)}

    answer = resp.json().get("message", {}).get("content", "")

    p = Path(advisor_log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps({"question": question, "answer": answer}) + "\n")

    return {"answer": answer}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest dashboard/tests/test_advisor.py -v`
Expected: all 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add dashboard/advisor.py dashboard/tests/test_advisor.py
git commit -m "feat: dashboard purple-team advisor (read-only Ollama query)"
```

---

### Task 7: Wire `dashboard/app.py` routes + found-it detector + banner data

**Files:**
- Modify: `dashboard/app.py`
- Test: `dashboard/tests/test_app.py`

**Interfaces:**
- Consumes: `dashboard.round_control.{clear_flags,stop_round,restart_round}`, `dashboard.actions.{run_red_action,run_blue_action}`, `dashboard.advisor.ask_advisor`.
- Produces: routes `POST /api/round/start`, `POST /api/round/stop`, `POST /api/round/restart`, `POST /api/red-action`, `POST /api/blue-action`, `POST /api/advisor`; `/api/state`'s JSON gains a `"latest_round_result"` key (the most recent `round_over` assessment, or `null`).

- [ ] **Step 1: Write the failing tests**

Create `dashboard/tests/test_app.py`:

```python
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from dashboard.app import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENT_LOG_PATH", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("REFEREE_LOG_PATH", str(tmp_path / "assessments.jsonl"))
    monkeypatch.setenv("REFEREE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("TARGET_BASE_URL", "http://target:5000")
    monkeypatch.setenv("INTERNAL_ACTION_TOKEN", "secret-token")
    monkeypatch.setenv("ROUND_HELPER_URL", "http://round_helper:8090")
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setenv("ADVISOR_LOG_PATH", str(tmp_path / "advisor.jsonl"))
    return create_app()


def test_api_state_reports_latest_round_result(app):
    Path(app.config["REFEREE_LOG_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    with open(app.config["REFEREE_LOG_PATH"], "w") as f:
        f.write(json.dumps({"phase": "go_signal", "side": "white"}) + "\n")
        f.write(json.dumps({"phase": "round_over", "side": "white", "outcome": "blue", "elapsed_seconds": 12.5}) + "\n")

    response = app.test_client().get("/api/state")

    assert response.get_json()["latest_round_result"] == {"outcome": "blue", "elapsed_seconds": 12.5}


def test_api_state_latest_round_result_is_null_when_no_round_has_ended(app):
    response = app.test_client().get("/api/state")
    assert response.get_json()["latest_round_result"] is None


def test_round_stop_endpoint_touches_stop_flag(app):
    response = app.test_client().post("/api/round/stop")
    assert response.status_code == 200
    assert Path(app.config["REFEREE_STATE_DIR"], "stop.flag").exists()


def test_round_restart_endpoint_calls_round_helper(app):
    with patch("dashboard.app.restart_round") as mock_restart:
        mock_restart.return_value = {"restarted": ["referee", "red_agent", "blue_agent"]}
        response = app.test_client().post("/api/round/restart")

    assert response.status_code == 200
    mock_restart.assert_called_once_with("http://round_helper:8090")


def test_red_action_endpoint_delegates_to_run_red_action(app):
    with patch("dashboard.app.run_red_action") as mock_run:
        mock_run.return_value = {"status_code": 200, "body": "ok"}
        response = app.test_client().post("/api/red-action", json={"template_name": "sqli"})

    assert response.status_code == 200
    mock_run.assert_called_once()


def test_blue_action_endpoint_delegates_to_run_blue_action(app):
    with patch("dashboard.app.run_blue_action") as mock_run:
        mock_run.return_value = {"status_code": 200, "body": "ok"}
        response = app.test_client().post("/api/blue-action", json={"action": "block_ip", "target": "10.0.0.5"})

    assert response.status_code == 200
    mock_run.assert_called_once()


def test_advisor_endpoint_delegates_to_ask_advisor(app):
    with patch("dashboard.app.ask_advisor") as mock_ask:
        mock_ask.return_value = {"answer": "block it"}
        response = app.test_client().post("/api/advisor", json={"question": "what now?"})

    assert response.status_code == 200
    assert response.get_json() == {"answer": "block it"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest dashboard/tests/test_app.py -v`
Expected: FAIL -- routes don't exist yet (404s) and `create_app` doesn't take env-driven config the same way yet.

- [ ] **Step 3: Implement**

Rewrite `dashboard/app.py` (keep `read_jsonl_tail` as-is; replace the rest):

```python
import os

from flask import Flask, jsonify, render_template_string, request

from dashboard.actions import run_blue_action, run_red_action
from dashboard.advisor import ask_advisor
from dashboard.page import PAGE
from dashboard.round_control import clear_flags, restart_round, stop_round


def read_jsonl_tail(path: str, limit: int) -> list:
    from pathlib import Path
    import json
    p = Path(path)
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["EVENT_LOG_PATH"] = os.environ.get("EVENT_LOG_PATH", "/app/shared_logs/events.jsonl")
    app.config["REFEREE_LOG_PATH"] = os.environ.get("REFEREE_LOG_PATH", "/app/referee_logs/referee_assessments.jsonl")
    app.config["REFEREE_STATE_DIR"] = os.environ.get("REFEREE_STATE_DIR", "/app/referee_state")
    app.config["TARGET_BASE_URL"] = os.environ.get("TARGET_BASE_URL", "http://target:5000")
    app.config["INTERNAL_ACTION_TOKEN"] = os.environ.get("INTERNAL_ACTION_TOKEN")
    app.config["ROUND_HELPER_URL"] = os.environ.get("ROUND_HELPER_URL", "http://round_helper:8090")
    app.config["OLLAMA_HOST"] = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434")
    app.config["OLLAMA_MODEL"] = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
    app.config["ADVISOR_LOG_PATH"] = os.environ.get("ADVISOR_LOG_PATH", "/app/referee_logs/advisor_log.jsonl")
    MAX_EVENTS, MAX_ASSESSMENTS = 300, 100

    @app.route("/api/state")
    def api_state():
        events = read_jsonl_tail(app.config["EVENT_LOG_PATH"], MAX_EVENTS)
        assessments = read_jsonl_tail(app.config["REFEREE_LOG_PATH"], MAX_ASSESSMENTS)
        go_flag = os.path.exists(os.path.join(app.config["REFEREE_STATE_DIR"], "go.flag"))
        stop_flag = os.path.exists(os.path.join(app.config["REFEREE_STATE_DIR"], "stop.flag"))

        round_overs = [a for a in assessments if a.get("phase") == "round_over"]
        latest_round_result = None
        if round_overs:
            last = round_overs[-1]
            latest_round_result = {"outcome": last.get("outcome"), "elapsed_seconds": last.get("elapsed_seconds")}

        return jsonify({
            "round": {"go": go_flag, "stop": stop_flag},
            "red_events": [e for e in events if e.get("side") == "red"][-100:],
            "blue_events": [e for e in events if e.get("side") == "blue"][-100:],
            "assessments": assessments,
            "latest_round_result": latest_round_result,
        })

    @app.route("/api/round/start", methods=["POST"])
    def round_start():
        clear_flags(app.config["REFEREE_STATE_DIR"])
        return jsonify({"cleared": True})

    @app.route("/api/round/stop", methods=["POST"])
    def round_stop():
        return jsonify(stop_round(app.config["REFEREE_STATE_DIR"]))

    @app.route("/api/round/restart", methods=["POST"])
    def round_restart():
        return jsonify(restart_round(app.config["ROUND_HELPER_URL"]))

    @app.route("/api/red-action", methods=["POST"])
    def red_action():
        body = request.get_json(force=True)
        result = run_red_action(
            app.config["TARGET_BASE_URL"],
            template_name=body.get("template_name"),
            raw=body.get("raw"),
            event_log_path=app.config["EVENT_LOG_PATH"],
        )
        return jsonify(result)

    @app.route("/api/blue-action", methods=["POST"])
    def blue_action():
        body = request.get_json(force=True)
        result = run_blue_action(
            app.config["TARGET_BASE_URL"],
            app.config["INTERNAL_ACTION_TOKEN"],
            action=body.get("action"),
            target=body.get("target"),
            event_log_path=app.config["EVENT_LOG_PATH"],
        )
        return jsonify(result)

    @app.route("/api/advisor", methods=["POST"])
    def advisor():
        body = request.get_json(force=True)
        result = ask_advisor(
            app.config["OLLAMA_HOST"], app.config["OLLAMA_MODEL"], body.get("question", ""),
            app.config["EVENT_LOG_PATH"], app.config["ADVISOR_LOG_PATH"],
        )
        return jsonify(result)

    @app.route("/")
    def index():
        return render_template_string(PAGE)

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
```

Create a placeholder-free minimal `dashboard/page.py` for now (Task 8 replaces its contents with the real frontend):

```python
PAGE = "<!doctype html><html><body>placeholder, replaced in Task 8</body></html>"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest dashboard/tests/test_app.py -v`
Expected: all 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add dashboard/app.py dashboard/page.py dashboard/tests/test_app.py
git commit -m "feat: wire dashboard round-control/action/advisor routes, add result banner data"
```

---

### Task 8: Functional frontend -- new tabs, forms, banner

**Files:**
- Modify: `dashboard/page.py`

**Interfaces:**
- Consumes: `/api/state`'s `latest_round_result`; `/api/round/{start,stop,restart}`, `/api/red-action`, `/api/blue-action`, `/api/advisor` (Task 7).
- Produces: a working (not yet visually polished -- Task 9 handles that) UI with 4 tabs (Red/Blue/White/Advisor), a manual-attack form on the Red tab, a manual-defend form on the Blue tab, a question box on the Advisor tab, round Start/Stop/Restart buttons, and a persistent result banner.

- [ ] **Step 1: Replace `dashboard/page.py` with the working template**

This extends the existing `PAGE` content from before this plan (tabs, event rendering, `tick()` polling) with the new controls. Full replacement:

```python
PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Purple Team Live View</title>
<style>
  :root { color-scheme: dark; }
  body { background: #0d0d0d; color: #c3c2b7; font-family: system-ui, sans-serif; margin: 0; }
  header { padding: 14px 24px; display: flex; align-items: center; gap: 16px; }
  #result-banner { padding: 8px 24px; font-size: 13px; }
  .hidden { display: none; }
  #found-it-toast { position: fixed; bottom: 20px; right: 20px; padding: 12px 20px; background: #0ca30c; color: #fff; border-radius: 6px; }
  nav.tabs button { padding: 10px 16px; }
  nav.tabs button.active { color: #fff; }
  .panel { display: none; padding: 20px; }
  .panel.active { display: block; }
  .ev { padding: 8px 0; border-bottom: 1px solid #2c2c2a; }
  form.action-form { display: flex; flex-direction: column; gap: 8px; max-width: 480px; margin-bottom: 20px; }
  #advisor-answer { white-space: pre-wrap; margin-top: 12px; }
</style>
</head>
<body>
<header>
  <h1>Purple Team Live View</h1>
  <span id="round-badge">loading...</span>
  <button id="btn-start">Start Round</button>
  <button id="btn-stop">Stop Round</button>
  <button id="btn-restart">Restart Round</button>
</header>
<div id="result-banner" class="hidden"></div>
<div id="found-it-toast" class="hidden"></div>
<nav class="tabs">
  <button data-team="red" class="active">Red Team</button>
  <button data-team="blue">Blue Team</button>
  <button data-team="white">White Team (Referee)</button>
  <button data-team="advisor">Purple Advisor</button>
</nav>
<main>
  <div id="panel-red" class="panel active">
    <form class="action-form" id="red-template-form">
      <label>Attack template
        <select name="template_name">
          <option value="sqli">SQL injection (/search)</option>
          <option value="bruteforce">Login bruteforce (/admin/login)</option>
          <option value="idor">IDOR (/documents/1)</option>
          <option value="command_injection">Command injection (/admin/diagnostics)</option>
        </select>
      </label>
      <button type="submit">Fire</button>
    </form>
    <div id="events-red"></div>
  </div>
  <div id="panel-blue" class="panel">
    <form class="action-form" id="blue-action-form">
      <label>Action
        <select name="action">
          <option value="lock_account">Lock account (username)</option>
          <option value="kill_session">Kill session (user_id)</option>
          <option value="block_ip">Block IP (source_ip)</option>
        </select>
      </label>
      <label>Target value <input type="text" name="target" required></label>
      <button type="submit">Defend</button>
    </form>
    <div id="events-blue"></div>
  </div>
  <div id="panel-white" class="panel"><div id="events-white"></div></div>
  <div id="panel-advisor" class="panel">
    <form class="action-form" id="advisor-form">
      <label>Ask the purple-team advisor
        <input type="text" name="question" required placeholder="What should blue do right now?">
      </label>
      <button type="submit">Ask</button>
    </form>
    <div id="advisor-answer"></div>
  </div>
</main>
<script>
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function renderEvent(e) {
  const content = e.content || e.action || e.reasoning || e.error || JSON.stringify(e);
  const actorTag = e.actor === 'human' ? ' [human]' : '';
  return `<div class="ev">${esc(e.phase || 'event')}${actorTag}: ${esc(String(content)).slice(0,1000)}</div>`;
}
function renderResultBanner(result) {
  const banner = document.getElementById('result-banner');
  if (!result) { banner.className = 'hidden'; return; }
  const who = { blue: 'Blue won', red: 'Red won', budget_expired: 'Round timed out' }[result.outcome] || result.outcome;
  banner.textContent = `Last round: ${who} (${Math.round(result.elapsed_seconds || 0)}s)`;
  banner.className = '';
}
async function tick() {
  try {
    const res = await fetch('/api/state');
    const data = await res.json();
    document.getElementById('round-badge').textContent =
      data.round.stop ? 'STOPPED' : data.round.go ? 'ROUND LIVE' : 'IDLE';
    renderResultBanner(data.latest_round_result);
    document.getElementById('events-red').innerHTML = data.red_events.map(renderEvent).join('');
    document.getElementById('events-blue').innerHTML = data.blue_events.map(renderEvent).join('');
    document.getElementById('events-white').innerHTML = data.assessments.map(renderEvent).join('');
  } catch (err) { console.error(err); }
}

for (const btn of document.querySelectorAll('nav.tabs button')) {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav.tabs button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.team).classList.add('active');
  });
}
document.getElementById('btn-start').addEventListener('click', () => fetch('/api/round/start', { method: 'POST' }));
document.getElementById('btn-stop').addEventListener('click', () => fetch('/api/round/stop', { method: 'POST' }));
document.getElementById('btn-restart').addEventListener('click', () => fetch('/api/round/restart', { method: 'POST' }));

function showFoundItToast(side) {
  const toast = document.getElementById('found-it-toast');
  toast.textContent = `Found it! Your ${side} action reproduced a win-condition result.`;
  toast.className = '';
  setTimeout(() => { toast.className = 'hidden'; }, 4000);
}

document.getElementById('red-template-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const template_name = new FormData(ev.target).get('template_name');
  const res = await fetch('/api/red-action', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ template_name }),
  });
  const data = await res.json();
  if (data.found_it) showFoundItToast('red');
  tick();
});
document.getElementById('blue-action-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const res = await fetch('/api/blue-action', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: fd.get('action'), target: fd.get('target') }),
  });
  const data = await res.json();
  if (data.found_it) showFoundItToast('blue');
  tick();
});
document.getElementById('advisor-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const question = new FormData(ev.target).get('question');
  const res = await fetch('/api/advisor', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question }),
  });
  const data = await res.json();
  document.getElementById('advisor-answer').textContent = data.answer || data.error || '';
});

tick();
setInterval(tick, 2000);
</script>
</body>
</html>
"""
```

- [ ] **Step 2: Manual acceptance check**

Run: `docker compose up -d --build purple_dashboard round_helper` from the repo root, then in a browser: confirm all 4 tabs switch, firing a red template logs an event tagged `[human]` in the Red tab, firing a blue action against a real `target` returns a result, asking the advisor returns text, and Start/Stop/Restart buttons change the round badge and (for Restart) bring back exited containers.

- [ ] **Step 3: Commit**

```bash
git add dashboard/page.py
git commit -m "feat: functional frontend for manual actions, advisor, and round control"
```

---

### Task 9: UI design pass

**Files:**
- Modify: `dashboard/page.py`

**Interfaces:**
- Consumes: the working markup/JS from Task 8 (structure and IDs stay the same so the JS wiring keeps working; only visual treatment -- CSS, layout, typography -- changes).
- Produces: a visually designed version of the same page, dark theme, red/blue/white color coding preserved.

- [ ] **Step 1: Invoke the design skill**

Use the `ui-ux-pro-max` (or `frontend-design`) skill to produce a real design pass on `dashboard/page.py`'s `<style>` block and markup structure: typography scale, spacing system, visual hierarchy for the header/banner/tabs/forms/event feed, consistent with a dark "live ops board" aesthetic. Keep every existing `id`/`data-team`/form `name` attribute the JS in Task 8 depends on -- this is a visual pass, not a markup-contract change.

- [ ] **Step 2: Manual visual review**

Run: `docker compose up -d --build purple_dashboard`, open `http://localhost:8080`, confirm: all 4 tabs render with clear visual hierarchy, the result banner is visually prominent (not just a plain text line), forms are legibly laid out, and the red/blue/white color coding is visually consistent across tabs, badges, and event entries.

- [ ] **Step 3: Regression check**

Run: `pytest dashboard/ -v`
Expected: all tests still PASS (this task only touches `dashboard/page.py`'s presentation; Task 7/8's Python-side tests don't inspect its content).

- [ ] **Step 4: Commit**

```bash
git add dashboard/page.py
git commit -m "style: real design pass on the dashboard UI"
```

---

## Manual Acceptance Criterion (full plan)

Once all 9 tasks are complete: `docker compose up -d --build` the whole stack, confirm a full live click-through -- round start -> manual red attack -> manual blue response -> advisor question -> "found it" toast (if separately scoped; otherwise the banner) -> round stop -> restart from fully-stopped -- all from the dashboard alone, no terminal access needed.
