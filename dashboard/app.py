import hmac
import os
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

from dashboard.actions import run_blue_action, run_red_action
from dashboard.advisor import ask_advisor
from dashboard.page import PAGE
from dashboard.round_control import clear_flags, start_round, stop_round


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


def read_jsonl_tail_excluding(path: str, limit: int, exclude_phases: set) -> list:
    """Like read_jsonl_tail, but scans backward from the end of the file and
    collects up to `limit` events whose phase isn't in exclude_phases. H69:
    reasoning and heartbeat turns are no longer budget-capped, so their
    volume can exceed any fixed raw-line window -- scanning until enough
    real events are found (or the file is exhausted) guarantees the tail
    actually contains `limit` real events regardless of how much noise
    precedes them, instead of picking an arbitrary raw-line constant that
    noise volume can outgrow."""
    p = Path(path)
    if not p.exists():
        return []
    import json
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict) or parsed.get("phase") in exclude_phases:
            continue
        out.append(parsed)
        if len(out) >= limit:
            break
    out.reverse()
    return out


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["EVENT_LOG_PATH"] = os.environ.get("EVENT_LOG_PATH", "/app/shared_logs/events.jsonl")
    app.config["REFEREE_LOG_PATH"] = os.environ.get("REFEREE_LOG_PATH", "/app/referee_logs/referee_assessments.jsonl")
    app.config["REFEREE_STATE_DIR"] = os.environ.get("REFEREE_STATE_DIR", "/app/referee_state")
    app.config["TARGET_BASE_URL"] = os.environ.get("TARGET_BASE_URL", "http://target:5000")
    app.config["INTERNAL_ACTION_TOKEN"] = os.environ.get("INTERNAL_ACTION_TOKEN")
    # H54: round_helper's own dedicated secret, distinct from
    # INTERNAL_ACTION_TOKEN (used above for target's /internal/* routes).
    app.config["ROUND_HELPER_TOKEN"] = os.environ.get("ROUND_HELPER_TOKEN")
    app.config["ROUND_HELPER_URL"] = os.environ.get("ROUND_HELPER_URL", "http://round_helper:8090")
    app.config["OLLAMA_HOST"] = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434")
    app.config["OLLAMA_MODEL"] = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
    app.config["ADVISOR_LOG_PATH"] = os.environ.get("ADVISOR_LOG_PATH", "/app/referee_logs/advisor_log.jsonl")
    app.config["DASHBOARD_AUTH_TOKEN"] = os.environ.get("DASHBOARD_AUTH_TOKEN")
    # H55: DASHBOARD_AUTH_TOKEN only proves "may view this dashboard" --
    # it used to also be the sole gate on firing a red action, firing a
    # blue action, and restarting the round's containers via
    # round_helper's docker.sock access, three separate privilege
    # domains behind one secret. Each now needs its own scoped token in
    # addition to DASHBOARD_AUTH_TOKEN, so a single leaked secret grants
    # at most one domain, never all three.
    app.config["DASHBOARD_RED_ACTION_TOKEN"] = os.environ.get("DASHBOARD_RED_ACTION_TOKEN")
    app.config["DASHBOARD_BLUE_ACTION_TOKEN"] = os.environ.get("DASHBOARD_BLUE_ACTION_TOKEN")
    app.config["DASHBOARD_INFRA_ACTION_TOKEN"] = os.environ.get("DASHBOARD_INFRA_ACTION_TOKEN")
    MAX_EVENTS, MAX_ASSESSMENTS = 300, 100
    # H69: reasoning and heartbeat events add no ledger value (heartbeats are
    # collapsed client-side; reasoning is logged for audit but isn't an
    # action) and neither is budget-capped anymore, so they're excluded from
    # what /api/state returns as red_events/blue_events via
    # read_jsonl_tail_excluding's scan-until-found approach.
    LEDGER_NOISE_PHASES = {"reasoning", "heartbeat"}

    # round_control.stop_round/clear_flags touch/unlink files under this dir
    # without creating it first -- ensure it exists so a fresh volume mount
    # (or a fresh tmp_path in tests) doesn't 500 on the first flag write.
    Path(app.config["REFEREE_STATE_DIR"]).mkdir(parents=True, exist_ok=True)

    @app.before_request
    def _require_dashboard_auth():
        # Confused-deputy guard: this app holds INTERNAL_ACTION_TOKEN server-side
        # and forwards it on the caller's behalf to target's internal routes, so
        # every route here -- including the index page -- must be gated, not just
        # the action routes. Fail closed: an unset/falsy configured token denies
        # all requests rather than silently letting them through. Mirrors
        # target/routes/internal.py's _is_authorized_internal_action() shape.
        expected = app.config.get("DASHBOARD_AUTH_TOKEN")
        auth = request.authorization
        supplied = auth.password if auth and auth.username == "operator" else None
        if not (expected and supplied and hmac.compare_digest(expected, supplied)):
            return "", 401, {"WWW-Authenticate": 'Basic realm="Purple Team Dashboard"'}

    def _require_action_token(config_key):
        # H55: fail-closed the same way the general auth gate does --
        # an unset configured token or a missing/wrong header both deny.
        # 403, not 401: the caller already passed the general dashboard
        # auth (else before_request would have stopped them at 401) but
        # lacks this specific domain's capability.
        expected = app.config.get(config_key)
        supplied = request.headers.get("X-Action-Token")
        if not (expected and supplied and hmac.compare_digest(expected, supplied)):
            return jsonify({"error": "missing or invalid action token for this capability"}), 403
        return None

    @app.route("/api/state")
    def api_state():
        # H69: reasoning/heartbeat events are logged for audit but must not
        # appear in the same ledger as real actions -- still on disk, just
        # not surfaced here.
        events = read_jsonl_tail_excluding(app.config["EVENT_LOG_PATH"], MAX_EVENTS, LEDGER_NOISE_PHASES)
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

    @app.route("/api/round/clear", methods=["POST"])
    def round_clear():
        # Real bug found live: this was previously mounted at /api/round/start
        # (a mislabel with zero test coverage) -- it clears go.flag/stop.flag,
        # it doesn't start anything. Collided with the real round-start
        # feature's route once that got wired up.
        clear_flags(app.config["REFEREE_STATE_DIR"])
        return jsonify({"cleared": True})

    @app.route("/api/round/stop", methods=["POST"])
    def round_stop():
        return jsonify(stop_round(app.config["REFEREE_STATE_DIR"]))

    @app.route("/api/round/start", methods=["POST"])
    def round_start():
        denied = _require_action_token("DASHBOARD_INFRA_ACTION_TOKEN")
        if denied:
            return denied

        # Hint mode (2026-08-12, upgraded to a 4-way off/red/blue/both
        # dropdown): round_helper only restarts existing containers, it
        # can't inject a new env var per round, so this is passed via
        # referee-state flag files instead (same shared-volume pattern as
        # go.flag/stop.flag) -- each agent checks for its own flag fresh on
        # every restart. Two independent flags, not one boolean, so either
        # side can be hinted without the other. Both explicitly cleared
        # when not selected so a prior round's mode can't silently leak
        # into this one (H27's same flag-leak lesson, applied here).
        body = request.get_json(silent=True) or {}
        state_dir = Path(app.config["REFEREE_STATE_DIR"])
        state_dir.mkdir(parents=True, exist_ok=True)
        hint_mode = body.get("hint_mode", "off")
        hint_mode_red_flag = state_dir / "hint_mode_red.flag"
        hint_mode_blue_flag = state_dir / "hint_mode_blue.flag"
        if hint_mode in ("red", "both"):
            hint_mode_red_flag.touch()
        else:
            hint_mode_red_flag.unlink(missing_ok=True)
        if hint_mode in ("blue", "both"):
            hint_mode_blue_flag.touch()
        else:
            hint_mode_blue_flag.unlink(missing_ok=True)

        # Memory toggle (2026-08-12): same mechanism/leak-prevention as the
        # hint_mode flags above. Defaults to memory ON (unset/true) --
        # `memory_enabled` must be explicitly False to disable it. Never
        # touches red_memory.json/blue_memory.json themselves, only gates
        # state.py's recall_summary() via this flag file's presence.
        memory_disabled_flag = state_dir / "memory_disabled.flag"
        if body.get("memory_enabled", True):
            memory_disabled_flag.unlink(missing_ok=True)
        else:
            memory_disabled_flag.touch()

        return jsonify(start_round(app.config["ROUND_HELPER_URL"], app.config["ROUND_HELPER_TOKEN"]))

    @app.route("/api/red-action", methods=["POST"])
    def red_action():
        denied = _require_action_token("DASHBOARD_RED_ACTION_TOKEN")
        if denied:
            return denied
        # or {} alone would mask a falsy-but-non-dict body (JSON `null`/`[]`)
        # as an empty dict; only treat a truly empty request body that way.
        body = request.get_json(force=True, silent=True) if request.get_data() else {}
        if not isinstance(body, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
        result = run_red_action(
            app.config["TARGET_BASE_URL"],
            template_name=body.get("template_name"),
            raw=body.get("raw"),
            event_log_path=app.config["EVENT_LOG_PATH"],
        )
        return jsonify(result)

    @app.route("/api/blue-action", methods=["POST"])
    def blue_action():
        denied = _require_action_token("DASHBOARD_BLUE_ACTION_TOKEN")
        if denied:
            return denied
        body = request.get_json(force=True, silent=True) if request.get_data() else {}
        if not isinstance(body, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
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
        body = request.get_json(force=True, silent=True) if request.get_data() else {}
        if not isinstance(body, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
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
