import hmac
import os
from pathlib import Path

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
    app.config["DASHBOARD_AUTH_TOKEN"] = os.environ.get("DASHBOARD_AUTH_TOKEN")
    MAX_EVENTS, MAX_ASSESSMENTS = 300, 100
    # H69: reasoning-only turns are no longer capped by max_iterations, so a
    # chatty model can log far more of them per round than real actions.
    # Read a much larger raw-line window before filtering them out, so a
    # reasoning flood can't push real action events out of the tail before
    # the filter ever sees them.
    RAW_EVENT_READ_LIMIT = 5000

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

    @app.route("/api/state")
    def api_state():
        raw_events = read_jsonl_tail(app.config["EVENT_LOG_PATH"], RAW_EVENT_READ_LIMIT)
        # H69: reasoning turns are logged for audit but must not appear in the
        # same ledger as real actions -- still on disk, just not surfaced here.
        events = [e for e in raw_events if e.get("phase") != "reasoning"][-MAX_EVENTS:]
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
        return jsonify(restart_round(app.config["ROUND_HELPER_URL"], app.config["INTERNAL_ACTION_TOKEN"]))

    @app.route("/api/red-action", methods=["POST"])
    def red_action():
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
