import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import g, request, session

DEFAULT_LOG_PATH = "target/logs/requests.jsonl"

# Module-level lock serializing writes to the log file across concurrent
# requests (Flask's dev/threaded server can handle requests on multiple
# threads simultaneously; without this, interleaved writes could corrupt
# or merge JSON lines).
_log_write_lock = threading.Lock()


def _redact_params(params: dict) -> dict:
    return {
        key: ("[REDACTED]" if key.lower() == "password" else value)
        for key, value in params.items()
    }


def register_logging(app, log_path: str = None):
    log_path = log_path or DEFAULT_LOG_PATH
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    app.config["REQUEST_LOG_PATH"] = log_path

    @app.before_request
    def _start_timer():
        g._start_time = time.time()

    @app.after_request
    def _capture_status(response):
        # Stashed on g so teardown_request (which always runs, even after
        # an unhandled exception) can log the real status code on the
        # happy path. On the exception path this hook never runs, so
        # teardown_request falls back to 500 below.
        g._status_code = response.status_code
        return response

    @app.teardown_request
    def _log_request(exc):
        # teardown_request runs unconditionally -- even when a view raises
        # an unhandled exception and after_request is skipped -- so this is
        # the one place guaranteed to observe every request against this
        # deliberately-vulnerable app, crashes included.
        start_time = getattr(g, "_start_time", None)
        duration_ms = (
            round((time.time() - start_time) * 1000, 2)
            if start_time is not None
            else None
        )

        status_code = getattr(g, "_status_code", None)
        if exc is not None or status_code is None:
            status_code = 500

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remote_addr": request.remote_addr,
            # Duplicate of remote_addr under Wazuh's own reserved field name.
            # The generic JSON decoder (ruleset/decoders/0006-json_decoders.xml)
            # auto-populates Wazuh's static `srcip` field whenever a JSON log
            # contains a literal "srcip" key -- confirmed via wazuh-logtest
            # (Task 7 fix-round). Without this, `firewall-drop`'s Active
            # Response has nothing to read and fails with "Cannot read
            # 'srcip' from data", even though remote_addr is present under a
            # non-reserved key name.
            "srcip": request.remote_addr,
            "method": request.method,
            "path": request.path,
            "query_params": _redact_params(request.args.to_dict()),
            "form_params": _redact_params(request.form.to_dict()),
            "status_code": status_code,
            "duration_ms": duration_ms,
            # Authenticated principal for this request, pulled from the Flask
            # session (not a request attribute -- unauthenticated requests
            # log this as null). Makes the acting user available to Active
            # Response scripts like kill-session.sh, which parse it out of
            # the alert JSON to know which session to kill.
            "user_id": session.get("user_id"),
        }
        with _log_write_lock:
            with open(app.config["REQUEST_LOG_PATH"], "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    return app
