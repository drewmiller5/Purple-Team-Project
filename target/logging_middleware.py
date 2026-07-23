import json
import time
from pathlib import Path

from flask import g, request

DEFAULT_LOG_PATH = "target/logs/requests.jsonl"


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
    def _log_request(response):
        entry = {
            "timestamp": time.time(),
            "remote_addr": request.remote_addr,
            "method": request.method,
            "path": request.path,
            "query_params": _redact_params(request.args.to_dict()),
            "form_params": _redact_params(request.form.to_dict()),
            "status_code": response.status_code,
            "duration_ms": round((time.time() - g._start_time) * 1000, 2),
        }
        with open(app.config["REQUEST_LOG_PATH"], "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return response

    return app
