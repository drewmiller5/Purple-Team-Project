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

# Module-level session shared across all calls so a login's Set-Cookie
# (e.g. bruteforce -> /admin/login) carries over to a later call in the same
# escalation chain (e.g. command_injection -> /admin/diagnostics), same as
# red_agent/http_tool.py's HttpTool.session. Fine for a single-operator lab
# dashboard, not a multi-tenant service (security reviewer signed off).
_session = requests.Session()


def _do_request(base_url: str, method: str, path: str, params=None, data=None, headers=None) -> dict:
    url = f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
    try:
        resp = _session.request(method.upper(), url, params=params, data=data,
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
        method, path = raw.get("method"), raw.get("path")
        if not method or not path:
            return {"error": "raw must include method and path"}
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
    if target is None:
        return {"error": "target is required"}
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
