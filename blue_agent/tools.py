import ipaddress
import json
import socket

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "escalate_response",
            "description": (
                "Take a real defensive action against a specific attacker identifier "
                "that Wazuh's automatic response has not yet handled, or that you "
                "judge needs a stronger response than Wazuh already took."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["lock_account", "kill_session", "block_ip"],
                    },
                    "target": {
                        "type": "string",
                        "description": (
                            "username for lock_account, numeric user_id for "
                            "kill_session, source IP for block_ip"
                        ),
                    },
                },
                "required": ["action", "target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "recall_past_findings",
            "description": "Get a summary of decisions recorded in previous runs, to avoid repeating them.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]

_ACTION_ENDPOINTS = {
    "lock_account": ("/internal/lock-account", "username"),
    "kill_session": ("/internal/kill-session", "user_id"),
    "block_ip": ("/internal/block-ip", "source_ip"),
}


def _protected_block_ip_targets():
    """Infra/self identities blue_agent must never be tricked into
    blocking, even if attacker-influenced alert content (H3) manipulates
    the model into asking for it. Defense in depth alongside target's own
    equivalent check (H2) -- blue_agent shouldn't rely solely on the
    downstream endpoint to catch this.
    """
    hostnames = ("target", "wazuh.manager", "blue_agent", socket.gethostname())
    # Both the literal hostnames and their resolved IPs are protected: the
    # model sees these hostnames in its own system prompt/alert data and
    # could plausibly be manipulated into naming one directly as `target`,
    # not just its IP.
    protected = {"127.0.0.1", *hostnames}
    for hostname in hostnames:
        try:
            protected.add(socket.gethostbyname(hostname))
        except socket.gaierror:
            continue
    return protected


def _is_protected_block_ip_target(target: str) -> bool:
    try:
        if ipaddress.IPv4Address(target).is_loopback:
            return True
    except ValueError:
        pass
    return target in _protected_block_ip_targets()


# H51 (2026-08-01 user decision): a narrower check than a full app-level
# infra-identity concept -- reject lock_account/kill_session calls that
# target the one seeded privileged account specifically, mirroring
# block_ip's own hardcoded-identifier pattern above rather than
# fabricating identity semantics that don't exist elsewhere in the
# codebase. lock_account targets by username ("admin" directly);
# kill_session targets by numeric user_id -- admin is seeded first in
# target/db.py's AUTOINCREMENT users table, so its user_id is
# deterministically 1 for any fresh deployment.
def _is_protected_account_target(action: str, target: str) -> bool:
    # Security-review-flagged bypass: comparing the raw, un-normalized
    # target string against a literal ("admin" / "1") missed that
    # target's own server-side endpoints normalize before matching --
    # lock_account strips whitespace, kill_session parses via Python's
    # int(). " admin", "01", " 1", "+1", "1\n" all land on the real
    # admin account server-side while never being byte-identical to the
    # literal this check used to compare against. Normalize the same way
    # the server does before comparing, so the check can't be dodged by
    # a formatting variant a model could plausibly produce.
    if action == "lock_account":
        return target.strip() == "admin"
    if action == "kill_session":
        try:
            return int(target) == 1
        except ValueError:
            return False
    return False


def dispatch_tool_call(call: dict, http, state) -> str:
    name = call["function"]["name"]
    args = call["function"].get("arguments", {})
    if isinstance(args, str):
        args = json.loads(args) if args else {}

    if name == "escalate_response":
        try:
            action = args["action"]
            target = args["target"]
        except KeyError as exc:
            return json.dumps({"error": f"missing or invalid arguments for {name}: {exc}"})

        endpoint = _ACTION_ENDPOINTS.get(action)
        if endpoint is None:
            return json.dumps({"error": f"unknown action {action}"})

        if action == "block_ip" and _is_protected_block_ip_target(target):
            state.log_event({
                "phase": "escalation_rejected",
                "action": action,
                "target": target,
                "reason": "protected infrastructure target",
            })
            return json.dumps({"error": "target is protected infrastructure, refusing to dispatch"})

        # H23: format validation matching what target's server-side already
        # enforces (client-side defense-in-depth, same class of check the
        # protected-target check above already applies to this same action
        # set). lock_account's username has no server-side format check
        # beyond non-empty (H13); kill_session's user_id is validated
        # numeric server-side (request.form.get(..., type=int)).
        if action == "lock_account" and not target.strip():
            state.log_event({
                "phase": "escalation_rejected",
                "action": action,
                "target": target,
                "reason": "empty username",
            })
            return json.dumps({"error": "username is required, refusing to dispatch"})

        if action == "kill_session":
            try:
                int(target)
            except ValueError:
                state.log_event({
                    "phase": "escalation_rejected",
                    "action": action,
                    "target": target,
                    "reason": "non-numeric user_id",
                })
                return json.dumps({"error": "user_id must be numeric, refusing to dispatch"})

        if action in ("lock_account", "kill_session") and _is_protected_account_target(action, target):
            state.log_event({
                "phase": "escalation_rejected",
                "action": action,
                "target": target,
                "reason": "protected account target",
            })
            return json.dumps({"error": "target is a protected account, refusing to dispatch"})

        path, field = endpoint
        result = http.request(method="POST", path=path, data={field: target})
        state.log_event({"phase": "escalation", "action": action, "target": target, "response": result})
        # H20: record the action taken so blue_memory.json accumulates
        # history across runs and recall_past_findings has something to
        # surface -- previously record_finding had zero call sites outside
        # its own unit test. Success requires both no transport-level
        # "error" key AND a 2xx status -- a non-2xx response (bad token,
        # target-side failure) is a normal dict with no "error" key.
        status = result.get("status_code")
        succeeded = "error" not in result and status is not None and 200 <= status < 300
        state.record_finding(action, f"{action} on {target}", succeeded)
        return json.dumps(result)

    if name == "recall_past_findings":
        summary = state.recall_summary()
        return summary if summary else "No prior findings."

    return json.dumps({"error": f"unknown tool {name}"})
