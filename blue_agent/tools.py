import json

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


def dispatch_tool_call(call: dict, http, state) -> str:
    name = call["function"]["name"]
    args = call["function"].get("arguments", {})
    if isinstance(args, str):
        args = json.loads(args) if args else {}

    if name == "escalate_response":
        action = args["action"]
        target = args["target"]
        endpoint = _ACTION_ENDPOINTS.get(action)
        if endpoint is None:
            return json.dumps({"error": f"unknown action {action}"})

        path, field = endpoint
        result = http.request(method="POST", path=path, data={field: target})
        state.log_event({"phase": "escalation", "action": action, "target": target, "response": result})
        return json.dumps(result)

    if name == "recall_past_findings":
        summary = state.recall_summary()
        return summary if summary else "No prior findings."

    return json.dumps({"error": f"unknown tool {name}"})
