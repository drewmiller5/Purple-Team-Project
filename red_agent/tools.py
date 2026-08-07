# red_agent/tools.py
import json

# K5: enforced recon-before-attack phase gate. Only one real target-facing
# tool exists (http_request), so classification happens on the request
# shape rather than a separate tool name: any state-changing POST, or any
# GET carrying an injection-shaped payload (matching the same SQLi/command-
# injection payload classes the seeded vulns use), counts as attack-class.
# A plain GET with no such markers is recon-class and opens the gate.
_ATTACK_INDICATORS = (
    "'", "--", " or ", " and ", ";", "|", "&&", "`", "$(", "%0a", "%0d", "../", "union", "select",
)
# ponytail: substring matching (not word-boundary/regex), so a benign value
# that happens to contain a marker (e.g. a path literally named
# "/select-plan") is misclassified attack-class and blocked pre-recon.
# Self-recovering (the agent just tries a different plain GET next), so left
# as-is -- upgrade to a regex with word boundaries if false positives prove
# disruptive in practice.

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send an HTTP request to the target application and see the response.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST"]},
                    "path": {"type": "string", "description": "URL path to request, e.g. /"},
                    "params": {"type": "object", "description": "Query string parameters for GET"},
                    "data": {"type": "object", "description": "Form body fields for POST"},
                },
                "required": ["method", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_finding",
            "description": "Record a confirmed discovery (vulnerability, credential, or access level) to memory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {"type": "string"},
                    "detail": {"type": "string"},
                    "success": {"type": "boolean"},
                },
                "required": ["category", "detail", "success"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "recall_past_findings",
            "description": "Get a summary of findings recorded in previous runs, to avoid repeating failed attempts.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


def _is_attack_class(method: str, path: str, params: dict | None, data: dict | None) -> bool:
    if str(method).upper() != "GET":
        return True
    haystack = " ".join(
        str(v) for v in [path, *(params or {}).values(), *(data or {}).values()]
    ).lower()
    return any(marker in haystack for marker in _ATTACK_INDICATORS)


def dispatch_tool_call(call: dict, http, state) -> str:
    name = call["function"]["name"]
    args = call["function"].get("arguments", {})
    if isinstance(args, str):
        args = json.loads(args) if args else {}

    if name == "http_request":
        try:
            method = args["method"]
            path = args["path"]
        except KeyError as exc:
            return json.dumps({"error": f"missing or invalid arguments for {name}: {exc}"})
        params = args.get("params")
        data = args.get("data")
        is_attack = _is_attack_class(method, path, params, data)

        if is_attack and not state.recon_done:
            return json.dumps({
                "error": (
                    "phase gate: at least one recon-class request (a plain "
                    "GET with no injection-shaped payload) is required "
                    "before an attack-class request is permitted"
                ),
            })

        result = http.request(method=method, path=path, params=params, data=data)
        if not is_attack:
            state.recon_done = True
        state.log_event({"phase": "http_request", "request": args, "response": result})
        return json.dumps(result)

    if name == "record_finding":
        try:
            category = args["category"]
            detail = args["detail"]
            success = args["success"]
        except KeyError as exc:
            return json.dumps({"error": f"missing or invalid arguments for {name}: {exc}"})
        state.record_finding(category, detail, success)
        return json.dumps({"recorded": True})

    if name == "recall_past_findings":
        summary = state.recall_summary()
        return summary if summary else "No prior findings."

    return json.dumps({"error": f"unknown tool {name}"})
