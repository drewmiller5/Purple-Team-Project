# red_agent/tools.py
import json

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
                    "path": {"type": "string", "description": "URL path, e.g. /search or /admin/login"},
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


def dispatch_tool_call(call: dict, http, state) -> str:
    name = call["function"]["name"]
    args = call["function"].get("arguments", {})
    if isinstance(args, str):
        args = json.loads(args) if args else {}

    if name == "http_request":
        result = http.request(
            method=args["method"],
            path=args["path"],
            params=args.get("params"),
            data=args.get("data"),
        )
        state.log_event({"phase": "http_request", "request": args, "response": result})
        return json.dumps(result)

    if name == "record_finding":
        state.record_finding(args["category"], args["detail"], args["success"])
        return json.dumps({"recorded": True})

    if name == "recall_past_findings":
        summary = state.recall_summary()
        return summary if summary else "No prior findings."

    return json.dumps({"error": f"unknown tool {name}"})
