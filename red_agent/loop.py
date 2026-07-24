# red_agent/loop.py
from red_agent.http_tool import HttpTool
from red_agent.ollama_client import OllamaClient
from red_agent.state import RedAgentState
from red_agent.tools import TOOL_SCHEMAS, dispatch_tool_call

SYSTEM_PROMPT = """You are a red-team penetration testing agent attacking a
web application at {base_url}. You have NO advance knowledge of its
structure, its vulnerabilities, or its source code — you must discover
everything yourself through reconnaissance using the http_request tool.

Your goal: gain the deepest access possible. General categories of web
vulnerabilities to consider during recon: SQL injection, weak or default
credentials, missing authorization checks (IDOR, accessing resources by
guessing IDs), and OS command injection in any endpoint that seems to
shell out to the system (for example, a network diagnostics, file
conversion, or export feature).

Use record_finding whenever you confirm something works or definitively
fails. Use recall_past_findings at the start of a run to avoid repeating
attempts that already failed. On each turn, reason briefly about your
next single action, then call exactly one tool.
"""


def run(config) -> None:
    state = RedAgentState(config)
    http = HttpTool(config.target_base_url)
    ollama = OllamaClient(config.ollama_host, config.ollama_model)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT.format(base_url=config.target_base_url)}
    ]
    past = state.recall_summary()
    if past:
        messages.append({"role": "user", "content": f"Past findings from previous runs:\n{past}"})

    for _ in range(config.max_iterations):
        response = ollama.chat(messages=messages, tools=TOOL_SCHEMAS)
        assistant_message = response["message"]
        messages.append(assistant_message)

        tool_calls = assistant_message.get("tool_calls") or []
        if not tool_calls:
            state.log_event({"phase": "reasoning", "content": assistant_message.get("content", "")})
            continue

        for call in tool_calls:
            result = dispatch_tool_call(call, http=http, state=state)
            messages.append({"role": "tool", "content": result})

    state.log_event({"phase": "run_complete", "iteration_count": config.max_iterations})
