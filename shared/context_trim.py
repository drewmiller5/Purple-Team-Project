# Task 14 (H22/H57): cap on `messages` sent to Ollama each iteration, so a
# long round's history doesn't grow unbounded and eventually exceed the
# model's context window. System prompt is always kept; only the oldest
# exchanges are dropped once the list exceeds the cap.
#
# Shared between red_agent/loop.py and blue_agent/loop.py, whose trim
# behavior must stay identical -- a prior version duplicated this in both
# files, which a dual code-review flagged as a drift risk once this bug
# needed fixing in both places at once.
#
# ponytail: fixed message-count cap, not token-aware -- a handful of huge
# messages (e.g. a big alert batch) could still overflow the real context
# window even under this cap. Upgrade to a token-budget trim if that's
# observed in practice.
MAX_CONTEXT_MESSAGES = 40


def trim_messages(messages: list) -> list:
    """Caller contract: a tool-call turn appends one assistant message
    (role="assistant", tool_calls=[...]) followed by one tool-role message
    per call. A raw count-based cut can land inside that pair -- dropping
    the assistant message but keeping its tool response, which Ollama's
    chat API rejects (a "tool" message with no preceding assistant.tool_calls
    is an invalid conversation). Dual code-review finding on this fix's
    first version. Drop any such leading orphaned tool message(s) instead
    of sending them dangling.
    """
    if len(messages) <= MAX_CONTEXT_MESSAGES + 1:
        return messages
    tail = messages[-MAX_CONTEXT_MESSAGES:]
    start = 0
    while start < len(tail) and tail[start].get("role") == "tool":
        start += 1
    return [messages[0]] + tail[start:]
