from shared.context_trim import MAX_CONTEXT_MESSAGES, trim_messages


def test_trim_messages_is_a_noop_under_the_cap():
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    assert trim_messages(messages) == messages


def test_trim_messages_keeps_system_prompt_and_caps_the_rest():
    system = {"role": "system", "content": "sys"}
    rest = [{"role": "user", "content": str(i)} for i in range(MAX_CONTEXT_MESSAGES + 20)]
    messages = [system] + rest

    trimmed = trim_messages(messages)

    assert len(trimmed) == MAX_CONTEXT_MESSAGES + 1
    assert trimmed[0] is system
    assert trimmed[1:] == rest[-MAX_CONTEXT_MESSAGES:]


def test_trim_messages_drops_leading_orphaned_tool_message():
    """Dual code-review finding on Task 14 (H22/H57): a raw count-based cut
    can split a tool-call turn -- landing between an assistant message's
    tool_calls and its tool-role response, leaving a dangling tool message
    with no preceding assistant.tool_calls. Ollama's chat API rejects that
    shape. The cut must never leave a tool-role message as the first kept
    entry after the system prompt."""
    system = {"role": "system", "content": "sys"}
    paired_assistant = {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": "x", "arguments": {}}}],
    }
    paired_tool = {"role": "tool", "content": "result"}
    filler = [{"role": "user", "content": str(i)} for i in range(MAX_CONTEXT_MESSAGES - 1)]
    # Total = 1 (system) + 2 (pair) + (cap - 1) filler = cap + 2 -> triggers
    # a trim whose naive cut lands exactly on paired_tool.
    messages = [system, paired_assistant, paired_tool] + filler

    trimmed = trim_messages(messages)

    assert trimmed[0] is system
    assert paired_tool not in trimmed
    assert trimmed[1] is filler[0]


def test_trim_messages_keeps_a_clean_tool_pair_when_the_boundary_lands_on_it():
    """A pair that survives the naive cut intact (assistant.tool_calls and
    its tool response both land past the boundary, since they're the most
    recent two messages) must not be disturbed."""
    system = {"role": "system", "content": "sys"}
    filler = [{"role": "user", "content": str(i)} for i in range(MAX_CONTEXT_MESSAGES)]
    paired_assistant = {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": "x", "arguments": {}}}],
    }
    paired_tool = {"role": "tool", "content": "result"}
    messages = [system] + filler + [paired_assistant, paired_tool]

    trimmed = trim_messages(messages)

    assert trimmed[-2] is paired_assistant
    assert trimmed[-1] is paired_tool
