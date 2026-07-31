import json
from pathlib import Path

import responses

from dashboard.advisor import ask_advisor


@responses.activate
def test_ask_advisor_returns_model_answer_and_logs_it(tmp_path):
    responses.add(
        responses.POST, "http://ollama:11434/api/chat",
        json={"message": {"content": "Try blocking the source IP."}}, status=200,
    )
    event_log = str(tmp_path / "events.jsonl")
    advisor_log = str(tmp_path / "advisor.jsonl")
    Path(event_log).write_text('{"side": "red", "phase": "http_request"}\n')

    result = ask_advisor("http://ollama:11434", "qwen2.5:7b", "What should blue do?", event_log, advisor_log)

    assert result == {"answer": "Try blocking the source IP."}
    logged = json.loads(Path(advisor_log).read_text().splitlines()[0])
    assert logged == {"question": "What should blue do?", "answer": "Try blocking the source IP."}


@responses.activate
def test_ask_advisor_surfaces_ollama_errors_instead_of_swallowing(tmp_path):
    responses.add(responses.POST, "http://ollama:11434/api/chat", status=500)
    event_log = str(tmp_path / "events.jsonl")
    advisor_log = str(tmp_path / "advisor.jsonl")

    result = ask_advisor("http://ollama:11434", "qwen2.5:7b", "hi", event_log, advisor_log)

    assert "error" in result
    assert not Path(advisor_log).exists()


@responses.activate
def test_ask_advisor_surfaces_malformed_200_response_instead_of_raising(tmp_path):
    responses.add(
        responses.POST, "http://ollama:11434/api/chat",
        body="not json at all", status=200,
    )
    event_log = str(tmp_path / "events.jsonl")
    advisor_log = str(tmp_path / "advisor.jsonl")

    result = ask_advisor("http://ollama:11434", "qwen2.5:7b", "hi", event_log, advisor_log)

    assert "error" in result
    assert not Path(advisor_log).exists()


def test_ask_advisor_never_writes_to_referee_log(tmp_path):
    # Regression guard: advisor_log_path and referee_log_path must stay
    # separate files -- this test just asserts the function signature has
    # no referee_log_path parameter at all (a TypeError here means someone
    # tried to reuse the referee's own log for advisory text).
    import inspect
    assert "referee_log_path" not in inspect.signature(ask_advisor).parameters
