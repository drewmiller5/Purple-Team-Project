import json
from pathlib import Path

import requests

from shared.event_log import read_events

ADVISOR_SYSTEM_PROMPT = (
    "You are a purple-team advisor observing a live red-vs-blue security "
    "exercise. Answer the operator's question using the recent event log "
    "context provided. You are advisory only -- you never take actions, "
    "you only explain and suggest."
)


def ask_advisor(ollama_host: str, ollama_model: str, question: str,
                 event_log_path: str, advisor_log_path: str) -> dict:
    recent_events = read_events(event_log_path)[-30:]
    context = json.dumps(recent_events)

    try:
        resp = requests.post(
            f"{ollama_host}/api/chat",
            json={
                "model": ollama_model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": ADVISOR_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Recent events:\n{context}\n\nQuestion: {question}"},
                ],
            },
            timeout=30.0,
        )
        resp.raise_for_status()
        answer = resp.json().get("message", {}).get("content", "")
    except (requests.RequestException, ValueError) as exc:
        return {"error": str(exc)}

    p = Path(advisor_log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps({"question": question, "answer": answer}) + "\n")

    return {"answer": answer}
