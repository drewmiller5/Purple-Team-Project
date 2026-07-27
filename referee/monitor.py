from datetime import datetime


def has_blue_heartbeat(events: list) -> bool:
    return any(e.get("side") == "blue" for e in events)


def red_has_host_access(events: list) -> bool:
    return any(
        e.get("side") == "red"
        and e.get("phase") == "http_request"
        and e.get("request", {}).get("path") == "/admin/diagnostics"
        and e.get("response", {}).get("status_code") == 200
        for e in events
    )


def blue_decisive_win(events: list, streak_threshold: int) -> bool:
    """True once the most recent `streak_threshold` red http_request events
    all came back blocked/failed, and blue has heartbeated at least once."""
    if not has_blue_heartbeat(events):
        return False

    red_requests = [e for e in events if e.get("side") == "red" and e.get("phase") == "http_request"]
    if len(red_requests) < streak_threshold:
        return False

    recent = red_requests[-streak_threshold:]

    def _is_blocked(e):
        response = e.get("response", {})
        return "error" in response or response.get("status_code") == 403

    return all(_is_blocked(e) for e in recent)


def red_decisive_win(events: list, now: datetime, stale_seconds: float) -> bool:
    """True once red has reached host-level access AND blue has gone dark
    (no blue event in the last `stale_seconds`), after blue had previously
    heartbeated at least once."""
    if not has_blue_heartbeat(events) or not red_has_host_access(events):
        return False

    blue_timestamps = [
        datetime.fromisoformat(e["timestamp"]) for e in events if e.get("side") == "blue"
    ]
    last_blue = max(blue_timestamps)
    return (now - last_blue).total_seconds() >= stale_seconds
