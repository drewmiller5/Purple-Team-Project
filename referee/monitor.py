from datetime import datetime


def has_blue_heartbeat(events: list) -> bool:
    # go.flag is gated on this alone -- red_agent's own _wait_for_go is a
    # free rider on blue's heartbeat, not anything red does itself (red has
    # no heartbeat call of its own). If this ever becomes a symmetric
    # "both agents ready" condition, red_agent/loop.py needs its own
    # unconditional pre-wait heartbeat-equivalent event first, or the same
    # deadlock blue_agent/loop.py had (fixed 2026-07-27) reappears for red.
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
        if not isinstance(response, dict):
            return False
        return "error" in response or response.get("status_code") == 403

    return all(_is_blocked(e) for e in recent)


def _parse_timestamp(e):
    """Best-effort parse of an event's timestamp. Returns None (rather than
    raising) if the key is missing or the value isn't a valid ISO-8601
    string -- callers should skip events this returns None for instead of
    letting a single malformed record crash the whole win-condition check."""
    ts = e.get("timestamp")
    if ts is None:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


def red_decisive_win(events: list, now: datetime, stale_seconds: float) -> bool:
    """True once red has reached host-level access AND blue has gone dark
    (no blue event in the last `stale_seconds`), after blue had previously
    heartbeated at least once."""
    if not has_blue_heartbeat(events) or not red_has_host_access(events):
        return False

    blue_timestamps = [
        ts for ts in (_parse_timestamp(e) for e in events if e.get("side") == "blue")
        if ts is not None
    ]
    if not blue_timestamps:
        return False
    last_blue = max(blue_timestamps)
    return (now - last_blue).total_seconds() >= stale_seconds
