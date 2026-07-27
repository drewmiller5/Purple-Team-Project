from datetime import datetime, timedelta, timezone

from referee.monitor import (
    blue_decisive_win,
    has_blue_heartbeat,
    red_decisive_win,
    red_has_host_access,
)


def _ts(offset_seconds=0):
    return (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def test_has_blue_heartbeat_false_when_no_blue_events():
    events = [{"side": "red", "phase": "http_request"}]
    assert has_blue_heartbeat(events) is False


def test_has_blue_heartbeat_true_when_any_blue_event_present():
    events = [{"side": "blue", "phase": "heartbeat"}]
    assert has_blue_heartbeat(events) is True


def test_red_has_host_access_true_when_diagnostics_returns_200():
    events = [{
        "side": "red", "phase": "http_request",
        "request": {"path": "/admin/diagnostics"},
        "response": {"status_code": 200},
    }]
    assert red_has_host_access(events) is True


def test_red_has_host_access_false_when_diagnostics_not_yet_hit():
    events = [{
        "side": "red", "phase": "http_request",
        "request": {"path": "/search"},
        "response": {"status_code": 200},
    }]
    assert red_has_host_access(events) is False


def test_blue_decisive_win_false_without_blue_heartbeat():
    events = [
        {"side": "red", "phase": "http_request", "response": {"status_code": 403}},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_blue_decisive_win_false_below_streak_threshold():
    events = [{"side": "blue", "phase": "heartbeat"}] + [
        {"side": "red", "phase": "http_request", "response": {"status_code": 403}},
    ] * 2
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_blue_decisive_win_true_when_recent_streak_all_blocked():
    events = [{"side": "blue", "phase": "heartbeat"}] + [
        {"side": "red", "phase": "http_request", "response": {"status_code": 403}},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is True


def test_blue_decisive_win_false_when_streak_broken_by_success():
    events = [{"side": "blue", "phase": "heartbeat"}] + [
        {"side": "red", "phase": "http_request", "response": {"status_code": 403}},
        {"side": "red", "phase": "http_request", "response": {"status_code": 200}},
        {"side": "red", "phase": "http_request", "response": {"status_code": 403}},
    ]
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_red_decisive_win_false_without_host_access():
    events = [
        {"side": "blue", "phase": "heartbeat", "timestamp": _ts(0)},
    ]
    now = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=200)
    assert red_decisive_win(events, now, stale_seconds=90) is False


def test_red_decisive_win_false_when_blue_still_fresh():
    events = [
        {"side": "blue", "phase": "heartbeat", "timestamp": _ts(0)},
        {
            "side": "red", "phase": "http_request", "timestamp": _ts(5),
            "request": {"path": "/admin/diagnostics"}, "response": {"status_code": 200},
        },
    ]
    now = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=10)
    assert red_decisive_win(events, now, stale_seconds=90) is False


def test_red_decisive_win_true_when_blue_stale_and_red_has_host_access():
    events = [
        {"side": "blue", "phase": "heartbeat", "timestamp": _ts(0)},
        {
            "side": "red", "phase": "http_request", "timestamp": _ts(5),
            "request": {"path": "/admin/diagnostics"}, "response": {"status_code": 200},
        },
    ]
    now = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=200)
    assert red_decisive_win(events, now, stale_seconds=90) is True
