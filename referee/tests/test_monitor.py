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


def test_blue_decisive_win_false_when_connection_errors_have_no_corroborating_block():
    """H81 core regression: a connection error (e.g. the target's own dev
    server briefly saturated under load) is indistinguishable, by shape
    alone, from a real iptables DROP -- both show up as `{"error": ...}`
    on red's side. Live-reproduced last session: a round scored "blue win"
    off 3 trailing red SQLi requests that hit raw ConnectTimeoutErrors,
    with blue having taken zero actions the entire round. A streak of bare
    connection errors must NOT count as "blocked" unless blue actually
    executed a real, successful defensive action somewhere in the round."""
    events = [{"side": "blue", "phase": "heartbeat"}] + [
        {"side": "red", "phase": "http_request", "response": {"error": "Connection refused"}},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_blue_decisive_win_true_when_connection_errors_are_corroborated_by_a_real_block():
    """Same connection-error streak as above, but this time blue actually
    executed a real, successful escalation -- now the errors are
    legitimately attributable to blue's own action, not target flakiness."""
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {
            "side": "blue", "phase": "escalation", "action": "block_ip", "target": "10.0.0.5",
            "response": {"status_code": 200, "body": '{"blocked_ip": "10.0.0.5"}'},
        },
    ] + [
        {"side": "red", "phase": "http_request", "response": {"error": "Connection refused"}},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is True


def test_blue_decisive_win_false_when_only_lock_account_succeeded_not_block_ip():
    """Security review regression (2026-08-12): lock_account/kill_session
    are pure application-layer checks (a normal HTTP response, e.g. a 200
    'Account blocked' page or a 403) -- they can never CAUSE a transport-
    level connection error the way an iptables block_ip DROP can. A
    successful lock_account proves nothing about why an unrelated later
    request timed out, so it must not corroborate a connection-error
    streak -- only block_ip can."""
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {
            "side": "blue", "phase": "escalation", "action": "lock_account", "target": "jsmith",
            "response": {"status_code": 200, "body": "locked"},
        },
    ] + [
        {"side": "red", "phase": "http_request", "response": {"error": "Connection refused"}},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_blue_decisive_win_false_when_block_ip_succeeds_after_the_streak_it_would_explain():
    """Security review regression (2026-08-12): a block_ip that happens
    AFTER the connection-error streak cannot have caused it -- corroboration
    requires the successful block_ip to have occurred at or before the
    request it's meant to explain, not just anywhere in the round."""
    events = [{"side": "blue", "phase": "heartbeat"}] + [
        {"side": "red", "phase": "http_request", "response": {"error": "Connection refused"}},
    ] * 3 + [
        {
            "side": "blue", "phase": "escalation", "action": "block_ip", "target": "10.0.0.5",
            "response": {"status_code": 200, "body": '{"blocked_ip": "10.0.0.5"}'},
        },
    ]
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_blue_decisive_win_false_when_escalation_was_attempted_but_failed():
    """A rejected/failed escalation attempt (e.g. H68's fail-open 503, or
    any non-200) must not count as "blue took real action" -- only a
    genuinely successful one corroborates a connection-error streak."""
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {
            "side": "blue", "phase": "escalation", "action": "block_ip", "target": "10.0.0.5",
            "response": {"status_code": 503, "body": '{"error": "not yet fully resolved"}'},
        },
    ] + [
        {"side": "red", "phase": "http_request", "response": {"error": "Connection refused"}},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_blue_decisive_win_true_via_explicit_403_regardless_of_escalation_history():
    """A real application-level 403 (e.g. the target's own is_blocked()
    check) is unambiguous on its own -- doesn't need escalation
    corroboration the way a bare connection error does."""
    events = [{"side": "blue", "phase": "heartbeat"}] + [
        {"side": "red", "phase": "http_request", "response": {"status_code": 403}},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is True


def test_blue_decisive_win_false_when_red_already_captured_a_flag_earlier_in_the_round():
    """H81's other half: the original repro had red get a real, unaddressed
    RCE/IDOR/login compromise EARLIER in the round, then blue's trailing
    streak (of what were actually just target timeouts, not real blocks)
    scored a false "blue win" with the earlier compromise never
    considered. Even with a real, corroborated block streak, blue must
    not be credited a win if red already captured a flag earlier in the
    same round -- a later block doesn't undo an earlier compromise."""
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {
            "side": "red", "phase": "http_request",
            "request": {"path": "/documents/1"}, "response": {"status_code": 200},
        },
        {"side": "red", "phase": "finding", "category": "IDOR", "success": True},
        {
            "side": "blue", "phase": "escalation", "action": "block_ip", "target": "10.0.0.5",
            "response": {"status_code": 200, "body": '{"blocked_ip": "10.0.0.5"}'},
        },
    ] + [
        {"side": "red", "phase": "http_request", "response": {"status_code": 403}},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_blue_decisive_win_false_when_response_is_none():
    # H26 regression: `response: None` must be treated as "not blocked"
    # rather than crashing on `"error" in None`.
    events = [{"side": "blue", "phase": "heartbeat"}] + [
        {"side": "red", "phase": "http_request", "response": None},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_blue_decisive_win_false_when_response_is_a_string():
    # H26 regression: a string-shaped `response` must be treated as "not
    # blocked" rather than crashing on `.get("status_code")`.
    events = [{"side": "blue", "phase": "heartbeat"}] + [
        {"side": "red", "phase": "http_request", "response": "unexpected string"},
    ] * 3
    assert blue_decisive_win(events, streak_threshold=3) is False


def test_has_blue_heartbeat_ignores_human_actor_events():
    events = [{"side": "blue", "actor": "human", "phase": "heartbeat"}]
    assert has_blue_heartbeat(events) is False


def test_blue_decisive_win_ignores_human_actor_red_requests():
    events = [{"side": "blue", "phase": "heartbeat"}]
    events += [
        {"side": "red", "actor": "human", "phase": "http_request", "response": {"status_code": 403}}
        for _ in range(3)
    ]
    assert blue_decisive_win(events, streak_threshold=3) is False


# --- red_decisive_win: capturing ANY known flag ends the round immediately ---
# Redefined 2026-08-12 (Drew's call): the old semantics only recognized
# reaching /admin/diagnostics AND blue going stale afterward as a red win --
# SQLi/IDOR/bruteforce captures had no win path at all. Now any confirmed
# (record_finding success=True) capture of one of white_memory.KNOWN_FLAGS
# is decisive -- no blue-staleness condition -- but ONLY when corroborated
# by a real http_request event matching that flag's expected evidence
# signature (dual review, same session: record_finding's category/detail
# are free-text from the red agent's own LLM with zero server-side
# validation, so trusting the claim alone would let a hallucinating or
# prompt-injected model self-declare a round-ending win with no exploit
# having actually happened -- generalizes red_has_host_access()'s original
# "require a real verified HTTP response" pattern from command-injection
# to all 4 flags instead of dropping it for the other 3).

_SQLI_EVENT = {
    "side": "red", "phase": "http_request",
    "request": {"method": "GET", "path": "/search", "params": {"q": "' OR '1'='1"}},
    "response": {"status_code": 200, "body": "results"},
}
_BRUTEFORCE_EVENT = {
    "side": "red", "phase": "http_request",
    "request": {"method": "POST", "path": "/admin/login", "data": {"username": "jsmith", "password": "Sunshine2024!"}},
    "response": {"status_code": 200, "body": '<span class="welcome-card__role">Role: admin</span>'},
}
_IDOR_EVENT = {
    "side": "red", "phase": "http_request",
    "request": {"method": "GET", "path": "/documents/7"},
    "response": {"status_code": 200, "body": '{"id": 7, "confidential": true}'},
}
_COMMAND_INJECTION_EVENT = {
    "side": "red", "phase": "http_request",
    "request": {"path": "/admin/diagnostics"}, "response": {"status_code": 200},
}


def test_red_decisive_win_false_without_blue_heartbeat():
    events = [
        {"side": "red", "phase": "finding", "category": "SQL Injection", "success": True},
        _SQLI_EVENT,
    ]
    assert red_decisive_win(events) is False


def test_red_decisive_win_false_when_no_finding_recorded():
    events = [{"side": "blue", "phase": "heartbeat"}, _SQLI_EVENT]
    assert red_decisive_win(events) is False


def test_red_decisive_win_false_when_finding_not_successful():
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "SQL Injection", "success": False},
        _SQLI_EVENT,
    ]
    assert red_decisive_win(events) is False


def test_red_decisive_win_false_when_category_matches_no_known_flag():
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "something unrelated", "success": True},
    ]
    assert red_decisive_win(events) is False


def test_red_decisive_win_false_when_claim_has_no_corroborating_evidence():
    """The exact scenario dual review flagged as CRITICAL: a plausible-
    sounding claim with no real http_request evidence behind it must not
    end the round. This is the core regression test for the fix."""
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "SQL Injection", "success": True},
        # No corroborating /search http_request event anywhere in events.
    ]
    assert red_decisive_win(events) is False


def test_red_decisive_win_false_when_finding_claims_success_but_real_request_was_the_failure_page():
    """Near-miss case: red recorded a bruteforce 'success' but the actual
    HTTP evidence in the same round shows the login failure page, not the
    real welcome page -- the claim must not be trusted over the evidence."""
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "Bruteforce admin login", "success": True},
        {
            "side": "red", "phase": "http_request",
            "request": {"method": "POST", "path": "/admin/login", "data": {"username": "admin", "password": "admin"}},
            "response": {"status_code": 200, "body": "Invalid credentials"},
        },
    ]
    assert red_decisive_win(events) is False


def test_red_decisive_win_true_when_sqli_claim_is_corroborated():
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "SQL Injection", "success": True},
        _SQLI_EVENT,
    ]
    assert red_decisive_win(events) is True


def test_red_decisive_win_true_when_bruteforce_claim_is_corroborated():
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "Bruteforce admin login", "success": True},
        _BRUTEFORCE_EVENT,
    ]
    assert red_decisive_win(events) is True


def test_red_decisive_win_true_when_idor_claim_is_corroborated():
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "IDOR on documents", "success": True},
        _IDOR_EVENT,
    ]
    assert red_decisive_win(events) is True


def test_red_decisive_win_true_when_command_injection_claim_is_corroborated():
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "OS command injection", "success": True},
        _COMMAND_INJECTION_EVENT,
    ]
    assert red_decisive_win(events) is True


def test_red_decisive_win_ignores_human_actor_finding():
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "actor": "human", "phase": "finding", "category": "SQL Injection", "success": True},
        _SQLI_EVENT,
    ]
    assert red_decisive_win(events) is False


def test_red_decisive_win_ignores_human_actor_corroborating_request():
    """A human manually reproducing the evidence pattern during a live
    round (the dashboard's manual red-action path) must not corroborate an
    autonomous agent's claim -- same actor-blindness rule as the rest of
    this module's win checks."""
    events = [
        {"side": "blue", "phase": "heartbeat"},
        {"side": "red", "phase": "finding", "category": "SQL Injection", "success": True},
        {**_SQLI_EVENT, "actor": "human"},
    ]
    assert red_decisive_win(events) is False
