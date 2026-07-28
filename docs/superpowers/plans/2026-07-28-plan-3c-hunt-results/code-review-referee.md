# Phase 1 (Hunt) Code Review: referee/

Scope: referee/ only (monitor.py, loop.py, config.py, main.py, tests/).
K1-K6 from the findings ledger are not repeated here. All line numbers refer
to the current state of the files on blue-agent-referee.

---

## CRITICAL

Summary: A single blue-side event missing a timestamp key, or carrying
a non-ISO-8601 timestamp value, crashes the referee main loop with an
unhandled KeyError/ValueError, and the referee container has no restart
policy, so the crash is permanent for the rest of the round.

File: referee/monitor.py:50-51 (inside red_decisive_win)

    blue_timestamps = [
        datetime.fromisoformat(e["timestamp"]) for e in events if e.get("side") == "blue"
    ]

Failure scenario: Every other field access on events in monitor.py
uses .get(...) with a default (e.get("side"), e.get("response", {}),
etc.), but this line uses direct-index e["timestamp"] and feeds it straight
into datetime.fromisoformat with no guard. has_blue_heartbeat (line 11)
only checks that some event has side == "blue" -- it never checks that
event also has a well-formed timestamp. So the guard at red_decisive_win
line 47 (if not has_blue_heartbeat(events) ...) does not protect this line
at all: any blue event that is missing timestamp (KeyError) or has a
malformed value such as an empty string, None, or a non-ISO string like
"2026-07-28 not-a-time" (ValueError) will raise inside the list
comprehension.

This exception propagates uncaught through blue_decisive_win /
red_decisive_win -> referee/loop.py:34 -> run() while True loop, which has
no try/except anywhere (referee/loop.py:19-52). The process exits.
referee/main.py:5-7 has no try/except either, so nothing catches it at the
top level. In docker-compose.yml, the referee service (lines 101-125) has
no restart: policy, so the container simply stops. Because blue_agent /
red_agent only stop when they observe stop.flag (blue_agent/loop.py:43),
and the referee crashed before ever writing stop.flag or budget_expired,
both agent containers keep running indefinitely with no adjudication ever
produced -- a silent, permanent hang that looks like "the round is just
taking a long time" rather than a crash, until someone checks
docker compose ps / logs (same detection gap called out in K6).

Nothing upstream guarantees this cannot happen: shared/event_log.py
log_event does default timestamp via setdefault for events it writes
itself, but read_events (shared/event_log.py:24-38) parses arbitrary JSON
lines and does not enforce that a timestamp key exists or is well-formed --
it only guards against non-JSON lines, not against valid-JSON-but-wrong-shape
ones.

Suggested fix: In red_decisive_win, filter/skip blue events that lack
a parseable timestamp (e.g. wrap the comprehension in a helper that
continues past KeyError/ValueError, logging a warning), rather than
letting a single bad record take down the whole adjudication loop.
Additionally, wrap run() per-iteration body in referee/loop.py in a
try/except that logs and continues (or fails safe by touching stop.flag
with an outcome of referee_error) instead of letting an uncaught exception
silently end the process with no restart policy.

---

## HIGH

Summary: blue_decisive_win _is_blocked helper assumes response is
always a dict. If a red http_request event has a response field present
but not a dict (e.g. null/None, a string, or a list -- plausible if an
upstream tool logs a raw error string or a timeout placeholder instead of a
structured response object), this raises an unhandled TypeError or
AttributeError, with the same uncaught-exception -> no-restart-policy ->
permanent-hang consequence described above.

File: referee/monitor.py:36-38

    def _is_blocked(e):
        response = e.get("response", {})
        return "error" in response or response.get("status_code") == 403

Failure scenario: e.get("response", {}) only substitutes the default {}
when the response key is absent. If the key is present with value None
(e.g. {"response": None}), response is None, and the "error" in None check
raises TypeError: argument of type NoneType is not iterable. If response is
a string (e.g. {"response": "connection timed out"}), the "error" in
response check succeeds (substring check, silently wrong semantics) but
response.get("status_code") raises AttributeError: str object has no
attribute get. Neither case is tested in referee/tests/test_monitor.py,
which only exercises response as a well-formed dict (with an "error" key or
a "status_code" key).

Suggested fix: Guard with a check like: if not isinstance(response, dict)
return False (treat non-dict/None responses as not blocked rather than
crashing), and add regression tests for a null response, response as a
string, and a missing response key entirely (the last one is already
implicitly covered by the {} default but is not explicitly asserted).

---

## HIGH

Summary: referee/loop.py run() never clears pre-existing go.flag /
stop.flag at the start of a round. Because referee-state is a persistent
named Docker volume (not a tmpfs or per-round-recreated mount), a referee
process that restarts mid-lab (crash, manual restart, docker compose
restart referee) will find stale flags left over from whatever round last
touched that volume, and both agents will misread them as belonging to the
new round.

File: referee/loop.py:11-14

    state_dir = Path(config.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    go_path = state_dir / "go.flag"
    stop_path = state_dir / "stop.flag"

No code anywhere in referee/loop.py calls unlink() on go_path or stop_path
before or during run(); flags are only ever created (touch()), never
removed. docker-compose.yml:125 mounts referee-state:/app/referee_state
read-write for the referee and read-only for red_agent/blue_agent (lines
69, 99, 148), and the volume is declared under top-level volumes: (line
297) with no driver_opts implying ephemeral storage -- it persists across
container stop/start/restart unless explicitly removed with docker compose
down -v. blue_agent/loop.py:38 and :43 read go.flag/stop.flag existence
directly with no round-identifier or timestamp check.

Failure scenario: Round N ends with stop.flag written. Operator restarts
the referee container to start round N+1 (e.g. after the crash described
in the CRITICAL finding above, or just a manual re-run) without also
recreating the referee-state volume. On the very first poll of round N+1,
blue_agent/red_agent (if also freshly started against the same volume)
immediately see stop.flag already present and treat the brand-new round as
already over before the referee has evaluated any real condition for it --
a false "round already ended" with no corresponding round_over assessment
describing why.

Suggested fix: At the top of run(), before entering the loop, unlink
both go_path and stop_path if they exist (best-effort, ignore
FileNotFoundError), so every fresh referee process starts a round from a
guaranteed-clean flag state.

---

## MEDIUM

Summary: blue_decisive_win has degenerate, effectively-inverted behavior
when blue_win_streak is configured to 0: it declares a blue win immediately
after the first blue heartbeat, with zero red http_request events
required, let alone a real streak of blocks.

File: referee/monitor.py:31-40; config source referee/config.py:23

    if len(red_requests) < streak_threshold:
        return False
    recent = red_requests[-streak_threshold:]
    ...
    return all(_is_blocked(e) for e in recent)

Failure scenario: If REFEREE_BLUE_WIN_STREAK is set to 0 (no validation
exists in load_config, referee/config.py:16-25, beyond int(...) parsing --
any non-negative-checked integer is accepted), then for red_requests equal
to an empty list: len([]) < 0 is False, so the early return is skipped;
recent equals [][-0:], and since negative zero equals zero in Python slice
semantics, this is [][0:] which is []; all(_is_blocked(e) for e in []) is
vacuously True. Result: blue_decisive_win returns True the instant blue
heartbeats, before red has made a single HTTP request -- the opposite of
the documented contract (the most recent streak_threshold red http_request
events all came back blocked). This is purely a config-validation gap, not
something achievable by red/blue runtime behavior alone, but nothing in
RefereeConfig or load_config rejects 0 or negative values for
blue_win_streak.

Suggested fix: Validate that blue_win_streak is at least 1 (and
reasonably, max_round_seconds, blue_stale_seconds, and
poll_interval_seconds are all greater than 0) in load_config, raising a
clear ValueError at startup rather than allowing a silently-wrong win
condition. Add a regression test asserting that blue_decisive_win with a
heartbeat-only event list and streak_threshold=0 returns False.

---

## MEDIUM

Summary: All three monitor functions assume every element of events is a
dict. read_events (shared/event_log.py:24-38, direct upstream of every call
site in referee/loop.py:20) only guards against lines that fail
json.loads -- it does not validate that a successfully-parsed line is a
JSON object. A log line containing a bare JSON scalar or array (e.g. the
number 42, the string "blue heartbeat", or the array [1,2,3] -- all valid
JSON, all plausible from a hand-edited log or a buggy writer elsewhere in
the system) passes through read_events unchanged and reaches
referee/monitor.py.

File: referee/monitor.py:11 (has_blue_heartbeat) and similarly lines
15-21, 30, 51 -- every e.get(...) call in the module.

Failure scenario: the any(e.get("side") == "blue" for e in events)
expression calls .get on every element of events; if any element is not a
dict (e.g. an int or str parsed from a malformed-but-valid-JSON line), this
raises an AttributeError such as int object has no attribute get (or
str/list), crashing the loop the same way as the CRITICAL finding above
(uncaught, no restart policy).

Suggested fix: Either have shared/event_log.py read_events filter out
non-dict parsed lines (symmetric to its existing JSONDecodeError guard), or
have referee/monitor.py defensively skip non-dict entries at the top of
each function. Given this is a referee/-scoped review, the minimal in-scope
fix is the latter; note the upstream shared/event_log.py gap for whoever
owns that file.

---

## LOW

Summary: load_config() performs no validation on env-var-derived numeric
config, so a misconfigured REFEREE_POLL_INTERVAL_SECONDS (negative value)
crashes time.sleep() in the main loop, and any non-numeric value for any of
the four numeric fields crashes at load_config() time with a raw
ValueError (an invalid literal for int() with base 10 style message) rather
than an actionable message.

File: referee/config.py:21-24; consumed at referee/loop.py:52 where
time.sleep(config.poll_interval_seconds) raises ValueError (sleep length
must be non-negative) for a negative value.

Suggested fix: Validate ranges (greater than 0 for the round/streak/poll
settings) in load_config with a clear error message, so misconfiguration
fails fast and legibly at container start rather than as an opaque stack
trace at the first affected call site.

---

## LOW: Test coverage gaps

referee/tests/test_monitor.py and referee/tests/test_loop.py cover the
happy path and the documented ordering/precedence cases well (see
test_run_prefers_red_win_over_budget_expired at
referee/tests/test_loop.py:84-107), but have no coverage for any of the
following, all of which are exactly the edge cases this review found
crash- or logic-affecting:

- Empty events list passed directly to blue_decisive_win or
  red_decisive_win (implicitly exercised only via has_blue_heartbeat
  returning False first -- never asserted as its own case).
- A blue event missing timestamp or with a malformed timestamp string,
  passed to red_decisive_win (would currently crash -- see CRITICAL
  finding).
- A red http_request event with response as None, a string, or absent
  entirely mixed with dict-shaped ones (would currently crash for
  None/string -- see first HIGH finding).
- blue_win_streak of 0 or a negative value (would currently short-circuit
  to an incorrect True for streak 0 -- see MEDIUM finding).
- referee/loop.py run() invoked against a state_dir that already contains
  a go.flag and/or stop.flag from a prior round (no test asserts stale
  flags are cleared or that their presence does not produce a bogus
  outcome).

Suggested fix: Add targeted regression tests for each bullet above once
the corresponding fixes land, so these edge cases cannot silently regress.

---

## Summary Table

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH     | 2 |
| MEDIUM   | 2 |
| LOW      | 2 |
