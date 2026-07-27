#!/bin/sh
# wazuh/active-response/bruteforce-guard.sh
#
# Task 8 fix: Wazuh's native frequency/if_matched_sid correlation (the old
# rule 100104 -- if_matched_sid=100103, frequency="5" timeframe="120",
# same_field=remote_addr) never fires. This was investigated exhaustively
# (see wazuh-rules/target_rules.xml header + task-8-bruteforce-idor-fix-
# report.md): wazuh-logtest confirmed the base rule (100103) matches every
# individual event correctly, but the aggregating rule never crosses into
# alerts.json even under live traffic -- reproduced against Wazuh's own
# shipped/working example (0580-win-security_rules.xml 60204/60205, which
# is structurally identical) and a minimal zero-condition if_matched_sid
# test rule. All plausible causes were ruled out with evidence. Decision
# (explicit direction from the human controller): stop fighting Wazuh's
# internal correlation engine and do the counting ourselves, the way a
# real SOC/blue-team script would -- this is that script.
#
# Design: rule 100103 (still level=0 internally, but bumped from its old
# level="0" to level="3" so Wazuh can generate a real, low-severity alert
# and therefore have something to bind Active Response to -- Wazuh only
# dispatches AR off of actual alerts; level-0 "silent" rules are evaluated
# for correlation bookkeeping only and never trigger AR, confirmed against
# Wazuh 4.9 docs/behavior before choosing this over any level-0-binding
# alternative, which does not exist) fires this script on EVERY single
# POST to /admin/login. This script must therefore be cheap and correct
# about when to actually act:
#   1. Pull the source IP AND the triggering event's own timestamp that
#      Wazuh decoded for this event (srcip / data.timestamp -- srcip
#      populated by the generic JSON decoder because
#      target/logging_middleware.py duplicates remote_addr under that
#      reserved key, see Task 7; data.timestamp is the request's own
#      original timestamp, see the "Fix round 1" note below for why it's
#      used instead of wall-clock time).
#   2. Count how many POSTs to /admin/login from that same source IP
#      appear in target's own request log within 120 seconds of THAT
#      event (the original rule's intended window).
#   3. Only at >=5 matches (the original rule's intended threshold) does
#      it actually lock the account -- by handing the same AR payload to
#      the existing lock-account.sh, reusing its already-hardened
#      (Task 7 fix-round 2) jq-based username extraction rather than
#      duplicating that logic here.
#   4. Below threshold: exit 0 with no output. Cheap, quiet, correct.
#
# Fix round 1 (task reviewer findings on the original Task 8 commit):
#   - Finding #2 (unbounded per-event work): the counting query used to
#     pull EVERY historical matching line from the (append-only, never
#     rotated) request log and fork an external `date -d` subprocess per
#     matching line in a shell loop -- strictly more work forever as the
#     log grows, on a script that fires on every single request. Time-
#     window filtering now happens inside ONE jq pass (jq's
#     fromdateiso8601, fed a normalized timestamp via jq's own sub(),
#     since Python's isoformat() -- fractional seconds + "+00:00" -- isn't
#     jq's strict ISO8601 form) over at most the last TAIL_LINES lines of
#     the log (bounded via `tail`), so per-event cost no longer grows
#     unboundedly with log size.
#   - Finding #3 (wall-clock window anchor): NOW_EPOCH used to be `date -u
#     +%s` evaluated when this script itself ran, not the triggering
#     alert's own event time -- under real AR-dispatch latency (empirically
#     observed during original verification: tightly-clustered bursts were
#     required just to stay inside the nominal window) the effective
#     window silently shrank below the nominal 120s. The window is now
#     anchored to the triggering event's own data.timestamp from the AR
#     payload instead.
#   - Minor note (also addressed): the counting query now matches rule
#     100103's own field conditions exactly (status_code==200,
#     form_params.username present), so this script's count can never
#     diverge from what actually fired the alert it's reacting to.
set -eu

REQUEST_LOG="/app/target/logs/requests.jsonl"
THRESHOLD=5
WINDOW_SECONDS=120
LOCK_ACCOUNT_SCRIPT="/var/ossec/active-response/bin/lock-account.sh"
# Finding #2: bound how much of the log gets scanned per invocation
# instead of the whole (ever-growing) file. 5000 lines is generous
# headroom for a threshold of 5 events inside a 120s window even with a
# lot of interleaved traffic from other endpoints/IPs, while keeping the
# per-event cost roughly constant rather than growing without bound
# across a long-running demo.
TAIL_LINES=5000

# Task 8 fix-round (live verification): wazuh-execd writes the AR JSON
# payload as a single line but does NOT close/EOF its child's stdin
# afterward on this Wazuh 4.9.2 build -- confirmed empirically (a hung
# `cat` subprocess, still blocked on read() with the pipe fd open, was
# caught live via /proc/<pid>/task during Task 8 verification). `$(cat)`
# waits for EOF and therefore hangs forever. `read -r` only needs the
# single newline execd DOES write after the JSON object, so it returns
# immediately. (lock-account.sh/kill-session.sh don't hit this: they're
# invoked here via a plain `echo ... | script` pipe, which closes its
# write end as soon as `echo` exits -- a real EOF, unlike execd's own
# child pipe.)
IFS= read -r INPUT_JSON
SRCIP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip | select(. != null and . != "null")')
# Fix round 1 finding #3: anchor the counting window to the triggering
# event's OWN timestamp (data.timestamp, propagated from
# target/logging_middleware.py's requests.jsonl line straight through to
# the alert payload), not to wall-clock time at script-invocation.
EVENT_TS=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.timestamp | select(. != null and . != "null")')

# No source IP or event timestamp decoded -> nothing to count against.
# Exit quietly.
if [ -z "${SRCIP:-}" ] || [ -z "${EVENT_TS:-}" ]; then
    exit 0
fi

if [ ! -f "$REQUEST_LOG" ]; then
    exit 0
fi

# jq's fromdateiso8601 only accepts the strict "%Y-%m-%dT%H:%M:%SZ" form
# (no fractional seconds, bare "Z" offset), but target/logging_middleware.py
# emits Python's isoformat() ("...ffffff+00:00"). Normalize with jq's own
# sub() -- still a single jq invocation, no external `date` subprocess
# (finding #2).
EVENT_EPOCH=$(echo "$EVENT_TS" | jq -R -r '
    sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601
' 2>/dev/null) || exit 0
[ -z "${EVENT_EPOCH:-}" ] && exit 0
CUTOFF_EPOCH=$((EVENT_EPOCH - WINDOW_SECONDS))

# Single jq pass: matches rule 100103's own field conditions exactly
# (status_code==200, form_params.username present) scoped to this source
# IP, converts each candidate line's own timestamp to epoch, and keeps
# only the ones inside the event-anchored window -- no per-line `date`
# subprocess, no full-file scan (bounded by `tail` above).
COUNT=$(tail -n "$TAIL_LINES" "$REQUEST_LOG" 2>/dev/null | jq -r --arg ip "$SRCIP" --argjson cutoff "$CUTOFF_EPOCH" '
    select(.path == "/admin/login" and .method == "POST" and .remote_addr == $ip
           and .status_code == 200 and .form_params.username != null)
    | .timestamp
    | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z")
    | fromdateiso8601
    | select(. >= $cutoff)
' 2>/dev/null | wc -l | tr -d ' ')

if [ "$COUNT" -lt "$THRESHOLD" ]; then
    exit 0
fi

# Real threshold crossed -- delegate to lock-account.sh with the same AR
# payload we received. It re-derives the username itself via jq from
# data.form_params.username, so there's no duplicated extraction logic
# to drift out of sync.
echo "$INPUT_JSON" | "$LOCK_ACCOUNT_SCRIPT"
