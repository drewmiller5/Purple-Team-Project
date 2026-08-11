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
# Finding #2's original TAIL_LINES=5000 cap is GONE as of the H34/H49 fix
# below -- see that comment for why bounding by line count instead of
# time was itself the bug.

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
# Fix round 1 finding #3: anchor the counting window to the triggering
# event's OWN timestamp (data.timestamp, propagated from
# target/logging_middleware.py's requests.jsonl line straight through to
# the alert payload), not to wall-clock time at script-invocation.
#
# H44 fix (Task 20): wrap both initial extractions so a jq failure here
# (a malformed, non-JSON INPUT_JSON) logs one line before exiting, instead
# of `set -eu` aborting silently on the spot -- same idiom as
# idor-guard.sh's matching fix.
if SRCIP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip | select(. != null and . != "null")' 2>/dev/null) &&
   EVENT_TS=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.timestamp | select(. != null and . != "null")' 2>/dev/null); then
    :
else
    echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/bruteforce-guard: jq failed to parse initial AR payload (malformed JSON?) -- aborting" >> /var/ossec/logs/active-responses.log
    exit 1
fi

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

# H34/H49 fix (Phase 3 Task 5). Two related bugs in the old version of
# this block:
#   - H49: the old `tail -n 5000 "$REQUEST_LOG" | jq ...` capped the
#     scanned window by LINE COUNT, not time. Since target logs every
#     request unconditionally with no rate limiting, an attacker could
#     interleave 5000+ decoy requests to any unrelated endpoint inside
#     the real 120s threshold window, pushing their own genuine
#     correlated login attempts out of the visible tail before this
#     script ever counted them -- COUNT came back under threshold and
#     the lockout silently never fired, no matter how many real matching
#     events actually occurred.
#   - H34: the jq pipeline's exit status was invisible -- piping into
#     `wc -l` means the pipeline's exit status (no `pipefail` in
#     /bin/sh) is `wc -l`'s, always 0. A malformed line mid-window making
#     jq error out (`2>/dev/null` hid the message) could silently
#     produce an undercounted COUNT from jq's partial output instead of
#     being detected.
# Fixed by scoping strictly by TIME instead of line position: jq reads
# $REQUEST_LOG directly with no tail truncation, so a real burst can
# never be starved out of view by decoy volume (every line's own
# timestamp is checked against the event-anchored cutoff, not its
# position from EOF).
#
# Regression found in dual review of the fix above (commit 56a72bb):
# the first version of this fix used `jq -s` (slurp mode), which
# requires the file's ENTIRE content to parse as valid JSON before it
# can build the array to filter/count at all. Since $REQUEST_LOG is
# explicitly append-only and never rotated, a single malformed line
# ANYWHERE in the log's history -- not just inside the current window,
# and regardless of how long ago it was written -- would make every
# future invocation of this script fail, permanently, for the rest of
# the round: worse than the original H34 bug, which at least self-healed
# once the bad line aged out of the old tail-n-5000 window. Fixed by
# reading the file as raw lines (`-R`, `-n`+`inputs`) and parsing each
# one independently with `try fromjson catch empty` -- a malformed line
# simply produces no value and is skipped, exactly like a real line that
# fails the timestamp/field select() below, instead of aborting the
# whole scan. A `select(type == "object")` right after the parse also
# skips a line that's syntactically valid JSON but not an object (a bare
# number/string/array) -- `try/catch` only guards the parse step itself,
# so without this a valid-but-wrong-shape line would still crash the
# `.path`/`.method` field access downstream and reproduce the same
# poison-pill failure through a narrower door (code review finding on
# this fix).
#
# Fix round 4 (final review of round 3): select(type == "object") only
# guarantees the LINE's top level is an object -- it does nothing to
# guarantee any NESTED field is the shape the rest of the pipeline
# assumes. A line can be a well-formed object and still crash downstream:
# form_params as a string instead of an object makes .form_params.username
# error ("Cannot index string with string"); a non-string .timestamp
# makes sub()/fromdateiso8601 error (they require a string input). Since
# this jq invocation processes every line inside one [inputs | ...] array
# construction, an uncaught error on ANY single line -- however deep --
# aborts the ENTIRE run, reproducing the exact poison-pill failure class
# fixed twice already (jq -s slurp, then unparseable/non-object lines)
# through a third, narrower door the per-field type check didn't close.
# Fixed by widening the try/catch to wrap the WHOLE per-line chain, from
# fromjson through the final timestamp select(), instead of guarding only
# the parse step and the top-level shape check -- any error anywhere in
# a single line's processing now just skips that line (catch empty),
# never the whole scan. jq's own exit status (JQ_STATUS below) now only
# goes non-zero for a genuinely fatal condition (e.g. the file becoming
# unreadable mid-read), not for content that was merely malformed at any
# depth, since malformed content of any shape is now handled inline.
#
# ponytail: full linear scan of $REQUEST_LOG on every invocation (this
# fires on every POST to /admin/login) -- O(log size) per event instead
# of the old O(5000). Fine at this lab's traffic volumes; if request
# volume in a round ever makes this a real bottleneck, a byte-offset
# checkpoint (skip content already known to be older than any possible
# future window) would bound it without reintroducing H49's starvation
# bug.
# Note: the jq call's exit status is captured via the `if`/`else` form,
# not a bare `COUNT=$(...); JQ_STATUS=$?` -- under `set -eu`, a plain
# failing command substitution would abort the script on the spot
# (POSIX's `-e` semantics), which would skip the error handling below
# entirely. Testing a command as an `if` condition is the one place
# POSIX explicitly exempts from `-e`, so this is the only shape that
# lets a failing jq surface as a checked, logged condition instead of
# silently killing the script before JQ_STATUS is ever read.
if COUNT=$(jq -n -R -r --arg ip "$SRCIP" --argjson cutoff "$CUTOFF_EPOCH" '
    [ inputs
      | (try (
          fromjson
          | select(type == "object")
          | select(.path == "/admin/login" and .method == "POST" and .remote_addr == $ip
                   and .status_code == 200 and .form_params.username != null)
          | .timestamp
          | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z")
          | fromdateiso8601
          | select(. >= $cutoff)
        ) catch empty)
    ] | length
' "$REQUEST_LOG" 2>/dev/null); then
    JQ_STATUS=0
else
    JQ_STATUS=$?
fi

if [ "$JQ_STATUS" -ne 0 ]; then
    echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/bruteforce-guard: jq counting pipeline failed (exit=${JQ_STATUS}) for srcip=${SRCIP} -- cannot verify threshold, refusing to report a below-threshold count" >> /var/ossec/logs/active-responses.log
    exit 1
fi

if [ "$COUNT" -lt "$THRESHOLD" ]; then
    exit 0
fi

# Real threshold crossed -- delegate to lock-account.sh with the same AR
# payload we received. It re-derives the username itself via jq from
# data.form_params.username, so there's no duplicated extraction logic
# to drift out of sync.
echo "$INPUT_JSON" | "$LOCK_ACCOUNT_SCRIPT"
