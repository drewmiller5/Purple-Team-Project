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
#   1. Pull the source IP Wazuh decoded for this event (srcip, populated
#      by the generic JSON decoder because target/logging_middleware.py
#      duplicates remote_addr under that reserved key -- see Task 7).
#   2. Count how many POSTs to /admin/login from that same source IP
#      appear in target's own request log within the last 120 seconds
#      (the original rule's intended window).
#   3. Only at >=5 matches (the original rule's intended threshold) does
#      it actually lock the account -- by handing the same AR payload to
#      the existing lock-account.sh, reusing its already-hardened
#      (Task 7 fix-round 2) jq-based username extraction rather than
#      duplicating that logic here.
#   4. Below threshold: exit 0 with no output. Cheap, quiet, correct.
set -eu

REQUEST_LOG="/app/target/logs/requests.jsonl"
THRESHOLD=5
WINDOW_SECONDS=120
LOCK_ACCOUNT_SCRIPT="/var/ossec/active-response/bin/lock-account.sh"

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

# No source IP decoded -> nothing to count against. Exit quietly.
if [ -z "${SRCIP:-}" ]; then
    exit 0
fi

if [ ! -f "$REQUEST_LOG" ]; then
    exit 0
fi

NOW_EPOCH=$(date -u +%s)
CUTOFF_EPOCH=$((NOW_EPOCH - WINDOW_SECONDS))

# Same event shape rule 100103 matches (POST /admin/login), scoped to
# this source IP, timestamps only -- one per line.
TIMESTAMPS=$(jq -r --arg ip "$SRCIP" '
    select(.path == "/admin/login" and .method == "POST" and .remote_addr == $ip)
    | .timestamp
' "$REQUEST_LOG" 2>/dev/null || true)

COUNT=0
if [ -n "$TIMESTAMPS" ]; then
    while IFS= read -r ts; do
        [ -z "$ts" ] && continue
        # jq's fromdateiso8601 can't parse Python's isoformat() output
        # (fractional seconds + "+00:00" offset instead of a bare "Z"),
        # so timestamps are compared with GNU `date -d` instead, which
        # parses that exact format natively (verified in-container).
        ts_epoch=$(date -d "$ts" +%s 2>/dev/null) || continue
        if [ "$ts_epoch" -ge "$CUTOFF_EPOCH" ]; then
            COUNT=$((COUNT + 1))
        fi
    done <<EOF
$TIMESTAMPS
EOF
fi

if [ "$COUNT" -lt "$THRESHOLD" ]; then
    exit 0
fi

# Real threshold crossed -- delegate to lock-account.sh with the same AR
# payload we received. It re-derives the username itself via jq from
# data.form_params.username, so there's no duplicated extraction logic
# to drift out of sync.
echo "$INPUT_JSON" | "$LOCK_ACCOUNT_SCRIPT"
