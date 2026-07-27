#!/bin/sh
# wazuh/active-response/idor-guard.sh
#
# Task 8 fix -- companion to bruteforce-guard.sh, same root cause and same
# decision (see that script's header and wazuh-rules/target_rules.xml's
# header for the full investigation recap): Wazuh's native
# frequency/if_matched_sid correlation on rule 100106 (if_matched_sid=
# 100105, frequency="5" timeframe="60", same_field=remote_addr) never
# fires, despite the base rule 100105 matching every individual event
# reliably. The counting now happens here instead, in a real
# blue-team-style Active Response script triggered off of rule 100105
# (bumped from level="0" to level="3" so Wazuh has a real alert to bind AR
# to -- level-0 rules are correlation-only and never dispatch AR).
#
# This script fires on EVERY GET to /documents/<id>, so it must be cheap
# and correct about when to actually act:
#   1. Pull the source IP Wazuh decoded for this event (srcip).
#   2. Count matching GETs to /documents/<id> from that same source IP in
#      target's own request log within the last 60 seconds (the original
#      rule's intended window).
#   3. Only at >=5 matches (the original rule's intended threshold) does
#      it actually block -- by inserting real iptables DROP rules against
#      the source IP.
#   4. Below threshold: exit 0 with no output.
#
# Why replicate iptables directly instead of invoking the stock
# firewall-drop binary: firewall-drop (installed at
# /var/ossec/active-response/bin/firewall-drop, a compiled Wazuh binary --
# confirmed via `cat`/strings in-container, not a shell script on this
# version) expects the full Wazuh AR JSON envelope
# (version/origin/command/parameters.alert.data.srcip etc.) constructed
# and dispatched by the manager itself; hand-forging that envelope from
# inside another AR script just to shell out to a binary that ultimately
# runs two iptables calls is worse than doing those two iptables calls
# directly. The strings in that binary confirm exactly what it does on
# Linux: insert a DROP rule for the source IP into both INPUT and
# FORWARD. That is reproduced verbatim below, so the resulting block is
# functionally identical to what firewall-drop would have done --
# confirmed live against `iptables -L -n` in Task 8 verification.
set -eu

REQUEST_LOG="/app/target/logs/requests.jsonl"
THRESHOLD=5
WINDOW_SECONDS=60

# Task 8 fix-round (live verification): see bruteforce-guard.sh for the
# full explanation -- wazuh-execd never sends EOF on this child's stdin,
# so `$(cat)` hangs forever. `read -r` only needs the single newline
# execd writes after the JSON payload.
IFS= read -r INPUT_JSON
SRCIP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip | select(. != null and . != "null")')

# No source IP decoded -> nothing to count against or block. Exit quietly.
if [ -z "${SRCIP:-}" ]; then
    exit 0
fi

if [ ! -f "$REQUEST_LOG" ]; then
    exit 0
fi

NOW_EPOCH=$(date -u +%s)
CUTOFF_EPOCH=$((NOW_EPOCH - WINDOW_SECONDS))

# Same event shape rule 100105 matches (GET /documents/<id>), scoped to
# this source IP, timestamps only -- one per line.
TIMESTAMPS=$(jq -r --arg ip "$SRCIP" '
    select(.method == "GET" and (.path | test("^/documents/[0-9]+$")) and .remote_addr == $ip)
    | .timestamp
' "$REQUEST_LOG" 2>/dev/null || true)

COUNT=0
if [ -n "$TIMESTAMPS" ]; then
    while IFS= read -r ts; do
        [ -z "$ts" ] && continue
        # See bruteforce-guard.sh: GNU `date -d` parses Python's
        # isoformat() output natively; jq's fromdateiso8601 does not.
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

# Real threshold crossed -- block the source IP at the network layer for
# real, same action firewall-drop's own binary performs on this platform.
iptables -I INPUT -s "$SRCIP" -j DROP
iptables -I FORWARD -s "$SRCIP" -j DROP
