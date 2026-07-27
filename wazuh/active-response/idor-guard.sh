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
#   1. Pull the source IP AND the triggering event's own timestamp Wazuh
#      decoded for this event (srcip / data.timestamp).
#   2. Count matching GETs to /documents/<id> from that same source IP in
#      target's own request log within 60 seconds of THAT event (the
#      original rule's intended window).
#   3. Only at >=5 matches (the original rule's intended threshold) does
#      it actually block -- by inserting real iptables DROP rules against
#      the source IP.
#   4. Below threshold: exit 0 with no output.
#
# Why replicate iptables directly instead of invoking the stock
# firewall-drop binary: firewall-drop (installed at
# /var/ossec/active-response/bin/firewall-drop, a compiled Wazuh binary --
# confirmed via strings-equivalent inspection in-container, not a shell
# script on this version) expects the full Wazuh AR JSON envelope
# (version/origin/command/parameters.alert.data.srcip etc.) constructed
# and dispatched by the manager itself; hand-forging that envelope from
# inside another AR script just to shell out to a binary that ultimately
# runs iptables calls is worse than doing those iptables calls directly.
# Inspecting that binary's embedded strings confirms exactly what it does
# on Linux and what payload shape it expects -- reproduced below (both
# the block itself, and per fix round 1, the reversal), so the resulting
# behavior is functionally identical to what firewall-drop provides --
# confirmed live against `iptables -L -n` in Task 8 verification.
#
# Fix round 1 (task reviewer finding #4): unlike firewall-drop (see its
# binding two blocks up in wazuh_manager.conf: <timeout>600</timeout>),
# this script's blocks used to be permanent with no reversal path -- no
# <timeout_allowed>/<timeout> in the config, and no delete-mode branch
# here. Wazuh's AR JSON payload carries the dispatch mode in its
# top-level "command" field ("add" or "delete") -- confirmed by
# inspecting the vendored firewall-drop binary's embedded strings, which
# read/validate exactly this field ("command", "delete", "Invalid value
# of 'command'", "Cannot read 'command' from json"), not argv[1]. This
# script now branches on that field: "add" runs the counting logic below
# as before; "delete" reverses a real block with `iptables -D` (never
# `-F`, which would also remove unrelated rules -- e.g. firewall-drop's
# own SQLi/command-injection blocks -- present at delete time).
#
# One extra wrinkle specific to this script (not present for
# firewall-drop): execd dispatches an "add" for EVERY GET matching rule
# 100105 (every single request, per the design above), and once
# <timeout> is configured it will schedule a "delete" for EVERY one of
# those "add" dispatches -- regardless of whether this script's own
# threshold logic actually inserted a block for that particular "add".
# Since most "add" dispatches are below-threshold no-ops, a naive
# unconditional delete-mode handler would eventually run `iptables -D`
# for source IPs that were never blocked by *that* dispatch -- and, worse,
# could delete a block that a *later*, real threshold-crossing dispatch
# for the same IP had legitimately put in place (iptables rules for the
# same IP are content-identical; there's no way to correlate a specific
# add dispatch to a specific delete dispatch beyond that). To keep
# deletes count-matched to real adds, a small per-source-IP counter file
# tracks how many real blocks this script has actually inserted; delete
# mode only runs `iptables -D` (and decrements) when that counter is
# still positive, so a spurious delete from a below-threshold dispatch
# can never remove a genuine block.
#
# Fix round 2 (task reviewer finding: non-atomic counter race): the
# STATE_FILE read-modify-write above (cat, arithmetic, echo >) was not
# atomic across concurrent invocations. execd can and does dispatch
# multiple "add"s for the same source IP close together (empirically
# observed in this project's own live testing -- 4 duplicate DROP rules
# from a single burst); two such invocations racing on the same
# STATE_FILE can both read the same stale counter value and both write
# value+1, losing an increment. If the counter under-counts the true
# number of blocks actually inserted, a later "delete" dispatch stops
# reversing once the (too-low) counter hits zero, leaving a genuine
# DROP rule stuck forever -- silently reintroducing the exact
# stale-rule failure mode fix round 1 closed. Both the "add" and
# "delete" code paths now serialize their counter read-modify-write
# through a per-source-IP flock (STATE_DIR/$SRCIP.lock, confirmed
# present in this image: flock ships in util-linux, an Essential/
# Priority:required Debian package present on every Debian-based image
# regardless of what target/Dockerfile explicitly apt-get installs, so
# no Dockerfile change was needed). flock's lock is tied to the open
# file descriptor, not a lockfile's mere existence, so it releases
# automatically if the holding process crashes or is killed mid
# critical-section -- unlike a hand-rolled mkdir/lockfile scheme, which
# would need its own staleness timeout to keep a crash from wedging all
# future invocations permanently. No -w/timeout is used when acquiring
# it: the critical section is a handful of filesystem ops (sub-
# millisecond), so there is no real wait-time concern, and a timeout
# here would risk the alternative failure mode of silently dropping a
# real increment (the exact bug being fixed) rather than just briefly
# blocking. Per-IP (not a single global lock) so concurrent dispatches
# for different source IPs never contend with each other.
set -eu

REQUEST_LOG="/app/target/logs/requests.jsonl"
THRESHOLD=5
WINDOW_SECONDS=60
# Finding #2: bound how much of the log gets scanned per invocation
# instead of the whole (ever-growing) file -- see bruteforce-guard.sh for
# the full rationale.
TAIL_LINES=5000
# Fix round 1 finding #4: per-source-IP count of real blocks this script
# has inserted but not yet reversed. /tmp is used deliberately -- it is
# NOT part of any bind mount back to the host repo (unlike
# /var/ossec/active-response/bin itself), so this is purely in-container
# runtime state, not something that leaks into version control.
STATE_DIR="/tmp/idor-guard-state"

# Task 8 fix-round (live verification): see bruteforce-guard.sh for the
# full explanation -- wazuh-execd never sends EOF on this child's stdin,
# so `$(cat)` hangs forever. `read -r` only needs the single newline
# execd writes after the JSON payload.
IFS= read -r INPUT_JSON

# Fix round 1 finding #4: dispatch mode ("add" on every rule match,
# "delete" once <timeout> seconds after each "add" -- see file header).
COMMAND=$(echo "$INPUT_JSON" | jq -r '.command | select(. != null and . != "null")')
SRCIP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip | select(. != null and . != "null")')

# No source IP decoded -> nothing to count against, block, or reverse.
# Exit quietly.
if [ -z "${SRCIP:-}" ]; then
    exit 0
fi

mkdir -p "$STATE_DIR" 2>/dev/null || true
STATE_FILE="$STATE_DIR/$SRCIP"

if [ "$COMMAND" = "delete" ]; then
    # Fix round 2: whole read-decide-write cycle serialized per source
    # IP via flock on an already-open fd (see header for why flock over
    # a hand-rolled lockfile). fd 9 -- confirmed empirically in this
    # image's actual /bin/sh (dash) that `exec N>file` only supports
    # single-digit N; a higher fd (tried 200 during development to dodge
    # a theoretical collision with execd's own fds) fails outright with
    # `exec: 200: not found`, which under `set -eu` aborts the script
    # AFTER the iptables insert already ran -- silently leaving a real
    # block with no counter entry, i.e. reintroducing the exact
    # stuck-rule bug this fix exists to close, for a different reason.
    # fd 9 is unused by execd itself (checked live: execd's own open fds
    # are only 0-4), so it's both safe and the only reliable choice
    # under this shell.
    LOCK_FILE="$STATE_DIR/$SRCIP.lock"
    exec 9>"$LOCK_FILE"
    flock -x 9
    ACTIVE_BLOCKS=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
    case "$ACTIVE_BLOCKS" in ''|*[!0-9]*) ACTIVE_BLOCKS=0 ;; esac
    if [ "$ACTIVE_BLOCKS" -gt 0 ]; then
        # Remove exactly one INPUT + one FORWARD rule for this IP --
        # never a blanket `-F` flush, which would also drop unrelated
        # rules (e.g. firewall-drop's own blocks for other IPs/vulns).
        iptables -D INPUT -s "$SRCIP" -j DROP 2>/dev/null || true
        iptables -D FORWARD -s "$SRCIP" -j DROP 2>/dev/null || true
        echo $((ACTIVE_BLOCKS - 1)) > "$STATE_FILE"
    fi
    flock -u 9
    exit 0
fi

# Anything other than an explicit "delete" is treated as "add" (matches
# the manual-invocation convention already used for verification).
if [ ! -f "$REQUEST_LOG" ]; then
    exit 0
fi

# Fix round 1 finding #3: anchor the counting window to the triggering
# event's OWN timestamp (data.timestamp), not wall-clock time at
# script-invocation -- see bruteforce-guard.sh for the full rationale.
EVENT_TS=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.timestamp | select(. != null and . != "null")')
[ -z "${EVENT_TS:-}" ] && exit 0

# jq's fromdateiso8601 only accepts the strict "%Y-%m-%dT%H:%M:%SZ" form;
# normalize Python's isoformat() output via jq's own sub() -- still a
# single jq invocation, no external `date` subprocess (finding #2).
EVENT_EPOCH=$(echo "$EVENT_TS" | jq -R -r '
    sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601
' 2>/dev/null) || exit 0
[ -z "${EVENT_EPOCH:-}" ] && exit 0
CUTOFF_EPOCH=$((EVENT_EPOCH - WINDOW_SECONDS))

# Single jq pass over a bounded tail of the log: matches rule 100105's
# own field conditions, scoped to this source IP, filtered to the
# event-anchored window -- no per-line `date` subprocess, no full-file
# scan.
COUNT=$(tail -n "$TAIL_LINES" "$REQUEST_LOG" 2>/dev/null | jq -r --arg ip "$SRCIP" --argjson cutoff "$CUTOFF_EPOCH" '
    select(.method == "GET" and (.path | test("^/documents/[0-9]+$")) and .remote_addr == $ip)
    | .timestamp
    | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z")
    | fromdateiso8601
    | select(. >= $cutoff)
' 2>/dev/null | wc -l | tr -d ' ')

if [ "$COUNT" -lt "$THRESHOLD" ]; then
    exit 0
fi

# Real threshold crossed -- block the source IP at the network layer for
# real, same action firewall-drop's own binary performs on this platform.
#
# Final-review fix (finding #3): this script previously blocked with no
# log line at all -- for a purple-team lab whose deliverable is the
# observable detection->response chain, a real block with nothing
# recording that it happened is a real gap.
#
# Deviation from the finding's suggested implementation: a plain `echo`
# to stdout does NOT get captured into active-responses.log -- verified
# empirically live (both for a bare echo here AND for lock-account.sh's
# existing `curl -s` output, which also does not appear there despite a
# real, confirmed lock-account block). The compiled Wazuh AR binaries
# (firewall-drop, disable-account, etc., confirmed as actual ELF binaries
# in this image, not shell scripts) write to that log via their own
# internal logging, not via execd capturing stdout -- there is no shared
# active-response.sh helper library in this Wazuh 4.9.2 image for custom
# scripts to source either. So the only way to actually land a line in
# active-responses.log is to append to it directly, which is what this
# does instead. This one line only lives on the threshold-crossing path;
# the below-threshold no-op above stays silent/cheap on purpose (that's
# the hot path -- fires on every single GET).
echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/idor-guard: threshold ${THRESHOLD} crossed for ${SRCIP} (count=${COUNT}), inserting DROP" >> /var/ossec/logs/active-responses.log
iptables -I INPUT -s "$SRCIP" -j DROP
iptables -I FORWARD -s "$SRCIP" -j DROP

# Record that this script inserted a real, reversible block for this IP
# (fix round 1 finding #4) so a later "delete" dispatch knows to actually
# reverse it. Fix round 2: read-modify-write serialized per source IP via
# flock, same mechanism, lock file, and fd 9 (see delete path above for
# why fd 9 specifically) as the delete path.
LOCK_FILE="$STATE_DIR/$SRCIP.lock"
exec 9>"$LOCK_FILE"
flock -x 9
ACTIVE_BLOCKS=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
case "$ACTIVE_BLOCKS" in ''|*[!0-9]*) ACTIVE_BLOCKS=0 ;; esac
echo $((ACTIVE_BLOCKS + 1)) > "$STATE_FILE"
flock -u 9
