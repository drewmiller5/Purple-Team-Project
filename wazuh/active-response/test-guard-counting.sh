#!/bin/sh
# wazuh/active-response/test-guard-counting.sh
#
# Shell-level verification for the H34/H49 fix (Phase 3 Task 5) to
# bruteforce-guard.sh / idor-guard.sh's counting jq pipeline. No .bats or
# other shell-test harness exists anywhere in this repo for the AR
# scripts (K3/H32/H33/H37 were verified live against wazuh-logtest/a
# running manager instead, per the ledger) -- this fills that gap with a
# minimal, self-contained script instead of introducing a new framework.
#
# Strategy: run BOTH the pre-fix version of each script (fetched from git
# HEAD, the parent commit before this fix) and the current, fixed version
# against the same crafted requests.jsonl + AR stdin payload, and assert
# the two diverge exactly the way H34/H49 predict:
#   - H49 (window starvation): 6000 decoy lines pushed in front of 5 real
#     matching lines defeats the old `tail -n 5000` cap (real matches
#     fall outside the tail) but not the new time-scoped full-file scan.
#   - H34 (silent jq failure): a malformed line mid-window makes the old
#     streaming jq pipeline undercount and exit 0 silently; the new `-s`
#     pipeline fails atomically, is detected via $?, and is logged.
#
# Usage: sh wazuh/active-response/test-guard-counting.sh
# Exit 0 and prints "ALL PASS" if every assertion holds; exit 1 on any
# failure, printing which assertion failed.

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

FAILURES=0

fail() {
    echo "FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "PASS: $1"
}

# Build a runnable copy of a script (either the current working-tree
# fixed version, or the git-HEAD pre-fix version) with its hardcoded
# absolute paths redirected into $WORKDIR so this test doesn't need
# root, a container, or /app//var/ossec to exist on the test host.
make_runnable_copy() {
    script_name="$1"      # bruteforce-guard.sh | idor-guard.sh
    source_mode="$2"      # fixed | prefix
    out_path="$3"
    req_log="$4"
    ar_log="$5"

    if [ "$source_mode" = "fixed" ]; then
        cat "$REPO_ROOT/wazuh/active-response/$script_name" > "$out_path"
    else
        (cd "$REPO_ROOT" && git show "HEAD:wazuh/active-response/$script_name") > "$out_path"
    fi
    # Portable in-place-ish edit: sed to a temp file then move over.
    sed -e "s#/app/target/logs/requests.jsonl#${req_log}#g" \
        -e "s#/var/ossec/logs/active-responses.log#${ar_log}#g" \
        "$out_path" > "${out_path}.tmp"
    mv "${out_path}.tmp" "$out_path"
    chmod +x "$out_path"
}

iso_ts() {
    # $1 = epoch seconds -> Python-isoformat-shaped UTC timestamp, the
    # same shape target/logging_middleware.py actually emits.
    date -u -d "@$1" '+%Y-%m-%dT%H:%M:%S.000000+00:00' 2>/dev/null \
        || date -u -r "$1" '+%Y-%m-%dT%H:%M:%S.000000+00:00'
}

BASE_EPOCH=1750000000

# ---------------------------------------------------------------------
# Scenario A (H49): decoy-flood window starvation.
# 5 real matching lines (oldest), then 6000 unrelated decoy lines.
# Old tail-n-5000 cap pushes the 5 real matches out of view -> COUNT=0,
# silent exit 0. New full-file time-scoped scan still finds them ->
# COUNT=5 >= THRESHOLD -> attempts to hand off to lock-account.sh
# (path doesn't exist on this host) -> nonzero exit, proving the action
# was actually attempted this time.
# ---------------------------------------------------------------------
echo "=== Scenario A: H49 window-starvation (bruteforce-guard.sh) ==="

REQ_LOG_A="$WORKDIR/requests-a.jsonl"
: > "$REQ_LOG_A"
i=0
while [ "$i" -lt 5 ]; do
    ts=$(iso_ts $((BASE_EPOCH + i)))
    printf '{"path":"/admin/login","method":"POST","remote_addr":"203.0.113.9","status_code":200,"form_params":{"username":"admin"},"timestamp":"%s"}\n' "$ts" >> "$REQ_LOG_A"
    i=$((i + 1))
done
DECOY_TS=$(iso_ts $((BASE_EPOCH + 6000)))
i=0
while [ "$i" -lt 6000 ]; do
    printf '{"path":"/other","method":"GET","remote_addr":"203.0.113.9","status_code":200,"form_params":{},"timestamp":"%s"}\n' "$DECOY_TS"
    i=$((i + 1))
done >> "$REQ_LOG_A"

EVENT_EPOCH_A=$((BASE_EPOCH + 100))
EVENT_TS_A=$(iso_ts "$EVENT_EPOCH_A")
AR_PAYLOAD_A=$(printf '{"command":"add","parameters":{"alert":{"data":{"srcip":"203.0.113.9","timestamp":"%s"}}}}' "$EVENT_TS_A")

OLD_SCRIPT_A="$WORKDIR/old-bruteforce-guard.sh"
NEW_SCRIPT_A="$WORKDIR/new-bruteforce-guard.sh"
OLD_AR_LOG_A="$WORKDIR/old-active-responses-a.log"
NEW_AR_LOG_A="$WORKDIR/new-active-responses-a.log"
: > "$OLD_AR_LOG_A"
: > "$NEW_AR_LOG_A"

make_runnable_copy "bruteforce-guard.sh" "prefix" "$OLD_SCRIPT_A" "$REQ_LOG_A" "$OLD_AR_LOG_A"
make_runnable_copy "bruteforce-guard.sh" "fixed"  "$NEW_SCRIPT_A" "$REQ_LOG_A" "$NEW_AR_LOG_A"

set +e
printf '%s\n' "$AR_PAYLOAD_A" | sh "$OLD_SCRIPT_A" >/dev/null 2>&1
OLD_EXIT_A=$?
printf '%s\n' "$AR_PAYLOAD_A" | sh "$NEW_SCRIPT_A" >/dev/null 2>&1
NEW_EXIT_A=$?
set -e

echo "  old (pre-fix) exit=$OLD_EXIT_A, new (fixed) exit=$NEW_EXIT_A"

if [ "$OLD_EXIT_A" -eq 0 ]; then
    pass "old pre-fix script silently exits 0 (misses the real burst, exactly the H49 bug)"
else
    fail "old pre-fix script was expected to exit 0 (silent miss) but exited $OLD_EXIT_A -- scenario construction may be wrong"
fi

if [ "$NEW_EXIT_A" -ne 0 ]; then
    pass "fixed script no longer exits 0 -- it counted the real burst despite 6000 decoys and attempted the lockout action"
else
    fail "fixed script exited 0 -- H49 window-starvation fix did not take effect"
fi

# ---------------------------------------------------------------------
# Scenario B (H34): malformed line mid-window silently undercounts.
# 3 real matches, then 1 malformed (non-JSON) line, then 3 more real
# matches (6 total, >= THRESHOLD=5 if all were counted). Old streaming
# jq flushes the pre-crash 3 matches to wc -l before dying on the bad
# line -> COUNT=3 < 5 -> silent exit 0, nothing logged. New `-s` slurp
# fails atomically on the same bad line -> exit 1, logged.
# ---------------------------------------------------------------------
echo "=== Scenario B: H34 malformed-line undercount (idor-guard.sh) ==="

REQ_LOG_B="$WORKDIR/requests-b.jsonl"
: > "$REQ_LOG_B"
i=0
while [ "$i" -lt 3 ]; do
    ts=$(iso_ts $((BASE_EPOCH + i)))
    printf '{"method":"GET","path":"/documents/42","remote_addr":"198.51.100.7","timestamp":"%s"}\n' "$ts" >> "$REQ_LOG_B"
    i=$((i + 1))
done
echo 'this is not valid json' >> "$REQ_LOG_B"
i=3
while [ "$i" -lt 6 ]; do
    ts=$(iso_ts $((BASE_EPOCH + i)))
    printf '{"method":"GET","path":"/documents/42","remote_addr":"198.51.100.7","timestamp":"%s"}\n' "$ts" >> "$REQ_LOG_B"
    i=$((i + 1))
done

EVENT_EPOCH_B=$((BASE_EPOCH + 5))
EVENT_TS_B=$(iso_ts "$EVENT_EPOCH_B")
AR_PAYLOAD_B=$(printf '{"command":"add","parameters":{"alert":{"data":{"srcip":"198.51.100.7","timestamp":"%s"}}}}' "$EVENT_TS_B")

OLD_SCRIPT_B="$WORKDIR/old-idor-guard.sh"
NEW_SCRIPT_B="$WORKDIR/new-idor-guard.sh"
OLD_AR_LOG_B="$WORKDIR/old-active-responses-b.log"
NEW_AR_LOG_B="$WORKDIR/new-active-responses-b.log"
: > "$OLD_AR_LOG_B"
: > "$NEW_AR_LOG_B"

make_runnable_copy "idor-guard.sh" "prefix" "$OLD_SCRIPT_B" "$REQ_LOG_B" "$OLD_AR_LOG_B"
make_runnable_copy "idor-guard.sh" "fixed"  "$NEW_SCRIPT_B" "$REQ_LOG_B" "$NEW_AR_LOG_B"

set +e
printf '%s\n' "$AR_PAYLOAD_B" | sh "$OLD_SCRIPT_B" >/dev/null 2>&1
OLD_EXIT_B=$?
printf '%s\n' "$AR_PAYLOAD_B" | sh "$NEW_SCRIPT_B" >/dev/null 2>&1
NEW_EXIT_B=$?
set -e

echo "  old (pre-fix) exit=$OLD_EXIT_B, new (fixed) exit=$NEW_EXIT_B"

if [ "$OLD_EXIT_B" -eq 0 ] && [ ! -s "$OLD_AR_LOG_B" ]; then
    pass "old pre-fix script silently exits 0 with nothing logged (undercounts past the malformed line, exactly the H34 bug)"
else
    fail "old pre-fix script was expected to exit 0 with an empty log but got exit=$OLD_EXIT_B, log-size=$(wc -c < "$OLD_AR_LOG_B" 2>/dev/null || echo '?')"
fi

if [ "$NEW_EXIT_B" -ne 0 ] && grep -q "jq counting pipeline failed" "$NEW_AR_LOG_B"; then
    pass "fixed script detects the jq failure, exits non-zero, and logs it instead of silently reporting below-threshold"
else
    fail "fixed script was expected to exit non-zero and log a jq-failure line, got exit=$NEW_EXIT_B, log=[$(cat "$NEW_AR_LOG_B" 2>/dev/null)]"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL PASS"
    exit 0
else
    echo "$FAILURES assertion(s) failed"
    exit 1
fi
