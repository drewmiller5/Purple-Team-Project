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
# Strategy: run scripts fetched from EXPLICIT, PINNED git commits against
# the same crafted requests.jsonl + AR stdin payload, and assert behavior
# diverges exactly the way each fix predicts:
#   - H49 (window starvation): 6000 decoy lines pushed in front of 5 real
#     matching lines defeats the old `tail -n 5000` cap (real matches
#     fall outside the tail) but not a time-scoped full-file scan.
#   - H34 (silent jq failure): a malformed line mid-window makes the old
#     streaming jq pipeline undercount and exit 0 silently; a fixed
#     pipeline detects the failure via $? and logs it.
#   - Regression found in dual review of the H34/H49 fix itself (commit
#     56a72bb): that fix's `jq -s` full-file slurp requires the ENTIRE,
#     never-rotated request log to parse cleanly on every invocation --
#     one malformed line anywhere in the log's history (not just the
#     current window) permanently breaks counting for both guard scripts
#     for the rest of the round, once written. Scenario C below proves
#     this against the pinned 56a72bb commit and proves the re-fix (in
#     the current working tree) tolerates a stale malformed line by
#     skipping it instead of failing the whole scan.
#
# Fix-review note (code review of 56a72bb/fd3e747): this harness used to
# fetch its "pre-fix" comparison arm via `git show HEAD:...`, which only
# worked correctly in the narrow window before 56a72bb was itself merged
# past HEAD. Every comparison arm below is now pinned to an EXPLICIT
# commit SHA (never HEAD or a floating ref) specifically so this harness
# keeps meaning what it says regardless of how much further `main` moves.
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

# Build a runnable copy of a script from an explicit source, with its
# hardcoded absolute paths redirected into $WORKDIR so this test doesn't
# need root, a container, or /app//var/ossec to exist on the test host.
make_runnable_copy() {
    script_name="$1"      # bruteforce-guard.sh | idor-guard.sh
    source_ref="$2"       # "worktree" for the current working-tree file,
                           # or an explicit, pinned git commit SHA (never
                           # HEAD or a branch name -- see header note)
    out_path="$3"
    req_log="$4"
    ar_log="$5"

    if [ "$source_ref" = "worktree" ]; then
        cat "$REPO_ROOT/wazuh/active-response/$script_name" > "$out_path"
    else
        (cd "$REPO_ROOT" && git show "${source_ref}:wazuh/active-response/$script_name") > "$out_path"
    fi
    # Portable in-place-ish edit: sed to a temp file then move over.
    sed -e "s#/app/target/logs/requests.jsonl#${req_log}#g" \
        -e "s#/var/ossec/logs/active-responses.log#${ar_log}#g" \
        "$out_path" > "${out_path}.tmp"
    mv "${out_path}.tmp" "$out_path"
    chmod +x "$out_path"
}

# Pinned commits, not floating refs -- see header note. 56a72bb is the
# H34/H49 fix itself (contains the jq -s poison-pill regression);
# 56a72bb^ is its immediate parent, the genuine pre-fix baseline.
PREFIX_COMMIT="56a72bb^"
REGRESSED_COMMIT="56a72bb"

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

make_runnable_copy "bruteforce-guard.sh" "$PREFIX_COMMIT" "$OLD_SCRIPT_A" "$REQ_LOG_A" "$OLD_AR_LOG_A"
make_runnable_copy "bruteforce-guard.sh" "worktree"       "$NEW_SCRIPT_A" "$REQ_LOG_A" "$NEW_AR_LOG_A"

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
# Scenario B (H34, 3-way): malformed line INSIDE the counting window.
# 3 real matches, then 1 malformed (non-JSON) line, then 3 more real
# matches (6 total, >= THRESHOLD=5 if all were counted).
#   - true pre-fix (PREFIX_COMMIT): old streaming jq flushes the
#     pre-crash 3 matches to wc -l before dying on the bad line ->
#     COUNT=3 < 5 -> silent exit 0, nothing logged (the original H34 bug).
#   - regressed (REGRESSED_COMMIT, 56a72bb): `jq -s` slurp fails
#     atomically on the same bad line -> exit 1, logged as a hard
#     failure -- correct detection, but throws away the 6 real matches
#     along with the 1 bad line.
#   - fixed (worktree): skips the one malformed line, still counts all 6
#     real matches, crosses THRESHOLD, and attempts the real block.
# ---------------------------------------------------------------------
echo "=== Scenario B: H34 malformed-line-in-window, 3-way (idor-guard.sh) ==="

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
REGRESSED_SCRIPT_B="$WORKDIR/regressed-idor-guard.sh"
NEW_SCRIPT_B="$WORKDIR/new-idor-guard.sh"
OLD_AR_LOG_B="$WORKDIR/old-active-responses-b.log"
REGRESSED_AR_LOG_B="$WORKDIR/regressed-active-responses-b.log"
NEW_AR_LOG_B="$WORKDIR/new-active-responses-b.log"
: > "$OLD_AR_LOG_B"
: > "$REGRESSED_AR_LOG_B"
: > "$NEW_AR_LOG_B"

make_runnable_copy "idor-guard.sh" "$PREFIX_COMMIT"    "$OLD_SCRIPT_B"       "$REQ_LOG_B" "$OLD_AR_LOG_B"
make_runnable_copy "idor-guard.sh" "$REGRESSED_COMMIT" "$REGRESSED_SCRIPT_B" "$REQ_LOG_B" "$REGRESSED_AR_LOG_B"
make_runnable_copy "idor-guard.sh" "worktree"           "$NEW_SCRIPT_B"       "$REQ_LOG_B" "$NEW_AR_LOG_B"

set +e
printf '%s\n' "$AR_PAYLOAD_B" | sh "$OLD_SCRIPT_B" >/dev/null 2>&1
OLD_EXIT_B=$?
printf '%s\n' "$AR_PAYLOAD_B" | sh "$REGRESSED_SCRIPT_B" >/dev/null 2>&1
REGRESSED_EXIT_B=$?
printf '%s\n' "$AR_PAYLOAD_B" | sh "$NEW_SCRIPT_B" >/dev/null 2>&1
NEW_EXIT_B=$?
set -e

echo "  pre-fix exit=$OLD_EXIT_B, regressed exit=$REGRESSED_EXIT_B, fixed exit=$NEW_EXIT_B"

if [ "$OLD_EXIT_B" -eq 0 ] && [ ! -s "$OLD_AR_LOG_B" ]; then
    pass "true pre-fix script silently exits 0 with nothing logged (undercounts past the malformed line, exactly the original H34 bug)"
else
    fail "pre-fix script was expected to exit 0 with an empty log but got exit=$OLD_EXIT_B, log-size=$(wc -c < "$OLD_AR_LOG_B" 2>/dev/null || echo '?')"
fi

if [ "$REGRESSED_EXIT_B" -ne 0 ] && grep -q "jq counting pipeline failed" "$REGRESSED_AR_LOG_B"; then
    pass "regressed (56a72bb) script detects the jq failure and logs it -- correct detection, but discards all 6 real matches along with the 1 bad line"
else
    fail "regressed script was expected to exit non-zero and log a jq-failure line, got exit=$REGRESSED_EXIT_B, log=[$(cat "$REGRESSED_AR_LOG_B" 2>/dev/null)]"
fi

if [ "$NEW_EXIT_B" -ne 0 ] && ! grep -q "jq counting pipeline failed" "$NEW_AR_LOG_B"; then
    pass "fixed script skips the one malformed line, still counts all 6 real matches, and attempts the real block (no false jq-failure report)"
else
    fail "fixed script was expected to skip the bad line and count the real matches, got exit=$NEW_EXIT_B, log=[$(cat "$NEW_AR_LOG_B" 2>/dev/null)]"
fi

# ---------------------------------------------------------------------
# Scenario C (HIGH regression found in dual review of 56a72bb): a STALE
# malformed line -- written long before the current burst, entirely
# outside any window that matters now -- permanently blocks ALL future
# counting under the regression, because `jq -s` must parse the file's
# ENTIRE history on every invocation regardless of window position.
# 1 malformed line first, then 5 real matches (all recent, crosses
# THRESHOLD=5) with nothing between them and the malformed line.
#   - regressed (56a72bb): fails and logs, even though the bad line is
#     irrelevant to the current window -- the exact HIGH finding.
#   - fixed (worktree): skips the stale bad line regardless of its
#     position, counts the real recent burst, attempts the block.
# ---------------------------------------------------------------------
echo "=== Scenario C: stale malformed line permanently poisons counting (bruteforce-guard.sh) ==="

REQ_LOG_C="$WORKDIR/requests-c.jsonl"
: > "$REQ_LOG_C"
echo 'this is not valid json either' >> "$REQ_LOG_C"
i=0
while [ "$i" -lt 5 ]; do
    ts=$(iso_ts $((BASE_EPOCH + 10000 + i)))
    printf '{"path":"/admin/login","method":"POST","remote_addr":"203.0.113.55","status_code":200,"form_params":{"username":"admin"},"timestamp":"%s"}\n' "$ts" >> "$REQ_LOG_C"
    i=$((i + 1))
done

EVENT_EPOCH_C=$((BASE_EPOCH + 10004))
EVENT_TS_C=$(iso_ts "$EVENT_EPOCH_C")
AR_PAYLOAD_C=$(printf '{"command":"add","parameters":{"alert":{"data":{"srcip":"203.0.113.55","timestamp":"%s"}}}}' "$EVENT_TS_C")

REGRESSED_SCRIPT_C="$WORKDIR/regressed-bruteforce-guard.sh"
NEW_SCRIPT_C="$WORKDIR/new-bruteforce-guard.sh"
REGRESSED_AR_LOG_C="$WORKDIR/regressed-active-responses-c.log"
NEW_AR_LOG_C="$WORKDIR/new-active-responses-c.log"
: > "$REGRESSED_AR_LOG_C"
: > "$NEW_AR_LOG_C"

make_runnable_copy "bruteforce-guard.sh" "$REGRESSED_COMMIT" "$REGRESSED_SCRIPT_C" "$REQ_LOG_C" "$REGRESSED_AR_LOG_C"
make_runnable_copy "bruteforce-guard.sh" "worktree"           "$NEW_SCRIPT_C"       "$REQ_LOG_C" "$NEW_AR_LOG_C"

set +e
printf '%s\n' "$AR_PAYLOAD_C" | sh "$REGRESSED_SCRIPT_C" >/dev/null 2>&1
REGRESSED_EXIT_C=$?
printf '%s\n' "$AR_PAYLOAD_C" | sh "$NEW_SCRIPT_C" >/dev/null 2>&1
NEW_EXIT_C=$?
set -e

echo "  regressed (56a72bb) exit=$REGRESSED_EXIT_C, fixed exit=$NEW_EXIT_C"

if [ "$REGRESSED_EXIT_C" -eq 1 ] && grep -q "jq counting pipeline failed" "$REGRESSED_AR_LOG_C"; then
    pass "regressed (56a72bb) script permanently refuses to count once ANY malformed line exists anywhere in the log, even one that's irrelevant to the current window -- exactly the HIGH regression this fix closes"
else
    fail "regressed script was expected to fail with 'jq counting pipeline failed' due to the stale malformed line, got exit=$REGRESSED_EXIT_C, log=[$(cat "$REGRESSED_AR_LOG_C" 2>/dev/null)]"
fi

if [ "$NEW_EXIT_C" -ne 0 ] && ! grep -q "jq counting pipeline failed" "$NEW_AR_LOG_C"; then
    pass "fixed script skips the stale malformed line and still correctly counts and escalates the real, recent burst"
else
    fail "fixed script was expected to skip the malformed line and attempt escalation, got exit=$NEW_EXIT_C, log=[$(cat "$NEW_AR_LOG_C" 2>/dev/null)]"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL PASS"
    exit 0
else
    echo "$FAILURES assertion(s) failed"
    exit 1
fi
