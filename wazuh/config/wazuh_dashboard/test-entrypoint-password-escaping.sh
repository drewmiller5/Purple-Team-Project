#!/bin/sh
# wazuh/config/wazuh_dashboard/test-entrypoint-password-escaping.sh
#
# Regression test for the Task 8 second fix round (dual-review finding #1):
# entrypoint.sh used to build wazuh.yml with
#   sed "s|WAZUH_API_PASSWORD_PLACEHOLDER|${API_PASSWORD}|" template > dest
# sed's replacement string treats `&` as "insert the whole match" -- not a
# literal ampersand -- so any API_PASSWORD containing `&` (explicitly in
# .env.example's allowed complexity charset: @$!%*?&-_.) got silently
# corrupted. A password containing the `|` delimiter broke the sed command
# itself. The fix replaced sed with bash `${var//search/replace}`
# parameter expansion, which is a literal substring replace with no
# metacharacters on the replacement side.
#
# No container/Docker is required to prove this -- the bug and fix live
# entirely in string-substitution semantics. This makes a runnable copy of
# entrypoint.sh with its two hardcoded absolute container paths redirected
# into a workdir and its `exec /bin/bash /entrypoint.sh` tail replaced with
# `exit 0` (same "make_runnable_copy" approach as
# wazuh/active-response/test-guard-counting.sh).
#
# Usage: sh wazuh/config/wazuh_dashboard/test-entrypoint-password-escaping.sh
# Exit 0 and prints "ALL PASS" if every assertion holds; exit 1 otherwise.

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC="$REPO_ROOT/wazuh/config/wazuh_dashboard/entrypoint.sh"
TEMPLATE_SRC="$REPO_ROOT/wazuh/config/wazuh_dashboard/wazuh.yml"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

FAILURES=0
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $1"; }

RUNNABLE="$WORKDIR/entrypoint-under-test.sh"
DEST_DIR="$WORKDIR/dest_config"

sed -e "s#/wazuh_dashboard_config_template/wazuh.yml#$WORKDIR/template.yml#" \
    -e "s#/usr/share/wazuh-dashboard/data/wazuh/config#$DEST_DIR#" \
    -e "s#exec /bin/bash /entrypoint.sh#exit 0#" \
    "$SRC" > "$RUNNABLE"
chmod +x "$RUNNABLE"
cp "$TEMPLATE_SRC" "$WORKDIR/template.yml"

run_with_password() {
    pw="$1"
    rm -rf "$DEST_DIR"
    API_PASSWORD="$pw" sh "$RUNNABLE"
    grep 'password:' "$DEST_DIR/wazuh.yml" | sed -e 's/^[[:space:]]*password: "//' -e 's/"$//'
}

echo "=== Case 1: password containing '&' (allowed by .env.example's charset) ==="
PW1='Aa1!&aaaa'
GOT1=$(run_with_password "$PW1")
echo "  input=[$PW1] output=[$GOT1]"
if [ "$GOT1" = "$PW1" ]; then
    pass "'&'-containing password round-trips byte-for-byte (old sed corrupted this to Aa1!WAZUH_API_PASSWORD_PLACEHOLDERaaaa)"
else
    fail "expected [$PW1], got [$GOT1]"
fi

echo "=== Case 2: password containing '|' (the old sed delimiter) ==="
PW2='Aa1!|bbbb'
GOT2=$(run_with_password "$PW2")
echo "  input=[$PW2] output=[$GOT2]"
if [ "$GOT2" = "$PW2" ]; then
    pass "'|'-containing password round-trips byte-for-byte (old sed command would have been malformed)"
else
    fail "expected [$PW2], got [$GOT2]"
fi

echo "=== Case 3: password containing backslash + full allowed charset ==="
PW3='Aa1@\$!%*?&-_.9'
GOT3=$(run_with_password "$PW3")
echo "  input=[$PW3] output=[$GOT3]"
if [ "$GOT3" = "$PW3" ]; then
    pass "backslash+full-charset password round-trips byte-for-byte"
else
    fail "expected [$PW3], got [$GOT3]"
fi

echo "=== Case 4: destination file permissions ==="
API_PASSWORD='Aa1!plain' sh "$RUNNABLE" >/dev/null
PERMS=$(stat -c '%a' "$DEST_DIR/wazuh.yml" 2>/dev/null || stat -f '%Lp' "$DEST_DIR/wazuh.yml")
echo "  perms=$PERMS"
if [ "$PERMS" = "600" ]; then
    pass "dest file is chmod 600 (not world-readable default)"
elif [ "$(uname -o 2>/dev/null)" = "Msys" ] || [ "$(uname -o 2>/dev/null)" = "Cygwin" ]; then
    echo "  SKIP: chmod ran without error, but NTFS/MSYS does not represent POSIX"
    echo "  owner/group/other bits the same way Linux does, so 600 can't be"
    echo "  observed from here -- the entrypoint runs in a Linux container at"
    echo "  runtime (Wazuh's Debian-based dashboard image), where chmod 600"
    echo "  behaves normally. Not counted as a failure."
else
    fail "expected perms 600, got $PERMS"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL PASS"
    exit 0
else
    echo "$FAILURES assertion(s) failed"
    exit 1
fi
