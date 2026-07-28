#!/bin/sh
# wazuh/active-response/lock-account.sh
#
# Task 7 fix-round 2 (security review): rewritten to parse the AR JSON
# payload with jq instead of a flat regex/grep scan. The regex approach
# (grep -o '"username":"[^"]*"' | cut -d'"' -f4) had the same structural
# blind spot as the original kill-session.sh bug: target/logging_middleware.py
# logs the full unfiltered request.args (data.query_params) AND
# request.form (data.form_params) separately, so an attacker could add a
# decoy `?username=...` query-string param on top of the real POST body
# username, producing two "username":"..." occurrences in the payload
# that a plain regex can't disambiguate.
#
# data.form_params.username IS the correct field here -- for a login POST,
# the form body's username is genuinely the value the attacker/user
# submitted and rule 100103/100104 matched on (there's no separate
# "true" username elsewhere the way user_id has a session-derived source
# of truth). The fix is jq's structured lookup reading ONLY that exact
# path, so a colliding query_params.username can never be selected
# instead.
#
# H33 fix: set -eu placed at the top of the script (see below) so any
# upstream failure here (malformed INPUT_JSON making jq error out, etc.)
# aborts the script instead of silently falling through to the final
# curl call with an empty/garbage USERNAME while still exiting 0.
set -eu

# Note (Task 8): this script is invoked in two ways -- directly by
# bruteforce-guard.sh via `echo "$INPUT_JSON" | lock-account.sh` (a real
# pipe close/EOF as soon as echo exits), and it has no <active-response>
# binding of its own in wazuh_manager.conf (see that file's Task 8
# comment), so it is never invoked directly by execd. $(cat) is therefore
# not subject to the H32 hang (execd's stdin-never-closed behavior only
# matters for scripts execd spawns directly) and is left as-is here.
INPUT_JSON=$(cat)
USERNAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.form_params.username | select(. != null and . != "null")')

# Final-review fix (finding #6): USERNAME is attacker-influenced and was
# previously interpolated into the POST body unescaped (-d
# "username=${USERNAME}"). --data-urlencode percent-encodes the value
# instead of splicing it into the body raw -- no behavior change for
# well-formed input, but it removes the (low-impact, per reviewer)
# ambiguity of unescaped `&`/`=` characters in USERNAME being interpreted
# as additional form fields by curl/Flask's form parser.
#
# K3 fix: curl's own exit status only reflects transport-level failure
# (DNS, connection refused, etc.) -- a successful connection with a
# non-2xx HTTP response (target rejecting an empty/invalid username, an
# internal error, etc.) previously went completely unnoticed: curl still
# exited 0 and the script exited 0 right behind it, "reporting success"
# regardless of what target actually did. -w '%{http_code}' captures the
# response status without a second request; -o /dev/null discards the
# body, which this script never inspects. Both failure modes are logged
# directly to active-responses.log -- the same mechanism idor-guard.sh's
# "Final-review fix" already established as the only way to get a custom
# AR script's own outcome into that log (Wazuh's compiled AR binaries
# write to it internally; execd does not capture custom scripts' stdout
# into it).
HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://target:5000/internal/lock-account -H "X-Internal-Action-Token: ${INTERNAL_ACTION_TOKEN:?INTERNAL_ACTION_TOKEN is required}" --data-urlencode "username=${USERNAME}") || {
    echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/lock-account: curl request failed for username=${USERNAME}" >> /var/ossec/logs/active-responses.log
    exit 1
}

case "$HTTP_STATUS" in
    2??)
        echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/lock-account: locked username=${USERNAME} (http_status=${HTTP_STATUS})" >> /var/ossec/logs/active-responses.log
        ;;
    *)
        echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/lock-account: target returned http_status=${HTTP_STATUS} for username=${USERNAME}" >> /var/ossec/logs/active-responses.log
        exit 1
        ;;
esac
