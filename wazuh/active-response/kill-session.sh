#!/bin/sh
# wazuh/active-response/kill-session.sh
#
# Task 7 fix-round 2 (security review): the prior regex-based extraction
# (grep -o '"user_id":[^,}]*' | tr -cd '0-9') did a flat text scan with no
# JSON structure awareness. target/logging_middleware.py logs the entire
# unfiltered request.form.to_dict() as data.form_params, so an attacker
# could add a decoy `user_id` field to their own command-injection POST
# (e.g. host=127.0.0.1;id&user_id=999) -- costing them nothing and not
# interfering with the injection. That produces TWO "user_id":"..."
# occurrences in the alert payload: the real one at the top level
# (data.user_id, from the Flask session) and the attacker-controlled one
# nested under data.form_params.user_id. The old regex matched and
# concatenated both digit sequences (e.g. "999" + "1" -> "9991"),
# blocking the wrong account while the real malicious session stayed
# alive -- reproduced and confirmed by the reviewer.
#
# Fixed by parsing the payload as real JSON with jq and reading only the
# single unambiguous top-level path, data.user_id -- never anything under
# form_params/query_params, which are attacker-controlled request data,
# not Wazuh's own decoded session-derived field.
#
# H33 fix: set -eu placed at the top of the script (see below) so any
# upstream failure here (malformed INPUT_JSON making jq error out, etc.)
# aborts the script instead of silently falling through to the final
# curl call with an empty/garbage USER_ID while still exiting 0.
set -eu

# H32 fix (Critical): this script is bound directly to Wazuh rule 100102
# via a live <active-response> block in wazuh_manager.conf (unlike
# lock-account.sh, which Task 8's own config comment confirms is no
# longer bound to any <active-response> block and is only ever invoked
# via bruteforce-guard.sh's `echo ... | script` pipe -- a real EOF).
# wazuh-execd on this Wazuh 4.9.2 build writes the AR JSON payload as a
# single line but never closes/EOFs the child's stdin afterward
# (confirmed empirically for bruteforce-guard.sh/idor-guard.sh -- see
# their headers: a hung `cat` subprocess was caught live via
# /proc/<pid>/task). `$(cat)` waits for EOF and therefore hangs forever,
# so on a real command-injection alert this script never reaches the
# curl call below at all. `read -r` only needs the single newline execd
# DOES write after the JSON object, so it returns immediately. Same fix,
# same root cause, as bruteforce-guard.sh/idor-guard.sh.
IFS= read -r INPUT_JSON
# Wazuh's JSON_Decoder serializes an absent/null value as the literal
# *string* "null" (not JSON null), so select() explicitly excludes both
# forms -- real JSON null (field truly absent) and the string "null"
# (unauthenticated request) -- leaving USER_ID empty in either case.
USER_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.user_id | select(. != null and . != "null")')

# K3 fix: curl's own exit status only reflects transport-level failure
# (DNS, connection refused, etc.) -- a successful connection with a
# non-2xx HTTP response (target rejecting an empty/invalid user_id, an
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
HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://target:5000/internal/kill-session --data-urlencode "user_id=${USER_ID}") || {
    echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/kill-session: curl request failed for user_id=${USER_ID}" >> /var/ossec/logs/active-responses.log
    exit 1
}

case "$HTTP_STATUS" in
    2??)
        echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/kill-session: killed session for user_id=${USER_ID} (http_status=${HTTP_STATUS})" >> /var/ossec/logs/active-responses.log
        ;;
    *)
        echo "$(date -u '+%Y/%m/%d %H:%M:%S') active-response/bin/kill-session: target returned http_status=${HTTP_STATUS} for user_id=${USER_ID}" >> /var/ossec/logs/active-responses.log
        exit 1
        ;;
esac
