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
INPUT_JSON=$(cat)
USERNAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.form_params.username | select(. != null and . != "null")')

curl -s -X POST http://target:5000/internal/lock-account -d "username=${USERNAME}"
