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
INPUT_JSON=$(cat)
# Wazuh's JSON_Decoder serializes an absent/null value as the literal
# *string* "null" (not JSON null), so select() explicitly excludes both
# forms -- real JSON null (field truly absent) and the string "null"
# (unauthenticated request) -- leaving USER_ID empty in either case.
USER_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.user_id | select(. != null and . != "null")')

curl -s -X POST http://target:5000/internal/kill-session -d "user_id=${USER_ID}"
