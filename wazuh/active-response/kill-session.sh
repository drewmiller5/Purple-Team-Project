#!/bin/sh
# wazuh/active-response/kill-session.sh
#
# Task 7 fix-round: Wazuh's JSON_Decoder plugin serializes every dynamic
# field in the alert's "data" section as a quoted string, even when the
# original app log emitted a bare integer (confirmed live: target now logs
# "user_id": 1 in requests.jsonl, but the alert JSON that reaches this
# script contains "data":{...,"user_id":"1"}). The original digit-only
# regex ("user_id":[0-9]*) can't match a value that starts with a quote
# character, so it always extracted an empty string. This version matches
# up to the next "," or "}" (covers both "user_id":"1" and "user_id":1) and
# then strips everything that isn't a digit, which also correctly yields
# an empty USER_ID for unauthenticated requests ("user_id":"null" /
# "user_id":null).
read -r INPUT_JSON
USER_ID=$(echo "$INPUT_JSON" | grep -o '"user_id":[^,}]*' | tr -cd '0-9')

curl -s -X POST http://target:5000/internal/kill-session -d "user_id=${USER_ID}"
