#!/bin/sh
# wazuh/active-response/kill-session.sh
read -r INPUT_JSON
USER_ID=$(echo "$INPUT_JSON" | grep -o '"user_id":[0-9]*' | cut -d':' -f2)

curl -s -X POST http://target:5000/internal/kill-session -d "user_id=${USER_ID}"
