#!/bin/sh
# wazuh/active-response/lock-account.sh
# Reads Wazuh's AR JSON payload from stdin, extracts the username from the
# alert's data.form_params.username field, and calls target's internal
# lock-account endpoint. Wazuh AR scripts always receive their trigger
# payload on stdin as a single JSON line.
read -r INPUT_JSON
USERNAME=$(echo "$INPUT_JSON" | grep -o '"username":"[^"]*"' | cut -d'"' -f4)

curl -s -X POST http://target:5000/internal/lock-account -d "username=${USERNAME}"
