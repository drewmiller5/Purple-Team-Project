#!/bin/bash
# wazuh/config/wazuh_dashboard/entrypoint.sh
#
# Task 8 fix round (finding #2): wazuh.yml (this repo's git-tracked
# dashboard config) hardcoded the pre-rotation wazuh-wui password, stale
# relative to Task 8's rotation of WAZUH_API_PASSWORD. This is a distinct
# auth path from OpenSearch/indexer auth (Task 8 already verified that one)
# -- it's the wazuh-app plugin's own connection to wazuh.manager's REST
# API. The image's own /wazuh_app_config.sh only auto-populates this from
# API_USERNAME/API_PASSWORD when wazuh.yml doesn't already have a host
# block; our committed file always has one (now with an obvious
# placeholder, never a real secret), so that auto-populate path never
# fires and can't be relied on here.
#
# Fix: copy the committed template into the runtime config volume and
# substitute the real password in from the env var, before handing off to
# the image's real entrypoint -- same thin secret-templating pattern as
# target/entrypoint.sh uses for the agent-enrollment PSK. The template
# stays mounted read-only at a staging path (not the live config path), so
# this substitution only ever touches the wazuh-dashboard-config named
# volume, never the bind-mounted tracked file on the host.
set -eu

TEMPLATE="/wazuh_dashboard_config_template/wazuh.yml"
DEST_DIR="/usr/share/wazuh-dashboard/data/wazuh/config"
DEST="$DEST_DIR/wazuh.yml"

mkdir -p "$DEST_DIR"
sed "s|WAZUH_API_PASSWORD_PLACEHOLDER|${API_PASSWORD:?API_PASSWORD must be set}|" \
    "$TEMPLATE" > "$DEST"

exec /bin/bash /entrypoint.sh
