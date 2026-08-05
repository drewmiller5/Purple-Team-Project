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
#
# Second fix round (dual-review finding #1): the substitution used to be a
# `sed "s|PLACEHOLDER|$API_PASSWORD|"`. sed's replacement string treats `&`
# as a backreference to the whole match, not a literal ampersand -- and
# .env.example's own documented password-complexity charset for
# WAZUH_API_PASSWORD explicitly allows `&` (`@$!%*?&-_.`). Any generated
# password containing `&` got silently corrupted (the literal placeholder
# text got spliced back into the password), sed still exited 0, and the
# dashboard's Wazuh-app-to-manager-API auth broke silently. A password
# containing the `|` delimiter would additionally make the sed command
# itself malformed.
#
# First attempt at a fix used bash's `${var//search/replace}` parameter
# expansion -- but live verification caught that bash >= 5.2's
# `patsub_replacement` behavior (on by default) makes an unescaped `&` in
# the REPLACEMENT of `${var/pat/replacement}` mean the exact same thing as
# in sed: "whole match". Same bug, moved to a different tool. Fixed for
# real by never putting API_PASSWORD on the replacement side of any
# pattern-substitution operator: split the template on the placeholder
# using `%%`/`#` (pattern matching only on the SEARCH side, where it's
# used to locate literal, quoted text) and reassemble with plain string
# concatenation, which has no special characters at all in bash.
set -eu

TEMPLATE="/wazuh_dashboard_config_template/wazuh.yml"
DEST_DIR="/usr/share/wazuh-dashboard/data/wazuh/config"
DEST="$DEST_DIR/wazuh.yml"
PLACEHOLDER="WAZUH_API_PASSWORD_PLACEHOLDER"

: "${API_PASSWORD:?API_PASSWORD must be set}"

mkdir -p "$DEST_DIR"
template_content=$(cat "$TEMPLATE")

case "$template_content" in
    *"$PLACEHOLDER"*) ;;
    *)
        echo "entrypoint.sh: $PLACEHOLDER not found in $TEMPLATE" >&2
        exit 1
        ;;
esac

prefix="${template_content%%"$PLACEHOLDER"*}"
suffix="${template_content#*"$PLACEHOLDER"}"
printf '%s\n' "$prefix$API_PASSWORD$suffix" > "$DEST"
chmod 600 "$DEST"

exec /bin/bash /entrypoint.sh
