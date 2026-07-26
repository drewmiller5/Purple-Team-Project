#!/bin/sh
# target/entrypoint.sh
set -e

/var/ossec/bin/agent-auth -m "${WAZUH_MANAGER:-wazuh.manager}"
/var/ossec/bin/wazuh-control start

exec python -m target.app
