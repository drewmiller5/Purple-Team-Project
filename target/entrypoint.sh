#!/bin/sh
# target/entrypoint.sh
#
# Final-review fix (finding #1): docker-compose's `target` service only has
# a bare `depends_on: wazuh.manager` (no `condition: service_healthy`), so
# `target` routinely starts before wazuh-authd is listening on 1515.
# `agent-auth` used to exit non-zero in that race and `set -e` killed the
# whole entrypoint before Flask ever started -- hit live twice during Task
# 8 verification (agent found fully Disconnected before any test traffic).
# Enrollment now retries in a bounded loop instead of failing hard, and
# `wazuh-control start` is allowed to fail (`|| true`) so the vulnerable
# app's liveness is never coupled to the detection layer being ready --
# the target app should come up regardless of whether the agent managed to
# enroll yet.
set -e

for i in $(seq 1 30); do
    /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER:-wazuh.manager}" && break
    sleep 2
done
/var/ossec/bin/wazuh-control start || true

exec python -m target.app
