FROM python:3.11-slim

WORKDIR /app

# H63 fix (Task 22): wazuh-agent is now installed from a pinned,
# immutable .deb pool URL instead of adding Wazuh's "stable" apt repo and
# running `apt-get install wazuh-agent=4.9.2-1`. Wazuh only publishes one
# rolling apt channel for the entire 4.x line ("stable" is a suite name,
# not a per-point-release path) -- pinning the PACKAGE version alone still
# depended on 4.9.2-1 still being present in whatever that mutable pool
# currently contains. If Wazuh's maintainers ever prune it (keeping only
# newer 4.9.x builds), the apt-based install breaks with no change on
# this side. A direct pool-URL download removes that dependency entirely:
# pool paths are immutable once published (Debian-pool convention Wazuh's
# repo follows), so this step either gets exactly this byte-identical
# package or fails loud on the checksum, never silently resolves to a
# different version.
#
# Review round 1 findings (2x independent ecc:code-reviewer), both fixed:
# (1) HIGH -- the original version of this fix hardcoded the amd64 .deb
# URL. `apt-get install wazuh-agent=4.9.2-1` (the old flow) let apt/dpkg
# auto-resolve architecture to match the base image, so the old Dockerfile
# built correctly on both amd64 and arm64 hosts (e.g. Apple Silicon dev
# machines); a hardcoded single-arch URL would have silently broken that.
# Fixed by detecting the build architecture via `dpkg --print-architecture`
# and selecting the matching pool URL + checksum -- both a real
# wazuh-agent_4.9.2-1_arm64.deb (confirmed to exist, same version, live
# HTTP 200) and its own checksum are now pinned alongside the amd64 pair.
# (2) MEDIUM -- the sha256 pins were originally trust-on-first-use (a
# checksum computed from one live download this session, no independent
# corroboration). Both hashes below are now cross-checked against Wazuh's
# own officially-published Packages index
# (https://packages.wazuh.com/4.x/apt/dists/stable/main/binary-{amd64,arm64}/Packages,
# fetched live, SHA256 field matched exactly for both architectures) --
# stronger than a single download, though still not equivalent to the old
# flow's full GPG-signed-repo trust chain (the InRelease file's own
# signature over that Packages index isn't verified here). Accepted as a
# reasonable tradeoff for this lab/coursework target container; a
# stronger bar would GPG-verify the Release file itself before trusting
# its Packages index.
#
# gnupg/apt-transport-https are dropped -- they existed only to add and
# trust the now-unused apt repo. lsb-release is KEPT, unlike those two --
# a real Docker build attempt (not an assumption) showed it's an actual
# postinst dependency of the wazuh-agent .deb itself, not just something
# needed to add the old apt source.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping curl procps iptables jq lsb-release \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
        amd64) WAZUH_DEB_SHA256="f57d8ca0a19a90b623de935f8aab18434b37e7b952b49e8c42714e016c6160f2" ;; \
        arm64) WAZUH_DEB_SHA256="4cd93642a41656f4183637bdeefc920588c8879a3b76a86f2d18431975f9e72b" ;; \
        *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL -o /tmp/wazuh-agent.deb "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_${ARCH}.deb" \
    && echo "${WAZUH_DEB_SHA256}  /tmp/wazuh-agent.deb" | sha256sum -c - \
    && dpkg -i /tmp/wazuh-agent.deb \
    && rm -f /tmp/wazuh-agent.deb \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY target/ target/
COPY shared/ shared/
COPY wazuh/agent/ossec.conf /var/ossec/etc/ossec.conf
COPY target/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONPATH=/app
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
