# Wazuh indexer SSL certs

The `.key`/`-key.pem` files in this directory (including the root CA key,
`root-ca.key`) are **not secrets protecting any real system**. They are
upstream [`wazuh-docker`](https://github.com/wazuh/wazuh-docker)'s own
documented single-node demo certificates -- the same defaults shipped in
Wazuh's official quickstart compose files.

They are regenerated locally at deploy time by running
`wazuh/generate-indexer-certs.yml` (which invokes the
`wazuh/wazuh-certs-generator` image against `wazuh/config/certs.yml`), not
hand-authored or reused across environments. Nothing outside this lab
trusts this CA, and this repo has no configured git remote, so there is no
live exposure from these files being present in version control.

They're committed (rather than gitignored) because Task 2 of the
[Wazuh detection-layer plan](../../../docs/superpowers/plans/2026-07-26-wazuh-detection-layer.md)
found individual-file cert mounts (as opposed to mounting the whole
directory) to be the reliable approach for this project's `docker-compose.yml`
-- see that plan's Task 2 notes. Regenerating and recommitting is the
expected workflow if these ever need to change, not a one-time secret to
rotate.

If a secret scanner flags `root-ca.key` or the other `*-key.pem` files
here: that's expected and correct behavior for a scanner, and this note is
the answer -- these are known-public upstream demo material, not a leak.
