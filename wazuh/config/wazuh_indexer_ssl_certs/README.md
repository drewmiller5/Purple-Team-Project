# Wazuh indexer SSL certs

The `*.key`/`*-key.pem` files in this directory (root CA and per-service
private keys) are gitignored and **not committed**. They're regenerated
locally by running `wazuh/generate-indexer-certs.yml` (which invokes the
`wazuh/wazuh-certs-generator` image against `wazuh/config/certs.yml`) --
each clone/deploy gets its own, rather than reusing key material from
another environment.

The corresponding `*.pem` certificate files (not `-key.pem`) are public
certs, not secrets, and stay committed so a fresh clone has a working,
internally-consistent bundle without needing to regenerate before first
boot.

This wasn't always the policy: this directory's private keys were
originally committed on the theory that they were disposable upstream
demo material with no live exposure (this repo had no git remote at the
time). That stopped being true once the repo went public on GitHub --
see finding **H47** in
[the findings ledger](../../../docs/ledger/plans/2026-07-28-plan-3c-findings-ledger.md)
for the full history. The old keys are still recoverable from git
history (accepted risk, rotate-forward only, no history rewrite), but
going forward: **do not commit any private key file in this directory.**
