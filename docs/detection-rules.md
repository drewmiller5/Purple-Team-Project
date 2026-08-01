# Detection Rules

Custom Wazuh rules (`wazuh-rules/target_rules.xml`) that detect `target`'s
three seeded vulnerabilities. Hand-written directly against Wazuh's rule
engine rather than generated from Sigma — no working `sigma-cli` Wazuh
backend exists today (tracked upstream as an open, unimplemented feature
request), so a hand translation was the only option.

| Rule ID | Level | Fires on | Detects | MITRE ATT&CK |
|---|---|---|---|---|
| 100100 | 0 (base) | Any `target` request log event | Scopes every rule below to `target`'s own JSON request log | — |
| 100101 | 12 | `GET /search` with a SQLi-shaped `q` param | SQL injection on the search endpoint | T1190 – Exploit Public-Facing Application |
| 100102 | 15 | `POST /admin/diagnostics` with shell metacharacters in `host` | OS command injection via the diagnostics ping | T1059 – Command and Scripting Interpreter |
| 100103 | 3 (base) | `POST /admin/login` with a username present | Feeds the brute-force guard below | — |
| 100104 | 10 | 5+ matches of 100103 from one source in 120s | Documents the original brute-force intent | T1110 – Brute Force |
| 100105 | 3 (base) | `GET /documents/<id>` | Feeds the IDOR guard below | — |
| 100106 | 7 | 5+ matches of 100105 from one source in 60s | Documents the original IDOR-probing intent | T1213 – Data from Information Repositories |

## Why 100104/100106 are defined but never fire

Wazuh 4.9.2's native `frequency`/`if_matched_sid` correlation was
extensively tested (live traffic, `wazuh-logtest`, structural diffing
against Wazuh's own shipped rules using the identical idiom) and never
dispatches these two rules, despite their base rules (100103, 100105)
matching correctly. This was confirmed to be a real engine/version
behavior, not a rule-authoring mistake.

Rather than keep fighting an undocumented engine limitation, the actual
counting moved to two Active Response scripts
(`wazuh/active-response/bruteforce-guard.sh`,
`wazuh/active-response/idor-guard.sh`) that read `target`'s request log
directly and do their own threshold/window arithmetic, triggered off the
always-firing base rules (100103, 100105) instead. 100104 and 100106 stay
in the ruleset purely as a record of the original Sigma-derived intent
(threshold, window, MITRE mapping) — they're expected to never appear in
`alerts.json`.

See `wazuh-rules/target_rules.xml` for the full rule definitions and
`docs/sigma-rules/*.yml` for the Sigma sources they were translated from.
