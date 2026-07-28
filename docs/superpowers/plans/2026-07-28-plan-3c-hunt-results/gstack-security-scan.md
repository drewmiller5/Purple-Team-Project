# Plan 3C Phase 1 (Hunt) -- Independent Security Scan

Second, independent reviewer pass. Reviewed fresh, without coordinating with
the parallel primary reviewer. K1-K6 (see
`docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md`) were not
re-derived; everything below is additional to that ledger. Findings are
listed roughly in descending severity as I assess it -- Phase 2 Triage may
re-rank.

---

### F1 -- Unauthenticated internal defensive-action endpoints reachable from the attacker's own network segment

**Component:** target (Flask app) / docker-compose network topology
**Severity:** High
**Summary:** `/internal/lock-account`, `/internal/kill-session`, and
`/internal/block-ip` have no authentication, no shared secret, and no
source-IP allow-listing of any kind -- they trust that only Wazuh's AR
scripts will ever call them. But they live on the exact same Flask app and
port (5000) as the public/admin routes, and `target` sits on `lab-net`
alongside `red_agent` (the adversary role) and the host's published
`5000:5000` port. Nothing stops `red_agent` (or, in the real-world pattern
this models, any attacker who reaches this network segment) from calling
these endpoints directly:
- `POST /internal/lock-account -d username=admin` locks out the legitimate
  admin account -- a self-inflicted DoS against the blue side, with zero
  Wazuh involvement.
- `POST /internal/kill-session -d user_id=<n>` kills an arbitrary session.
- `POST /internal/block-ip -d source_ip=<valid IPv4>` inserts a real
  iptables DROP inside `target`'s own container (`cap_add: NET_ADMIN`) for
  any address the caller chooses, including `wazuh.manager`'s or
  `blue_agent`'s.
All three fully bypass the detection -> AR pipeline (rule matching, guard
scripts, thresholds) since they're invoked as a direct HTTP call, not via
Wazuh.
**File:line:** `target/routes/internal.py:12-65`; `docker-compose.yml:2-13`
(target on `lab-net`, port 5000 published), `docker-compose.yml:47-54`
(red_agent also on `lab-net`).
**Suggested fix:** Require a shared secret / mTLS client identity scoped to
the Wazuh manager+agent role for `/internal/*`, and/or move those routes to
a listener bound only to a loopback/AR-script-invoked path (the AR scripts
already run inside the same container per the `<location>local</location>`
design) rather than the network-reachable Flask port.

---

### F2 -- Untrusted, attacker-controlled alert content flows unsanitized into blue_agent's LLM context and straight through to escalate_response

**Component:** blue_agent (LLM loop) / trust boundary between red-controlled input and blue's tool-calling
**Severity:** High (indirect prompt injection with a real-world-impact tool call at the end of the chain)
**Summary:** `logging_middleware.py` logs `request.form`/`request.args`
verbatim (already known to contain attacker-chosen "decoy" fields per the
comments in `kill-session.sh`/`lock-account.sh`). That same untrusted
content flows through Wazuh's JSON decoder into `alerts.json`, and
`blue_agent/loop.py:83` injects it directly into the chat transcript as
`f"New Wazuh alerts:\n{json.dumps(new_alerts)}"` -- i.e. attacker-controlled
strings are handed to the LLM as part of its instruction-following context,
not fenced off as inert data. `blue_agent/tools.py:49-69`'s
`escalate_response` then forwards whatever `action`/`target` the model
produces straight to target's (also unauthenticated, see F1)
`/internal/*` endpoints with **no validation at all** on `target` -- no
check that a `block_ip` target isn't `wazuh.manager`'s/`blue_agent`'s own
address, no check that a `lock_account` target isn't the legitimate admin
account currently in active use. An attacker who can get arbitrary text
into a request field that ends up reflected into an alert (e.g. a crafted
`username`, the `diagnostics` `host` field, or a `/search` query) has a
plausible path to steer blue's own model into an action against
legitimate infrastructure -- a classic indirect-prompt-injection-to-tool-call
chain sitting exactly on the red/blue trust boundary this project is meant
to test.
**File:line:** `blue_agent/loop.py:78-83`; `blue_agent/tools.py:49-69`;
`target/logging_middleware.py:74-75` (unredacted param logging, by design
per its own comments).
**Suggested fix:** Don't interpolate raw alert field values directly into
the model's chat turn without clearly delimiting them as untrusted
data/quoting; add server-side validation (in `target`'s `/internal/*`
handlers or in `blue_agent/tools.py` before the call) rejecting
infra/allow-listed identities as escalation targets.

---

### F3 -- Command-injection detection rule is bypassed by a newline separator

**Component:** wazuh-rules/target_rules.xml + target (diagnostics route)
**Severity:** Medium-High
**Summary:** Rule 100102's field regex is `(;|\||&amp;&amp;|\$\(|`)` --
it does not include `\n`/`\r`. But `diagnostics.py` runs
`subprocess.run(f"ping -c 1 {host}", shell=True, ...)`, and a POSIX shell
treats an embedded newline exactly like a semicolon (a new statement). A
payload such as `host=8.8.8.8%0Aid` (submitted as a literal newline once
Flask decodes the form field) achieves command execution while never
matching rule 100102 -- the one detection rule that exists for this attack
class -- so no alert fires and no AR (kill-session/firewall-drop) ever
triggers.
**File:line:** `wazuh-rules/target_rules.xml:122-132`;
`target/routes/diagnostics.py:29-35`.
**Suggested fix:** Add `\n`/`\r` to the character alternation (and
consider other statement separators), or move to a coverage strategy less
dependent on enumerating every shell metacharacter (e.g. flag any
non-IP/hostname-shaped `host` value).

---

### F4 -- SQL-injection detection rule is a narrow 3-pattern signature list, trivially bypassed

**Component:** wazuh-rules/target_rules.xml (rule 100101) + target/routes/public.py
**Severity:** Medium
**Summary:** Rule 100101 only matches
`'\s*OR\s*'1'='1 | '\s*OR\s*1=1 | -- | UNION\s+SELECT`. Any semantically
equivalent payload that avoids those exact substrings -- `' OR 'a'='a`,
`' OR ''=''`, injections using `<>`/`!=` tautologies, or blind/time-based
payloads (`' AND (SELECT ...)`, etc.) -- reaches the actually-vulnerable
`/search` endpoint (string-built query in `public.py:39-43`) with zero
detection or response.
**File:line:** `wazuh-rules/target_rules.xml:110-119`;
`target/routes/public.py:39-43`.
**Suggested fix:** Broaden to a more generic tautology/quote-imbalance
pattern set, or add a handful of the other common idioms (alternate
comment styles, boolean literals, common blind-SQLi function names).

---

### F5 -- Hardcoded, source-committed Flask SECRET_KEY enables a fully undetectable admin-session forgery path

**Component:** target/app.py (auth trust boundary)
**Severity:** Medium (contained to lab context; would be Critical outside it)
**Summary:** `app.config["SECRET_KEY"] = "purple-lab-dev-key"` is a fixed
string checked into source control. It's the same key Flask's
`itsdangerous`-based session signer uses to sign the cookie carrying
`role`/`user_id` (set at `admin.py:52-53`, trusted by `diagnostics.py:13`).
Anyone who knows this key -- trivial, since it's in the repo -- can forge a
signed session cookie asserting `role=admin` and reach `/admin/diagnostics`
(the command-injection escalation path) **without ever calling
`/admin/login`**. Since the only detection this project has for admin-panel
compromise (rules 100103/100104, bruteforce-guard.sh) watches for repeated
`POST /admin/login`, a forged-cookie approach produces zero login events
and therefore zero telemetry -- a full auth bypass invisible to every
detection mechanism in the stack. Marked lab-contained since the comment
acknowledges "not production," but it's worth flagging plainly: this
pattern, if the code/pattern is ever reused verbatim outside the lab,
is a critical secret-exposure bug, and even inside the lab it represents an
escalation path with strictly more privilege and less observability than
the seeded brute-force vuln the detection layer is built around.
**File:line:** `target/app.py:21`.
**Suggested fix:** Generate a random `SECRET_KEY` per instance/from an env
var/secret store even in the lab; don't let the exercise's entire detection
model rest on the assumption that privilege only ever arrives via a logged
login endpoint.

---

### F6 -- SIEM management plane shares a flat network with the simulated attacker, and ships hardcoded public default credentials

**Component:** docker-compose.yml / wazuh.manager, wazuh.indexer network + auth config
**Severity:** Medium (lab-contained, but a genuine architecture gap if the pattern is reused)
**Summary:** `red_agent` -- the adversary role -- is attached to `lab-net`
(`docker-compose.yml:52-54`) together with `wazuh.manager` and
`wazuh.indexer`; there is no network boundary between "attacker-reachable"
and "SIEM management plane." On top of that:
- `wazuh.manager`'s agent-enrollment port (1515) runs with
  `<use_password>no</use_password>` and no configured `<ssl_agent_ca>`
  (`wazuh_cluster/wazuh_manager.conf:346-359`) -- no pre-shared key gates
  enrollment.
- The indexer (`INDEXER_PASSWORD=SecretPassword`) and manager API
  (`API_PASSWORD=MyS3cr37P450r.*-`) both use the well-known default
  credentials from Wazuh's own published docker-compose example,
  committed directly into `docker-compose.yml:201-208,260-266`.
Combined, any host reachable on `lab-net` -- which, by this project's own
design, includes the simulated attacker -- has a network path to attempt
rogue-agent enrollment or authenticate to the SIEM's own control plane
using publicly documented default credentials, i.e. a path to disable or
spoof the detection layer itself rather than just attacking `target`.
**File:line:** `docker-compose.yml:52-54,150-274`;
`wazuh/config/wazuh_cluster/wazuh_manager.conf:346-359`.
**Suggested fix:** Put `wazuh.manager`/`wazuh.indexer` management ports on
a network segment the red/attacker role cannot reach (or at minimum
require a real pre-shared enrollment key), and replace the default
credentials even in a lab context so the pattern isn't copy-pasted
into a real deployment.

---

### F7 -- `/internal/block-ip` has no denylist for infrastructure/self addresses

**Component:** target/routes/internal.py
**Severity:** Low-Medium (compounds F1 and F2)
**Summary:** Beyond the missing auth (F1), `block_ip` validates only that
`source_ip` is a syntactically valid IPv4 address -- there's no check
against blocking the container's own gateway, `wazuh.manager`'s address, or
`blue_agent`'s address. Combined with F2 (a manipulable blue_agent) or
simply a blue-agent reasoning mistake, this is a plausible self-inflicted
denial-of-service path against the detection/response chain itself.
**File:line:** `target/routes/internal.py:42-65`.
**Suggested fix:** Maintain a small denylist (gateway IP, `wazuh.manager`,
`blue_agent`) that `block_ip` refuses to act on regardless of caller.

---

### F8 -- red_agent's Ollama-error path busy-loops with no backoff (ambiguous / low-confidence)

**Component:** red_agent/loop.py
**Severity:** Low (availability/resource-exhaustion against the local Ollama host, not the target)
**Summary:** On an Ollama request failure, `blue_agent/loop.py:88-90` logs
and then sleeps `poll_interval_seconds` before retrying. `red_agent/loop.py`
handles the identical exception (`requests.RequestException, KeyError`,
lines 80-82) by logging and immediately `continue`-ing with no sleep at
all. Bounded by `RED_MAX_ITERATIONS` (default 50) so not unbounded, but if
Ollama is degraded/erroring, red_agent will hammer it in a tight loop for
the remainder of the run where blue_agent would back off. Flagging as
ambiguous rather than dropping it: this may be an intentional asymmetry
(red's tighter iteration budget) rather than an oversight.
**File:line:** `red_agent/loop.py:77-82` (compare
`blue_agent/loop.py:84-90`).
**Suggested fix, if wanted:** add the same `time.sleep` backoff on the
error path for consistency with blue_agent.

---

## Summary table

| ID | Component | Severity | One-line |
|----|-----------|----------|----------|
| F1 | target / docker network | High | `/internal/*` AR endpoints have zero auth, reachable from red_agent's own network segment |
| F2 | blue_agent | High | Untrusted alert content reaches the LLM context unsanitized; escalate_response has no target validation |
| F3 | wazuh-rules + target | Medium-High | Command-injection rule 100102 misses newline-separated payloads |
| F4 | wazuh-rules | Medium | SQLi rule 100101 is a 3-pattern signature list, trivially bypassed |
| F5 | target | Medium | Hardcoded static SECRET_KEY enables undetectable session forgery to admin |
| F6 | docker-compose / wazuh | Medium | SIEM control plane flat-networked with the attacker role + public default creds |
| F7 | target | Low-Medium | block-ip has no infra/self denylist |
| F8 | red_agent | Low | Busy-loops on Ollama errors with no backoff (ambiguous, may be intentional) |
