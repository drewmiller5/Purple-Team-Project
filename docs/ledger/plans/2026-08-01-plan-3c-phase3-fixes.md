# Plan 3C Phase 3 — Fix Everything in the Ledger, Severity Order

Source of truth for every requirement below: `docs/ledger/plans/2026-07-28-plan-3c-findings-ledger.md`.
This plan translates its 53 still-Open rows (old ledger + fresh 2026-08-01
hunt) into 22 tasks, grouped by shared file/root-cause per the ledger's own
"same fix shape -> one Fix-loop iteration" guidance, in severity order.

## Global Constraints

- TDD: a failing test first, for every fix, in every task.
- Every task's tests MUST be run in the foreground by the implementer.
  Backgrounding `pytest` has stalled implementers on this project before —
  do not do it.
- Full suite (`pipenv run pytest` from repo root) should run in ~40-50s.
  If any task's changes make it take 15+ minutes, check
  `brain/Gotchas.md` (vault) for the known "unmocked real-time sleep in a
  test" bug class before assuming the environment is slow.
- Do NOT touch `red_memory.json` / `blue_memory.json` / `white_memory.json`
  (agents' persisted research data) in any task.
- Do NOT add an `<?xml-stylesheet?>` processing instruction to
  `wazuh-rules/target_rules.xml` (confirmed live to crash `wazuh-analysisd`).
- Commit each task's fix as its own commit (matches this project's existing
  commit granularity — one logical change per commit).
- Never run `git push`.
- After each task, update the corresponding row(s) in
  `docs/ledger/plans/2026-07-28-plan-3c-findings-ledger.md` — Disposition
  to `Fixed (commit <hash>)`, one line each — as part of the same commit
  or a fast-follow docs commit.

---

## Task 1: Ollama-response and tool-dispatch exception-boundary hardening (red_agent + blue_agent)

Closes: K2, H15, H16, H17, H21.

Files: `red_agent/loop.py`, `red_agent/tools.py`, `blue_agent/loop.py`, `blue_agent/tools.py`, `red_agent/state.py`.

Requirements:
1. `red_agent/loop.py` and `blue_agent/loop.py`: the code path that reads
   `response["message"]` and then calls `.get(...)` on it (red: lines ~82,88;
   blue: lines ~100-108) must not raise an uncaught `AttributeError` when
   Ollama returns a non-dict/`null` `"message"` value. Guard with an
   isinstance/type check; on a bad shape, log an `ollama_error` event (same
   shape as the existing `except (requests.RequestException, KeyError)`
   branch) and `continue` the loop rather than crashing.
2. `red_agent/tools.py` and `blue_agent/tools.py`: `json.loads(args)` where
   `args` is a string (red: ~line 53; blue: ~lines 83-85) must not raise an
   uncaught `json.JSONDecodeError`. Catch it alongside the existing
   `(KeyError, TypeError)` tuple in each loop's tool-dispatch except clause,
   and produce a clean per-call error result (matching the existing pattern
   for unknown tool names / unknown actions) instead of crashing the process.
3. `red_agent/loop.py`'s tool-dispatch except clause (~line 96) must also
   catch `OSError` from the file I/O underneath `record_finding`/`log_event`
   (disk full, permission error) — same fix shape as blue_agent needs per
   item 4 below.
4. `blue_agent`'s equivalent call sites (`state.heartbeat()`, `state.log_event(...)`
   in `loop.py` and `tools.py`) must not crash the process on `OSError` —
   wrap the unconditional-every-iteration `state.heartbeat()` call (currently
   outside any try/except) so a disk-full/permission error degrades rather
   than kills the process.
5. `red_agent/loop.py`: `state.recall_summary()` (~line 65), called before
   `_wait_for_go`, must not let `shared/memory.py`'s typed `ValueError` (on
   corrupt JSON) crash the process before the round even starts. Catch it,
   log an event, and proceed with an empty/degraded summary.

Tests: one test per guarded failure mode (non-dict message, malformed JSON
args, `OSError` on log write, corrupt memory file at recall time) — 5+ new
tests total across the 2 agents' existing test files.

## Task 2: Wire blue_agent's `record_finding` into the live loop

Closes: H20.

Files: `blue_agent/loop.py` or `blue_agent/tools.py` (wherever `escalate_response`'s
dispatch happens — `state.record_finding()` currently has zero call sites
outside its own unit test).

Requirement: the live loop must actually call `state.record_finding(...)`
at an appropriate point (e.g. when `escalate_response` successfully takes
an action), so `blue_memory.json` gets written and `recall_past_findings`
stops being a permanent no-op. Match `record_finding`'s existing signature/
tests in `blue_agent/tests/test_state.py`.

Test: an integration-style test asserting a full loop iteration that calls
`escalate_response` results in a `record_finding` call / a non-empty
`blue_memory.json` entry.

## Task 3: Rewrite blue_agent's alert-file position tracking to byte offset (not line count)

Closes: H19, H24.

File: `blue_agent/wazuh_alerts.py`.

Requirements:
1. Replace `self._lines_read` (a line count) with a byte-offset (or
   inode+offset) tracking scheme so that if the alerts log is ever
   rotated/truncated shorter than the previous position, `poll_new_alerts()`
   detects this (position > file size) and resets to the start, rather than
   silently returning `[]` forever.
2. `poll_new_alerts()` must not fully re-read and re-parse the entire file
   from byte 0 on every poll — seek to the stored offset and read only new
   content, then update the offset.

Tests: (a) normal incremental poll only sees new lines; (b) simulated
rotation/truncation (write a shorter file at the same path) is detected and
recovers rather than silently returning `[]` forever.

## Task 4: Fix the second K6-class bind-mount shadowing bug (wazuh active-response volume)

Closes: H41.

File: `docker-compose.yml` (`wazuh_active_response` named volume + the 4
custom AR script bind-mounts at the same path).

Requirement: apply the same fix pattern already used for K6/`target_rules.xml`
(the `WAZUH_CONFIG_MOUNT`-style overlay, or an init step that populates the
named volume with Wazuh's default AR binaries before/alongside the 4 custom
scripts) so a fresh volume does not look pre-populated and skip installing
the manager's own default AR binaries (`firewall-drop`, `disable-account`,
`host-deny`, `restart-wazuh`, `route-null`).

Test: this is infra/compose config — provide a `docker compose config`
validation check and, if there's an existing pattern for testing the K6 fix
(check how K6's original fix was verified, likely a documented manual
verification or a script under `scripts/`), replicate it for this second
instance. If no automated test is feasible for compose-level volume
semantics, the implementer must document the manual verification steps
performed (matching how K6 was originally verified) in the commit message.

## Task 5: AR guard-script counting integrity — pipefail + window-starvation fix

Closes: H34, H49.

Files: `wazuh/active-response/bruteforce-guard.sh`, `wazuh/active-response/idor-guard.sh`.

Requirements:
1. The counting `jq` pipeline must not silently undercount on a malformed
   line — add proper error checking / `pipefail` semantics (`/bin/sh` has no
   native `pipefail`; use an equivalent guard, e.g. checking each stage's
   exit status or restructuring to avoid a multi-stage pipe swallowing
   errors) so a `jq` failure mid-window is detected and logged, not silently
   treated as "count is fine."
2. The `tail -n 5000` bounded window must not let an attacker who floods
   >5000 unrelated requests within the threshold window push their own
   real correlated events out of view before the count runs. Widen the
   window meaningfully (e.g. count by time-window directly rather than a
   fixed line count — filter `requests.jsonl` by timestamp range first,
   then count, so the correlation is bounded by time not by an arbitrary
   line count) or otherwise ensure the counting logic can't be starved by
   decoy volume.

Tests: shell-level tests (or a documented manual verification against a
running `wazuh-logtest`/manager, matching how K3/H32/H33/H37 were verified)
proving: (a) a malformed line mid-window is now detected/logged rather than
silently undercounting; (b) >5000 interleaved decoy lines before the real
threshold-crossing events no longer defeats the count.

## Task 6: Validate `lock_account`/`kill_session` targets in blue_agent's escalate_response

Closes: H23, H51.

Files: `blue_agent/tools.py`.

Per the 2026-08-01 user decision on H51: do not build a full app-level
infra-identity concept. Add a narrower, targeted check: `escalate_response`
must reject `lock_account`/`kill_session` calls that target the `admin`
account specifically (mirroring `block_ip`'s existing infra-denylist
pattern at `_is_protected_block_ip_target`), so a prompt-injected blue_agent
cannot permanently lock out the account that is also red's designed win
path. This closes the concrete H51 exploit chain. For H23 more broadly, add
basic format validation matching what `target`'s server-side already
enforces where it exists (`kill_session`'s `user_id` is already validated
numeric server-side; `lock_account`'s `username` has none) — add the same
class of check client-side in blue_agent as defense-in-depth.

Tests: (a) `escalate_response(action="lock_account", target="admin")` is
rejected before dispatch, with an `escalation_rejected` event logged (same
pattern as the existing `block_ip` rejection test); (b) non-admin username
targets still pass through unchanged (no regression).

## Task 7: Rotate-forward the committed CA private keys

Closes: H47.

Files: `.gitignore`, `wazuh/config/wazuh_indexer_ssl_certs/root-ca.key`,
`wazuh/config/wazuh_indexer_ssl_certs/root-ca-manager.key`, `wazuh/README.md`.

Per the 2026-08-01 user decision: rotate-forward only, do not rewrite git
history (impact is bounded to an `internal: true` Docker network).

Requirements:
1. Add `*.key` to `.gitignore`.
2. Remove the 2 committed key files from the working tree (`git rm`, not
   just filesystem delete) so future clones don't get them, while leaving
   git history untouched.
3. Regenerate fresh certs via the existing `generate-indexer-certs.yml`
   process documented in `wazuh/README.md` so the local working stack still
   has valid keys to run with (they just won't be committed going forward).
4. Update `wazuh/README.md` if its current wording implies the keys are
   meant to be committed.

Test: this is a config/secrets-hygiene task, not app logic — the
implementer verifies `git status` shows the key files as untracked/ignored
after the change, and documents the regeneration steps run.

## Task 8: Wazuh network & credential exposure hardening

Closes: H7, H48, H52, H53.

Files: `docker-compose.yml`, `.env.example`, `wazuh/config/wazuh_indexer/internal_users.yml`,
`wazuh/config/wazuh_cluster/wazuh_manager.conf`.

Requirements (per the 2026-07-28 H7 user decision — rotate credentials and
segment the network — sharpened by the fresh hunt's H48/H52/H53):
1. Move `wazuh.indexer`'s `9200:9200`, `wazuh.manager`'s `1514:1514`/`1515:1515`/
   `514:514/udp`/`55000:55000`, and `wazuh.dashboard`'s `443:5601` host
   port publishes to bind to `127.0.0.1` only (`"127.0.0.1:9200:9200"` etc)
   instead of all interfaces — closes H48's "reachable from outside Docker
   entirely" angle without breaking local access.
2. Replace the hardcoded `INDEXER_PASSWORD=SecretPassword`, `API_PASSWORD`,
   `DASHBOARD_PASSWORD=kibanaserver` (and matching `internal_users.yml`
   bcrypt hashes) with values generated at deploy time / read from `.env`
   (matching the `${VAR:?message}` fail-closed pattern already used for
   `INTERNAL_ACTION_TOKEN`/`DASHBOARD_AUTH_TOKEN`), with instructions in
   `.env.example`.
3. Add a pre-shared key to the agent-enrollment `<auth>` block in
   `wazuh_manager.conf` (currently `<use_password>no</use_password>`).
4. Remove `agent-net` from `wazuh.dashboard`'s `networks:` list (H53) —
   verify first, as the fresh hunt did, that `ports:` publishing doesn't
   depend on network membership (compare `wazuh.manager`/`wazuh.indexer`,
   which are host-reachable while `lab-net`-only).
5. `red_agent` stays off `wazuh.manager`/`wazuh.indexer`'s network where
   feasible, completing the network-segmentation half of the original H7
   decision.

Test: `docker compose config` validates; document the manual verification
that the stack still starts and `blue_agent` can still reach the indexer
after credential rotation (matching how prior infra fixes in this project
were verified — see K6's fix for the pattern).

## Task 9: Harden `target/routes/diagnostics.py`'s subprocess call

Closes: H10, H58.

File: `target/routes/diagnostics.py`.

Requirements:
1. Wrap the `subprocess.run(f"ping -c 1 {host}", shell=True, ..., timeout=5)`
   call in try/except so `subprocess.TimeoutExpired` returns a clean JSON
   error response instead of an uncaught-exception 500 (H10).
2. On timeout, the injected shell's grandchildren must not be orphaned and
   left running — use `preexec_fn=os.setsid` (or `start_new_session=True`)
   plus killing the process group on timeout, so a `sleep`/CPU-bound
   injected command doesn't keep running after the endpoint returns (H58).

Tests: (a) a `host` value causing a >5s shell command now returns a clean
error response, not a 500; (b) after timeout, no orphaned child process
remains running (spawn a detectable marker process via the injection and
assert it's gone shortly after the endpoint returns).

## Task 10: Harden `target/routes/internal.py`'s account-management endpoints

Closes: H11, H12, H13, H61.

Files: `target/routes/internal.py`, `target/db.py`.

Requirements:
1. Add a `UNIQUE` constraint on `blocked_users.username` (H11) — cheap
   hardening even though the race isn't live today (single-threaded dev
   server).
2. Per the 2026-07-28 H12 user decision: rename `/internal/kill-session`'s
   handler/route to match its real behavior (a permanent block, not a
   session kill) — e.g. `lock_account_permanent`-shaped naming — rather
   than building new session-store/logout architecture. Keep the existing
   route path stable unless the plan's global constraints say otherwise;
   rename the Python function/internal naming and update callers
   (`blue_agent/tools.py`, docs) to match.
3. Reject empty-string usernames in `/internal/lock-account` (H13).
4. Cache `_protected_source_ips()`'s DNS/file-I/O lookups (computed once at
   process startup, not on every `/internal/block-ip` request) (H61).

Tests: one per requirement — UNIQUE-constraint violation is handled
cleanly, renamed function name/behavior is covered by existing or updated
tests, empty username is rejected, protected-IPs cache returns the same
result without re-resolving DNS on a second call (mock/spy on
`socket.gethostbyname` to assert it's called once, not per-request).

## Task 11: Harden `shared/event_log.py` and `shared/memory.py` against malformed/corrupt data

Closes: H29, H30, H31.

Files: `shared/event_log.py`, `shared/memory.py`.

Requirements:
1. `read_events` must validate each parsed JSON line is a `dict` before
   yielding/returning it — skip (and count/log, matching the existing
   corrupt-line handling style) any syntactically-valid-but-non-dict line,
   rather than letting it crash every downstream `.get(...)` caller (H29).
2. `read_events` and `load_memory` must open files with explicit `errors=`
   handling (or catch `UnicodeDecodeError` per-line/per-file) so one bad
   byte doesn't crash the read of the entire file — matching the module's
   own stated intent of skipping bad content, not failing the whole read
   (H30).
3. `append_memory_entry`/`load_memory` must validate the loaded JSON has
   the expected shape (`{side, created_at, entries}` with `entries` a
   list) and raise the same typed `ValueError` the module already uses for
   JSON-decode corruption, not an unhandled `KeyError`/`AttributeError`
   (H31).

Tests: one per requirement, in `shared/tests/test_event_log.py` and
`shared/tests/test_memory.py` — non-dict line skipped not crashed, invalid
UTF-8 byte skipped not crashed, wrong-shape memory file raises the typed
`ValueError`.

## Task 12: Referee crash hardening round 2

Closes: H28, H56.

Files: `referee/config.py`, `referee/loop.py`, `referee/white_memory.py`.

Requirements:
1. `load_config()` must validate its 4 numeric env vars: reject/clamp
   negative `poll_interval_seconds` (currently crashes `time.sleep()`),
   reject `blue_win_streak=0` (currently degenerates `blue_decisive_win` to
   an instant evidence-free win per Python's `[-0:]` slice semantics — must
   require a positive streak), and validate the others don't silently
   accept non-numeric garbage beyond the `int()`/`float()` crash they
   already produce at `main.py` (make that crash a clear, actionable
   startup error rather than a bare traceback, if not already).
2. `prepare_round()`'s `load_memory` calls (`white_memory.py`) must not let
   an uncaught `ValueError` (from Task 11's now-typed corrupt-memory error,
   or the existing one) kill the referee process after `go.flag`/`stop.flag`
   are already cleared but before a new `go.flag` is created — catch it,
   log the corruption, and proceed with empty memory rather than crashing
   into a permanent silent hang.

Tests: (a) `blue_win_streak=0` is rejected at config-load time; (b) negative
`poll_interval_seconds` is rejected at config-load time; (c) a corrupt
`white_memory.json`/`red_memory.json` at round start no longer crashes
`prepare_round()`.

## Task 13: red_agent heartbeat + phase gate

Closes: K1, K5.

Files: `red_agent/state.py`, `red_agent/loop.py`.

Per the 2026-07-28 user decisions: K1 gets the same deadlock-fix pattern
Plan 3B already used for blue's heartbeat (add a `heartbeat()` method to
`RedAgentState` mirroring `BlueAgentState.heartbeat()`, called from
`red_agent/loop.py`'s main loop). K5 gets an **enforced** phase gate (not
left to per-turn model judgment) — add code-level state tracking that
requires at least one recon-class tool call before an attack-class tool
call is permitted in a given round.

Tests: (a) `red_agent` writes a heartbeat on each loop iteration (mirroring
blue's existing heartbeat test); (b) an attack-class tool call attempted
before any recon-class tool call is rejected/blocked by the phase gate.

## Task 14: Cap/trim the Ollama conversation context (red_agent + blue_agent)

Closes: H22, H57.

Files: `red_agent/loop.py`, `blue_agent/loop.py`.

Requirement: the `messages` list sent to Ollama on each iteration must not
grow unbounded across a long round. Add a cap/trim/summarization strategy
(e.g. keep only the last N exchanges, or summarize older turns) applied
identically in both agents' loops, so token count/latency doesn't grow
monotonically and exceed the model's context window before the round's
time/iteration budget is reached.

Tests: a test that runs enough simulated iterations to exceed the chosen
cap and asserts `messages` length/size stays bounded rather than growing
indefinitely.

## Task 15: red_agent misc hardening — backoff, arg validation, method enum

Closes: H9, H18, H64.

Files: `red_agent/loop.py`, `red_agent/tools.py`.

Requirements:
1. Per the 2026-07-28 H9 user decision: add matching backoff
   (`time.sleep(config.poll_interval_seconds)` or equivalent) before the
   `continue` in `red_agent/loop.py`'s Ollama-failure except branch,
   matching `blue_agent`'s existing behavior.
2. Tool argument values (e.g. `success`) must be validated/coerced against
   `TOOL_SCHEMAS`'s declared types before being persisted via
   `record_finding`, instead of being stored/fed back into later runs
   unchecked (H18).
3. `http_request`'s `method` argument must be checked against
   `TOOL_SCHEMAS`'s declared enum (`GET`/`POST`) at dispatch time, not just
   advisory to the model — reject other verbs before the request is sent
   (H64).

Tests: one per requirement — Ollama failure now sleeps before retry
(assert `time.sleep` called), a non-boolean `success` value is coerced or
rejected cleanly, a non-GET/POST `method` value is rejected before
`http.request` is called.

## Task 16: Token separation of duties (round_helper + dashboard)

Closes: H54, H55.

Files: `round_helper/app.py`, `dashboard/app.py`, `dashboard/actions.py`,
`dashboard/round_control.py`, `docker-compose.yml`, `.env.example`.

Per the 2026-08-01 user decisions on both H54 and H55:
1. Give `round_helper` its own separate secret (e.g. `ROUND_HELPER_TOKEN`),
   distinct from `target`'s `INTERNAL_ACTION_TOKEN`, so a token leaked via
   `target`'s RCE can no longer reach `round_helper`'s `/restart-round`
   even if the network topology ever changes.
2. Scope `dashboard`'s single `DASHBOARD_AUTH_TOKEN`-gated capability
   surface: at minimum, `run_red_action`'s arbitrary-request `raw` mode
   should have some allowlist/scoping (method/path) rather than unrestricted
   passthrough, reducing what a single leaked dashboard credential grants.

Tests: (a) `round_helper` rejects a request authenticated with the old
`INTERNAL_ACTION_TOKEN` value, accepts one with the new dedicated token;
(b) `run_red_action`'s `raw` mode rejects a request outside its new
allowlist scope (or documents/tests whatever scoping mechanism is chosen).

## Task 17: Add restart policies to unsupervised services

Closes: H50.

File: `docker-compose.yml`.

Requirement: add `restart: on-failure` (or equivalent) to `red_agent`,
`blue_agent`, `referee`, and `round_helper`'s service blocks, matching the
pattern already used by `target`/`purple_dashboard` (`unless-stopped`) and
the Wazuh services (`always`) — so a crash from any residual exception path
doesn't leave the container silently, permanently dead for the rest of the
round.

Test: `docker compose config` validates; document that the 4 service
blocks now show a `restart` policy in the resolved config output.

## Task 18: `target/logging_middleware.py` redaction + process-safety note

Closes: H14, H62.

File: `target/logging_middleware.py`.

Requirements:
1. `_redact_params` must cover more than an exact case-insensitive match on
   `"password"` — extend to nested JSON bodies and related field names
   (`confirm_password`, `token`, etc), matching the pattern of secret-like
   field names elsewhere in the codebase.
2. Add a one-line comment (or, if cheap, a `multiprocessing.Lock`/file-lock)
   noting that `_log_write_lock` is thread-safe only, not process-safe, so a
   future move to a multi-worker WSGI server doesn't silently corrupt
   `requests.jsonl`.

Test: a redaction test covering a nested JSON body field and a
`confirm_password`-shaped key name, asserting both are now redacted.

## Task 19: `wazuh-rules/` cleanup — regex hardening + stale artifacts

Closes: H4, H5, H39, H40, H59.

Files: `wazuh-rules/target_rules.xml`, `wazuh-rules/target_rules.css`.

Requirements:
1. Rule 100102's injection-char regex must include `\n`/`\r` alternatives so
   a newline-separated payload (`8.8.8.8%0Aid`) doesn't bypass detection (H4).
2. Rule 100101's SQLi regex (currently 3 narrow patterns including a bare
   `--`) should be broadened to catch more semantically-equivalent payloads
   without excessively widening false positives from the bare `--` pattern
   flagged by H40 — replace the bare `--` alternative with something more
   specific (e.g. `--` followed by whitespace/end-of-value, or requiring it
   alongside another SQL keyword) so legitimate values with em-dashes/date
   ranges don't trip it (H5, H40).
3. Remove rule 100103's no-op `status_code==200` condition (or replace with
   a comment explaining it can't distinguish success/failure given
   `/admin/login`'s current response shape) (H39).
4. Delete `wazuh-rules/target_rules.css` (dead end from a rejected
   approach, its own header comment is a landmine for reintroducing the
   banned `<?xml-stylesheet?>` PI) — do NOT wire it up, just remove it (H59).

**Reminder**: do not add an `<?xml-stylesheet?>` PI to `target_rules.xml`
under any circumstance in this task.

Test: this is XML/detection-rule content — the implementer must verify via
`wazuh-logtest` (or the documented equivalent used for K3/H32/H33/H37's
verification) that: (a) a `%0A`-delimited injection payload now matches
rule 100102; (b) a legitimate value containing `--` (e.g. a date range) no
longer false-positives on rule 100101; (c) rules still load with no XML
errors.

## Task 20: AR script exit-path hardening — remaining robustness gaps

Closes: H35, H36, H38, H43, H44.

Files: `wazuh/active-response/idor-guard.sh`, `wazuh/active-response/bruteforce-guard.sh`,
`wazuh/active-response/lock-account.sh`, `wazuh/active-response/kill-session.sh`.

Requirements:
1. `idor-guard.sh`: move the "inserting DROP" log line to *after* both
   `iptables -I` calls succeed (or check each call's exit status before
   logging success), so the audit log and actual firewall state can't
   disagree (H35).
2. `idor-guard.sh`: extend the per-IP `flock` to cover the
   threshold-decision-and-block section, not just the counter increment,
   closing the narrow concurrent-duplicate-block window (H36).
3. `idor-guard.sh`: validate `$SRCIP`'s format before interpolating it into
   file paths (`STATE_FILE`/`LOCK_FILE`) — defensive hardening even though
   not currently reachable without a reverse proxy in front of `target`
   (H38).
4. `lock-account.sh`/`kill-session.sh`: short-circuit before the `curl` call
   when `USERNAME`/`USER_ID` come back empty from `jq`'s extraction, matching
   the guard scripts' existing `SRCIP`/`EVENT_TS` empty-value guards (H43).
5. All 4 scripts: wrap the initial `jq -r '.parameters.alert...'` field
   extractions so a `jq` failure under `set -eu` writes one line to
   `active-responses.log` before exiting, instead of aborting with zero
   observability (H44).

Tests: shell-level or documented manual verification (matching K3/H32/H33/H37's
verification approach) for each of the 5 items.

## Task 21: Fix `target/routes/admin.py`'s raw-HTML login response

Closes: H60.

File: `target/routes/admin.py`.

Requirement: replace the raw f-string HTML response on successful login
with `render_template_string` (matching every other response in the app),
so the pattern stays consistent and auto-escaping applies even though
`username` is currently constrained to exact-match seeded values.

Test: existing login-success test(s) still pass; add one asserting the
response is generated via the templated path (or that HTML-special
characters in a hypothetical username would be escaped).

## Task 22: Pin `target/Dockerfile`'s Wazuh apt repo for build reproducibility

Closes: H63.

File: `target/Dockerfile`.

Requirement: pin the Wazuh apt repo to a specific, version-locked path
rather than the rolling `stable` channel, so the build doesn't silently
break if `stable` drops the `wazuh-agent=4.9.2-1` point release from its
index.

Test: this is a build-config change — the implementer verifies
`docker build` still succeeds against the pinned repo path (or documents
why a full build wasn't run, e.g. no Docker available in the execution
environment, and what was verified instead: the repo URL pattern is valid,
matches Wazuh's documented versioned-repo scheme).
