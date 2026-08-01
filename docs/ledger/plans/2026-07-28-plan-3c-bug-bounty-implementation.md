# Plan 3C: Full-System Bug Bounty — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit the entire Purple Team system (not just the `blue-agent-referee` branch's new code) for correctness and robustness bugs, fix every finding with full honesty about what was and wasn't fixed, and re-verify live before the deferred whole-branch review/merge of both Plan 3B and 3C together.

**Architecture:** Four sequential phases on the existing `blue-agent-referee` branch/worktree: Hunt (parallel domain-scoped review agents produce raw findings) → Triage (consolidate into one ledger, dedupe, rank, disposition every item) → Fix (repeatable subagent-driven-development loop: implementer + task reviewer + independent secondary reviewer per finding, TDD for code) → Re-verify (a live Docker/Ollama round engineered to make `blue_agent` react to a real Wazuh alert, plus explicit SIEM daemon health checks, plus full regression).

**Tech Stack:** Python 3.11, pytest, Docker Compose, Wazuh 4.9.2, Ollama (qwen2.5:7b), Flask (`target`).

## Global Constraints

- **"Don't cheat anything"** (user's standing rule): every finding reported honestly; nothing silently weakened, hidden, or reclassified to make a check pass; anything parked gets a written reason in the ledger. This governs every task below.
- **Scope is the whole repo**, not just this branch's diff: `target/`, `red_agent/`, `blue_agent/`, `referee/`, `shared/`, `wazuh-rules/`, `wazuh/active-response/*.sh`, `docker-compose.yml`, both Dockerfiles, `pytest.ini`.
- **Out of scope**: `.devcontainer/` onboarding, manual-play mode (now Plan 3D, sequenced after this plan), the Groq/OpenAI provider-swap seam.
- **Every fix in Phase 3 gets two reviews**: a standard task reviewer AND an independent secondary review (`gstack` or `ecc:code-review`) — same dual-review bar as Plan 3B. Neither review is optional; neither is skipped to save time.
- **TDD for every code fix**: failing test first (proving the bug), then the minimal fix, then passing test. Shell-script and config fixes use direct verification (real command/state checks) since they aren't unit-testable the same way.
- **No merge yet**: Plan 3B's and this plan's final whole-branch review/merge decision happen together, once, after Phase 4 passes — not before.

---

### Task 1: Seed the findings ledger

**Files:**
- Create: `docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md`

**Interfaces:**
- Produces: a markdown table with columns `ID | Source | Component | Severity | Summary | Disposition | Notes`. Later tasks (Triage, Fix) append rows and update `Disposition`/`Notes` — never delete a row, per "no silent drops."

- [ ] **Step 1: Create the ledger file with the 6 known findings pre-seeded**

```markdown
# Plan 3C Findings Ledger

Every finding from Phase 1 (Hunt) lands here via Phase 2 (Triage). No row is
ever deleted — a rejected or parked finding gets a `Disposition` explaining
why, not removal. `Severity` is assigned/re-ranked during Triage by actual
impact, not by which tool found it.

| ID | Source | Component | Severity | Summary | Disposition | Notes |
|----|--------|-----------|----------|---------|--------------|-------|
| K1 | Known (pre-3C) | red_agent | Unranked (Triage assigns) | `red_agent/loop.py` has no heartbeat of its own -- it's a free rider on blue's go-signal heartbeat. Latent same-class deadlock risk if the go-condition ever becomes symmetric (see `referee/monitor.py::has_blue_heartbeat` comment). | Open | Fix in Phase 3 per Plan 3B's existing deadlock-fix pattern (2026-07-27). |
| K2 | Known (pre-3C) | red_agent, blue_agent | Unranked (Triage assigns) | `json.loads(args)` in both `red_agent/tools.py` and `blue_agent/tools.py` has no guard against a malformed non-JSON string -- same unhandled-input class as the KeyError gap already fixed in `escalate_response`. | Open | Two files, same fix shape -- can be one Fix-loop iteration covering both. |
| K3 | Known (pre-3C) | wazuh/active-response | Unranked (Triage assigns) | `lock-account.sh` and `kill-session.sh` never check `curl`'s exit code or `target`'s HTTP status -- same "claims success regardless of outcome" class as the original (fixed) `/internal/block-ip` bug. | Open | Direct verification fix (real curl/exit-code checks against a live container), not unit-testable. |
| K4 | Known (pre-3C) | blue_agent | Unranked (Triage assigns) | `blue_agent`'s alert-driven ReAct loop is verified only at the unit-test level -- never observed reacting to a real, Wazuh-generated alert in a live round. | Open | This is what Phase 4's re-verification is specifically designed to close -- see Task 6. |
| K5 | Known (pre-3C) | red_agent | Unranked (Triage assigns) | `red_agent` has no enforced recon-before-attack phase gating -- purely per-turn model judgment; confirmed by live observation to sometimes degenerate into unproductive looping. | Open | May be a design tradeoff rather than a clear bug -- flag for user's call during Triage if the Fix isn't obvious. |
| K6 | Known (pre-3C), highest priority | docker-compose.yml / wazuh.manager | Unranked (Triage assigns) | `docker-compose.yml` used to bind-mount `wazuh-rules/target_rules.xml` directly into `/var/ossec/etc/rules/`, which made `/var/ossec/etc/` look "already populated" to the Wazuh image's own first-boot init script and silently skipped installing `shared/ar.conf` and the rest of the default config tree on a fresh volume. `wazuh-analysisd` crashed at boot; nothing restarted it; the container still reported "Up" with zero Wazuh daemons running internally. Already fixed for this one file (routed through `WAZUH_CONFIG_MOUNT` overlay, commit `c02e726`) -- the real finding is the *verification methodology gap*: no automated check (not unit tests, not `docker compose ps`, not three live-run attempts) checks the SIEM's own internal daemon health. Only a human opening the dashboard caught it. | Fixed (mount), gap open | Phase 1's Hunt MUST include a check for any other bind-mount that could shadow an image's own init-time population logic. Phase 4's re-verification MUST add an explicit Wazuh-manager health check (all expected daemons running, API reachable) as a first-class assertion, not an afterthought. |
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md
git commit -m "docs: seed Plan 3C findings ledger with 6 known items"
```

---

### Task 2: Phase 1 Hunt — dispatch parallel domain-scoped review agents

**Files:**
- Create: `docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/` (one output file per agent, named after the agent)

**Interfaces:**
- Consumes: `docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md` (Task 1) — every dispatched agent gets briefed on the 6 known items so it doesn't waste effort rediscovering them, but is explicitly told to look everywhere else too.
- Produces: one raw-findings markdown file per agent in `hunt-results/`, each finding as `Component | Severity (agent's own opinion) | Summary | File:line | Suggested fix (if any)`. Task 3 (Triage) consumes all of these.

Dispatch every one of the following **in parallel** (single message, multiple tool calls — no dependencies between them), each as a background agent, each told: *"This is Phase 1 (Hunt) of Plan 3C, a full-system bug bounty on the `blue-agent-referee` branch at `<worktree path>`. Six findings are already known (read `docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md` first) — don't spend effort rediscovering those, but scope your review to [component] and report everything else you find, including things you're not sure are real bugs. Write your findings to `docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/<your-name>.md`. Report is honest and complete — an ambiguous case gets reported as ambiguous, not dropped."*

- [ ] **Step 1: Dispatch `ecc:security-review` against the whole repo**

Scope: injection, auth gaps, secret exposure, SSRF, unsafe crypto, OWASP-shaped issues, across `target/`, `red_agent/`, `blue_agent/`, `referee/`, `shared/`.
Output: `docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/security-review.md`

- [ ] **Step 2: Dispatch a gstack security-scan pass (second, independent security opinion)**

Same scope as Step 1, different tool/methodology — this is the "independent secondary opinion" principle applied to discovery, not just verification.
Output: `docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/gstack-security-scan.md`

- [ ] **Step 3: Dispatch `ecc:code-review` once per major component (5 separate dispatches)**

One each for `target/`, `red_agent/`, `blue_agent/`, `referee/`, `shared/`. Scope: correctness, silent failures, error handling, test coverage gaps.
Output: `docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/code-review-<component>.md` (5 files)

- [ ] **Step 4: Dispatch a dedicated Wazuh-rules/Active-Response review**

Scope: `wazuh-rules/target_rules.xml` and `wazuh/active-response/*.sh` (`lock-account.sh`, `kill-session.sh`, `bruteforce-guard.sh`, `idor-guard.sh`). Brief the agent explicitly: this is Wazuh rule XML and POSIX shell, a different idiom than the Python-focused reviews above — look for quoting bugs, `set -eu` gaps, race conditions, and exit-code/status-check omissions (Plan 3A's own history already found several of this exact class, per K3 — assume more exist).
Output: `docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/wazuh-rules-and-ar.md`

- [ ] **Step 5: Dispatch an infra/config review**

Scope: `docker-compose.yml`, `target/Dockerfile`, `red_agent/Dockerfile`, `blue_agent/Dockerfile`, `referee/Dockerfile`, `pytest.ini`. Brief the agent on K6 specifically (the bind-mount-shadows-init-script class of bug) and ask it to check every other volume mount in `docker-compose.yml` for the same shadowing risk, plus check `pytest.ini`'s `testpaths` actually collects every test directory that exists in the repo (the exact class of gap that motivated this whole plan).
Output: `docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/infra-config.md`

- [ ] **Step 6: Wait for all agents to complete, then commit the raw results**

```bash
git add docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/
git commit -m "docs: Phase 1 Hunt raw findings from 8 parallel review agents"
```

---

### Task 3: Phase 2 Triage — consolidate into one ranked, dispositioned ledger

**Files:**
- Modify: `docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md`

**Interfaces:**
- Consumes: all files in `docs/superpowers/plans/2026-07-28-plan-3c-hunt-results/` (Task 2).
- Produces: the ledger with every hunt finding added as a new row (IDs `H1`, `H2`, ... continuing after `K6`), every row's `Disposition` set to one of `Open` / `Fixed` / `Rejected: <reason>` / `Parked: <reason>` / `Needs user call: <question>`, and every `Severity` re-ranked by actual impact rather than by which agent reported it.

- [ ] **Step 1: Read every file in `hunt-results/` and list every distinct finding**

Do this yourself (the controller), not a subagent — Triage is a judgment task, not a search task.

- [ ] **Step 2: Dedupe** — if two agents reported the same underlying issue (e.g. both the security-review and a component code-review flag the same missing input guard), merge into one ledger row and note both sources.

- [ ] **Step 3: Rank by real severity** — a silent-failure crash risk outranks a naming nit regardless of which agent found it or how it was phrased. Assign `Severity` as one of `Critical` / `High` / `Medium` / `Low`.

- [ ] **Step 4: Flag genuinely ambiguous items for the user's call**

For anything that's a design tradeoff rather than a clear bug (K5 — the recon-gating question — is a likely candidate, and any hunt finding of similar shape), set `Disposition` to `Needs user call: <specific question>` rather than silently deciding either way.

- [ ] **Step 5: Give every row — including rejected/false-positive ones — a written disposition**

A hunt agent's finding that turns out not to be a real issue on inspection still gets a row with `Disposition: Rejected: <why>` — never silently dropped, per the global "don't cheat anything" constraint.

- [ ] **Step 6: Present the completed ledger to the user for the flagged judgment calls before Phase 3 starts**

Any `Needs user call` rows must get a real answer from the user (updating `Disposition` to a real value) before that specific row moves into Task 4 — the rest of the ledger can proceed independently.

- [ ] **Step 7: Commit**

```bash
git add docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md
git commit -m "docs: Phase 2 Triage -- consolidated, ranked, dispositioned findings ledger"
```

---

### Task 4: Phase 3 Fix — repeatable subagent-driven-development loop

**Files:**
- Modify: whichever files each ledger row's fix touches (determined per-iteration, not knowable in advance since the ledger is populated by Task 3).
- Modify: `docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md` (`Disposition` updated to `Fixed` per row as each iteration completes).
- Create: test files per fix, following each component's existing test layout (`red_agent/tests/`, `blue_agent/tests/`, `referee/tests/`, `shared/tests/`; shell/config fixes get a documented manual-verification script instead, saved alongside the fix).

**Interfaces:**
- Consumes: the completed ledger (Task 3) — every row with `Disposition: Open` (or a user-answered `Needs user call`) is a Fix-loop iteration. Rows marked `Rejected` or `Parked` are skipped by design (their written reason stands as-is).
- Produces: for each fixed row, a merged code change + passing test (or passing manual verification for shell/config) + the ledger row updated to `Fixed`.

This task is **one procedure, applied once per open ledger row**, in severity order (Critical first). It cannot be split into per-finding sub-tasks up front because the findings themselves don't exist until Task 3 completes — this is the same shape Plan 3B's own build used for its own bug fixes.

- [ ] **Step 1: Pick the next `Open` row, highest severity first**

If it's `Needs user call` and still unanswered, skip it and move to the next row — don't guess at the user's intent. Because rows are fixed and committed one at a time (never in parallel), an implementer always works against the current, already-partially-fixed codebase — this is what prevents two rows' fixes from silently conflicting in the same file. If a row's suggested fix (from its Hunt source) turns out to be incompatible with a change an earlier row already made to the same file, the implementer re-reads both findings against the current code state and resolves in favor of the more severe/foundational issue, documenting the choice in the row's `Notes` column.

- [ ] **Step 2: Dispatch a fresh implementer subagent for that one row**

Brief: the exact ledger row (component, summary, file/line if known), the global constraint that this is TDD for code / direct verification for shell-or-config, and that it should not touch any other ledger row's scope in the same pass.

For code fixes, the implementer must, in order: write a failing test proving the bug, run it to confirm it fails, write the minimal fix, run it to confirm it passes.

For shell/config fixes (K3's class, K6's class), the implementer must, in order: reproduce the bug's observable symptom against a live container (e.g. for K3: call the AR script with a `curl` target rigged to fail, confirm the script currently reports success anyway), apply the fix, re-run the same reproduction to confirm the symptom is gone.

- [ ] **Step 3: Dispatch the standard task reviewer** (per `subagent-driven-development`'s normal task-review stage) against the implementer's diff for this one row.

- [ ] **Step 4: Dispatch the independent secondary reviewer** — `gstack` review or `ecc:code-review`, whichever wasn't already used as a Hunt source for this same component in Task 2, so the second opinion is genuinely independent. This review is never skipped, even for a small fix.

- [ ] **Step 5: If either review finds a real problem, send the finding back to a fresh implementer subagent for that same row** (not the original implementer instance) and repeat Steps 2-4 for that row only.

- [ ] **Step 6: Once both reviews pass, update the ledger row's `Disposition` to `Fixed` and commit**

```bash
git add <files touched by this fix> docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md
git commit -m "fix: <one-line summary of the ledger row that was just fixed>"
```

- [ ] **Step 7: Repeat Steps 1-6 until every non-`Rejected`/non-`Parked` row is `Fixed`**

If a row can't be fixed within reasonable effort, it does not get silently left `Open` — it gets `Disposition: Parked: <specific written reason>` (per the global "don't cheat anything" constraint) and the loop moves on.

---

### Task 5: Phase 4 Re-verify — live round with Wazuh daemon health as a first-class check

**Files:**
- Create: `scripts/verify_wazuh_health.sh` (or `.py`, matching the project's existing scripting language convention — check `scripts/` for precedent before choosing)
- Modify: whichever re-verification/integration test currently drives a live round (check `referee/tests/` and any existing live-round harness from Plan 3B's own Task 12 verification for the file to extend, rather than creating a parallel one)

**Interfaces:**
- Produces: a health-check routine callable both as a standalone script and from the live re-verification run, returning non-zero if any expected Wazuh daemon (`wazuh-analysisd`, `wazuh-remoted`, `wazuh-apid`, and any others the manager's own `/var/ossec/bin/wazuh-control status`-equivalent reports) is not running, or if the Wazuh API doesn't respond (401 unauthenticated is a PASS — it proves the API process is up; connection-refused is a FAIL).

- [ ] **Step 1: Write the health-check script**

```bash
#!/usr/bin/env bash
# scripts/verify_wazuh_health.sh
# Exit 0 only if every expected Wazuh daemon is running inside the manager
# container AND the API responds (401 unauthenticated counts as up --
# connection-refused does not). This is the check that would have caught
# the K6 config-mount bug: the container reported "Up" while running zero
# Wazuh daemons internally, and nothing else in this project checked that.
set -euo pipefail

MANAGER_CONTAINER="purple-lab-wazuh-manager"

echo "Checking Wazuh daemon status inside $MANAGER_CONTAINER..."
STATUS_OUTPUT=$(docker exec "$MANAGER_CONTAINER" /var/ossec/bin/wazuh-control status)
echo "$STATUS_OUTPUT"

for daemon in wazuh-analysisd wazuh-remoted wazuh-apid wazuh-execd wazuh-db; do
  if ! echo "$STATUS_OUTPUT" | grep -q "${daemon}.*is running"; then
    echo "FAIL: ${daemon} is not running" >&2
    exit 1
  fi
done

echo "Checking Wazuh API reachability..."
HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:55000/ || echo "000")
if [ "$HTTP_CODE" = "000" ]; then
  echo "FAIL: Wazuh API connection refused (000)" >&2
  exit 1
elif [ "$HTTP_CODE" != "401" ] && [ "$HTTP_CODE" != "200" ]; then
  echo "FAIL: unexpected Wazuh API status $HTTP_CODE" >&2
  exit 1
fi

echo "PASS: all Wazuh daemons running, API reachable (HTTP $HTTP_CODE)"
```

- [ ] **Step 2: Make it executable and run it against the currently-running stack to confirm it passes today**

```bash
chmod +x scripts/verify_wazuh_health.sh
./scripts/verify_wazuh_health.sh
```

Expected: `PASS: all Wazuh daemons running, API reachable (HTTP 401)` — if this fails right now, that's itself a new, real finding; add it to the ledger (Task 1's file) before continuing, don't route around it.

- [ ] **Step 3: Prove the check actually catches the K6 class of failure (negative test)**

Temporarily revert the K6 fix in a scratch copy of `docker-compose.yml` (bind-mount `target_rules.xml` straight into `/var/ossec/etc/rules/` again), bring up a fresh `wazuh.manager` against a fresh volume (`docker compose down -v && docker compose up -d wazuh.indexer wazuh.manager`), and confirm `scripts/verify_wazuh_health.sh` now reports FAIL. This is the proof the check has teeth, not just that it happens to pass today. Restore the real `docker-compose.yml` afterward.

- [ ] **Step 4: Bring the full stack up fresh and drive a real Wazuh-triggering attack sequence**

```bash
docker compose down -v
docker compose up -d --build
```

Wait for `target` healthy, then let `red_agent` run autonomously — per K4, the goal is to confirm `blue_agent` reacts to a *real* Wazuh alert, not just synthetic/unit-test alerts. If a full round doesn't naturally produce a Wazuh-detectable pattern (SQLi, bruteforce, IDOR, command injection — the same four classes Plan 3A proved trigger real alerts), that's acceptable only if honestly reported per Step 6 below — don't fabricate a test alert or lower detection thresholds to force the demo to look complete.

- [ ] **Step 5: While the round runs, poll the health check and the blue-team event feed**

```bash
watch -n 10 ./scripts/verify_wazuh_health.sh
```

Confirm in `events.jsonl` (or the `purple_dashboard` UI, if still running) that `blue_agent` logs a `reasoning` or `escalation` event whose content references an actual Wazuh alert ID/rule from this run — not a heartbeat, not a stale alert from a previous run.

- [ ] **Step 6: Run the full regression suite**

```bash
pytest -v
```

Confirm the actual collected test count matches what's expected across every component's `tests/` directory (the exact class of gap `pytest.ini`'s `testpaths` misconfiguration hid before this plan started) — report the real number, not just "no failures."

- [ ] **Step 7: Write the honest re-verification summary and commit**

Document, in `docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md`, a final `## Phase 4 Re-verification Summary` section: whether `blue_agent` was observed reacting to a real alert (with the alert ID/rule and timestamp as evidence), the health-check result, and the regression suite's actual pass/fail/collected counts.

```bash
git add scripts/verify_wazuh_health.sh docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md
git commit -m "test: Phase 4 re-verification -- Wazuh daemon health check + live round evidence"
```

---

### Task 6: Final whole-branch review and merge decision (Plan 3B + 3C together)

**Files:** none created — this is a review/decision task, not a code task.

**Interfaces:**
- Consumes: the full diff of `blue-agent-referee` against `main`, covering both Plan 3B's original work and every fix from Task 4.

- [ ] **Step 1: Confirm every ledger row is `Fixed`, `Rejected: <reason>`, or `Parked: <reason>` — none left `Open`**

Read `docs/superpowers/plans/2026-07-28-plan-3c-findings-ledger.md` end to end. If any row is still `Open`, this task cannot start yet — return to Task 4.

- [ ] **Step 2: Invoke `superpowers:finishing-a-development-branch`** for the whole branch diff (`main...blue-agent-referee`), covering both Plan 3B and Plan 3C's changes together in one pass, per the original spec's Sequencing decision.

- [ ] **Step 3: Follow whatever that skill's process determines** (final review, merge, or further changes) — this plan's job ends at handing off to that skill with a clean, fully-dispositioned ledger.
