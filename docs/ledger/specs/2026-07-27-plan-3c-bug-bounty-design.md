# Plan 3C: Full-System Bug Bounty — Design

Brainstormed with Claude 2026-07-27, following completion of Plan 3B (`blue_agent` + `referee`, verified end-to-end live on the `blue-agent-referee` branch, not yet merged to `main`).

## Context

Plan 3B's build-and-verify process (subagent-driven-development, task review + independent secondary review per task, three live Docker/Ollama verification attempts) surfaced real bugs at every layer it touched — a cross-process deadlock, a container-readiness race, silent-failure gaps in error handling, and a testpaths misconfiguration that had been silently hiding a real regression across the *entire* project (not just this branch) since before this session started. That last one is the reason for Plan 3C: if a config gap that basic could sit undetected in already-merged code, there is no reason to assume the rest of the system (`target`, `red_agent`, Wazuh detection rules, Active Response scripts) is clean just because it shipped and passed its own review at the time.

Plan 3C is a dedicated, open-ended audit of the **whole system** — not just this branch's new code — before the project moves toward deployment. The user's explicit standing rule for this entire effort: **don't cheat anything.** Every finding gets reported honestly. Nothing gets silently weakened, hidden, or reclassified to make a check pass. Anything that can't be fixed now gets parked with a written reason, never quietly dropped.

## Scope

Everything in the repo, not just Plan 3B's diff:

- `target/` — the Flask app, its 4 seeded vulns, `target/routes/internal.py`'s three defensive endpoints
- `red_agent/` — config, loop, tools, http/ollama clients, state
- `blue_agent/` — same, from tonight's build
- `referee/` — the deterministic monitor, from tonight's build
- `shared/` — memory + event log primitives (unmodified since Plan 1, but never independently security-reviewed)
- `wazuh-rules/` and `wazuh/active-response/*.sh` — the Sigma-derived XML rules and the custom counting/AR shell scripts from Plan 3A
- `docker-compose.yml`, both Dockerfiles, `pytest.ini` — infra/config, proven this session to hide real gaps
- The 5 items already on record from tonight (guaranteed floor, not the ceiling):
  1. `red_agent/loop.py` has no heartbeat at all and is a "free rider" on blue's go-signal heartbeat — latent same-class-deadlock risk if the go-condition ever becomes symmetric.
  2. `json.loads(args)` in both `red_agent/tools.py` and `blue_agent/tools.py` has no guard against a malformed non-JSON string — same unhandled-input class as the KeyError gap already fixed in `escalate_response`.
  3. `wazuh/active-response/lock-account.sh` and `kill-session.sh` never check `curl`'s exit code or `target`'s HTTP status — same "claims success regardless of outcome" class as the original (fixed) `/internal/block-ip` bug.
  4. `blue_agent`'s alert-driven ReAct loop is verified only at the unit-test level — it has never been observed reacting to a real, Wazuh-generated alert in a live round.
  5. `red_agent` has no enforced recon-before-attack phase gating — purely per-turn model judgment, confirmed by live observation to sometimes work well and sometimes degenerate into unproductive looping.
  6. **(Highest priority — found after this spec was first written, during live user interaction post-Task-12)** `docker-compose.yml` bind-mounted `wazuh-rules/target_rules.xml` directly into `/var/ossec/etc/rules/` on `wazuh.manager`, which made `/var/ossec/etc/` look "already populated" to the Wazuh image's own first-boot init script and silently skipped installing `shared/ar.conf` and the rest of the default config tree on a fresh volume. `wazuh-analysisd` (the actual detection engine) crashed at boot with a config error and nothing restarted it — the container reported "Up" in `docker compose ps` while running zero Wazuh daemons internally. Already fixed for this specific file (routed through the `WAZUH_CONFIG_MOUNT` overlay instead, commit `c02e726`), but the *verification methodology gap* this exposes is the real finding: no automated check in this project — not unit tests, not `docker compose ps`, not any of Task 12's three live-run attempts — checks the SIEM's own internal process health. Only a human opening the dashboard and looking caught it. Phase 1's Hunt should explicitly include a check for this class of bug (any other bind-mount that could shadow an image's own init-time population logic) and Phase 4's re-verification must add an explicit Wazuh-manager health check (all expected daemons running, API reachable) as a first-class assertion, not an afterthought.

**Out of scope:** anything already explicitly deferred in the design spec (`.devcontainer/` onboarding, manual-play mode, the Groq/OpenAI provider-swap seam) stays deferred — 3C is about correctness and robustness of what's built, not adding new features.

## Approach

Four phases:

### Phase 1 — Hunt

Dispatch parallel, domain-scoped review agents against the full merged system (this branch, since it already contains everything — see Sequencing below):

- **`ecc:security-review`** — injection, auth gaps, secret exposure, SSRF, unsafe crypto, OWASP-shaped issues, across all Python packages.
- **gstack security-scan** (or equivalent gstack security tooling) — a second, differently-shaped security pass, same "independent secondary opinion" principle used throughout Plan 3B, but applied to discovery instead of just verification.
- **`ecc:code-review`** general sweeps, one per major component (`target`, `red_agent`, `blue_agent`, `referee`, `shared/`) — correctness, silent failures, error handling, test coverage gaps.
- **A dedicated pass over `wazuh-rules/*.xml` and `wazuh/active-response/*.sh`** — these are a different idiom (Wazuh rule XML, POSIX shell) that general Python-focused review tools won't meaningfully evaluate; needs a reviewer briefed on Wazuh AR semantics and shell-scripting pitfalls (quoting, `set -eu` behavior, race conditions — Plan 3A's own history already found several of these, so this pass should assume more exist).
- **Infra/config review** — `docker-compose.yml`, both Dockerfiles, `pytest.ini` — informed directly by tonight's lesson that config gaps hide real regressions silently.

The 5 known items above go straight into the Phase 2 findings ledger without needing rediscovery — hunt agents are briefed on them so effort isn't wasted re-finding what's already known, but instructed to look everywhere else too.

### Phase 2 — Triage

Controller consolidates every hunt agent's output into one findings ledger. Dedupe overlapping reports. Rank by real severity, not by which tool found it — a silent-failure crash risk outranks a naming nit regardless of source. Anything genuinely ambiguous (a design tradeoff, not a clear bug) gets flagged for the user's call, same pattern as tonight's block-ip / lock-account.sh / recon-phase decisions. Every finding — including ones ultimately judged not worth fixing — gets a written disposition in the ledger. No silent drops.

### Phase 3 — Fix

`subagent-driven-development`: fresh implementer + task review + independent secondary review per finding or tightly-related batch, exactly tonight's loop. TDD where the finding is code (failing test proving the bug → fix → passing test), direct verification where it isn't (config, shell scripts).

### Phase 4 — Re-verify

A final live Docker/Ollama round, specifically designed to give `blue_agent` a real chance to react to an actual Wazuh-generated alert (addressing known item #4) — e.g., driving `red_agent` toward request patterns proven in Plan 3A to trigger real alerts (SQLi, bruteforce, IDOR, command injection), rather than relying on unscripted model behavior alone. Full regression suite run. Only after this passes does the branch move to final whole-branch review and the merge decision (for both 3B and 3C's fixes together — see Sequencing).

## Sequencing: does this need 3B merged first?

No. Plan 3B's final whole-branch review and merge-to-`main` decision were explicitly deferred by the user tonight in favor of writing Plan 3C. Since 3C's scope requires `blue_agent`/`referee` to exist to audit them, and they currently only exist on the `blue-agent-referee` branch, Plan 3C continues directly on that same branch rather than merging first and re-branching. The final whole-branch review (per `subagent-driven-development`'s own process) happens once, after both 3B's and 3C's work are both complete, covering the full branch diff from `main` in one pass — not twice.

## Error Handling / Failure Modes

- If a hunt agent's finding turns out to be a false positive on triage, it still gets logged in the ledger with a "reviewed, not a real issue, because X" disposition — not silently discarded.
- If a fix for one finding conflicts with another finding's fix (e.g., two agents propose incompatible changes to the same file), the controller resolves by re-reading both findings against the current code state and choosing the fix that serves the more severe/foundational issue, documenting the choice.
- If Phase 4's re-verification still can't get a real Wazuh alert to fire for blue to react to after a deliberately-crafted attack sequence, that itself is a finding to report honestly (per "don't cheat anything") — not something to route around by fabricating a test alert or lowering detection thresholds just to make the demo look complete.

## Testing Strategy

- Every code fix follows TDD: failing test first (proving the bug), then the fix, per this project's established convention.
- Shell script fixes (AR scripts) get their existing manual-verification-style checks (real `iptables`/`curl` state checks against a live container), matching how Plan 3A's own AR script bugs were originally verified, since these aren't unit-testable in the same way as Python code.
- Config/infra fixes (compose, Dockerfiles, pytest.ini) get validated the same way tonight's fixes were: `docker compose config`, `docker compose build`, and a direct `pytest -v` re-run confirming the *actual* collected test count, not just "no failures" (the testpaths lesson).
- Phase 4's live re-verification is the acceptance test for the whole plan — it isn't complete until a real round demonstrates blue reacting to a real alert, or an honest, evidence-based explanation of why it still doesn't.
