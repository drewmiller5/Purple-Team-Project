# Plan 3D: Manual Play & Purple-Team Advisor — Design

Brainstormed with Claude 2026-07-28, following the build of the `purple_dashboard` observability service (a live, read-only 3-tab view over the shared event log, referee assessments, and round state) added earlier the same session.

## Context

The dashboard was originally built strictly read-only and network-isolated (its own `dashboard-net`, no route to any other container, all volume mounts `:ro`) — deliberately mirroring the referee's own "no direct kill capability over either agent" design principle elsewhere in this project.

While reviewing the dashboard, the user asked for something bigger: the ability to manually issue red-team or blue-team actions, toggle the autonomous round on/off, and get purple-team advisory suggestions for both sides — "full interaction and capabilities if they choose... it needs to be simple." This is manual-play mode.

**Manual-play mode was explicitly deferred out of scope in Plan 3C's design spec** (`docs/superpowers/specs/2026-07-27-plan-3c-bug-bounty-design.md`: *"anything already explicitly deferred in the design spec (.devcontainer/ onboarding, manual-play mode, the Groq/OpenAI provider-swap seam) stays deferred — 3C is about correctness and robustness of what's built, not adding new features"*). Rather than silently reversing that decision or bolting a new feature onto a bug-bounty pass, this is broken out as its own plan (3D), brainstormed and specced separately, with implementation explicitly sequenced **after** Plan 3C's Hunt → Triage → Fix → Re-verify completes — the interactive layer gets built on top of a system that has actually been audited, not before.

## Facts established during brainstorming (grounding the design)

- `red_agent` and `blue_agent` are pure outbound ReAct loops against Ollama — **neither has a listening port or command inbox**. There is no way to "tell the running agent what to do next" without modifying its loop.
- `blue_agent`'s only real defensive tool, `escalate_response` (`blue_agent/tools.py`), is nothing more than an HTTP POST from the agent to `target`'s own `/internal/lock-account`, `/internal/kill-session`, or `/internal/block-ip` endpoints, keyed by `{lock_account: username, kill_session: user_id, block_ip: source_ip}`.
- The only existing control surface anywhere in the system is the referee's flag-file protocol: `referee-state/go.flag` (touched once by the referee after seeing blue's first heartbeat) and `stop.flag` (touched once a decisive winner or timeout is reached). `red_agent`/`blue_agent` poll for these; nothing else reads or writes them today.
- `referee/monitor.py`'s win conditions (`blue_decisive_win`, `red_decisive_win`, `has_blue_heartbeat`) are plain Python functions scanning the shared `events.jsonl` by `side` only — no concept of *who* (human vs. agent) produced an event.
- `red_agent`/`blue_agent` already have independent, persistent cross-run memory (`red_memory.json` / `blue_memory.json`, surfaced via `recall_past_findings` / `recall_summary`) that lets each agent build on its own past autonomous decisions across separate rounds. This is a *separate* mechanism from anything in this spec and is unaffected by it — manual play adds a second, parallel actor (a human) alongside the agent, it does not feed into or alter the agent's own memory/learning loop.

## Scope

An interactive control layer added to the existing `purple_dashboard` service:

1. **Round control** — Start/Stop using the existing `go.flag`/`stop.flag` protocol (no new mechanism).
2. **Manual red actions** — canned templates for `target`'s 4 seeded vulnerabilities (SQLi login, IDOR, bruteforce, command injection) plus a raw method/path/JSON-body form, issued as direct HTTP requests from the dashboard to `target`.
3. **Manual blue actions** — the same three actions `blue_agent` already performs (`lock_account`/`kill_session`/`block_ip`), issued via the same `target` `/internal/*` endpoints.
4. **Purple-team advisor** — a 4th dashboard tab: free-text question, answered by Ollama using recent event-log context as a system-prompted advisor. **Read-only by construction — it returns text only and never calls any tool, endpoint, or agent action itself.**
5. **"Found it" acknowledgment** — a cosmetic detector, separate from the referee, that recognizes when a *human-tagged* action matches a win-condition-shaped result (e.g. manually reaching `/admin/diagnostics`, or manually reproducing blue's decisive-win pattern) and surfaces a congratulatory UI toast. It has no effect on round state, scoring, or `stop.flag`.

**Explicitly out of scope**: giving `red_agent`/`blue_agent` themselves a live command inbox (considered and rejected as Approach C during brainstorming — it would mean reopening and modifying the two loop files Plan 3B just spent a full night verifying, before Plan 3C has even audited them, for a capability manual play already delivers via the parallel-actor model below). Also out of scope: anything Plan 3C already covers (bug-bounty findings) — this plan assumes 3C's fixes are already merged.

## Design

**Architecture**: The dashboard container moves off its isolated `dashboard-net` onto `lab-net` (to reach `target:5000` directly) and `agent-net` (to reach Ollama at `host.docker.internal:11434`). This is a deliberate, disclosed change to the isolation posture built earlier the same session — the whole point of this plan is to let a human act, not just observe. No Docker socket is mounted; no host-level container control is added. `red_agent`, `blue_agent`, and `referee` application code is untouched, with one narrow exception below.

**Actor model**: A human using manual play and an autonomous agent become two independent actors that can both act against `target` concurrently. Every manual action is logged to the same shared `events.jsonl` with `actor: "human"` (vs. the implicit agent default) alongside the existing `side` field, so manual and autonomous activity render identically in the existing red/blue feeds, distinguished only by actor tag.

**The one change to existing verified code**: `referee/monitor.py`'s three functions (`has_blue_heartbeat`, `blue_decisive_win`, `red_decisive_win`) gain a filter excluding `actor == "human"` events from their scans, so a human manually reproducing a win-condition pattern during a live autonomous round can never silently end that round. This is a small, mechanical, independently-testable change — not a rewrite of referee logic.

**Data flow**:
- *Round control*: dashboard POST → touch/clear `go.flag`/`stop.flag` in `referee-state` (now mounted read-write for the dashboard, was `:ro`).
- *Manual red*: dashboard form (template pick or raw request) → dashboard issues the HTTP request to `target` directly using a plain HTTP client → logs `{"side": "red", "actor": "human", "phase": "http_request", "request": ..., "response": ...}` to `events.jsonl`.
- *Manual blue*: dashboard form (action + target identifier) → dashboard POSTs to `target`'s corresponding `/internal/*` endpoint (same endpoint/field mapping `blue_agent/tools.py` uses) → logs `{"side": "blue", "actor": "human", "phase": "escalation", ...}`.
- *Purple advisor*: dashboard reads recent `events.jsonl` tail, sends it plus the user's question to Ollama with an advisor system prompt, displays the response. Not written to `referee_assessments.jsonl` (the referee's own deterministic-judge log) — kept in a separate file/volume so advisory text never mixes with or is mistaken for an actual referee verdict.
- *"Found it"*: after each manual action, the dashboard re-runs a human-scoped copy of the win-condition check shape against `actor:"human"` events only, and if matched, shows a toast. No write path to `stop.flag`.

**Error handling**: if `target` or Ollama is unreachable when a manual action or advisor query fires, the dashboard surfaces the error inline (mirroring how `blue_agent` already logs `ollama_error` rather than swallowing it) — consistent with this project's standing "don't cheat anything" rule; failures are shown, not hidden.

**Testing**: the `monitor.py` actor-filter change gets unit tests following the existing `referee/tests/` pattern (failing test first, proving human-tagged events don't trigger a win, then the fix). The dashboard's new POST endpoints get integration-style tests against a `target` test double, matching how `red_agent`/`blue_agent`'s own HTTP tool tests work today. Manual acceptance criterion: a full live click-through — round start → manual red attack → manual blue response → advisor question → "found it" toast → round stop — once implemented.

## Sequencing

Implementation waits until Plan 3C's Phase 4 (Re-verify) completes and the branch is ready for the deferred whole-branch review. This plan's spec exists now so both specs are ready ahead of any implementation, but 3D's implementation plan should not be executed until 3C's fixes land — the interactive layer is built on an audited system, not a pre-audit one.
