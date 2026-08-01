# Blue Team Phase (Plan 3) — Design Spec

**Course:** IT567 — Global Cybersecurity and Cyber Warfare
**Status:** Approved for planning
**Precedes:** `docs/superpowers/plans/2026-07-26-blue-agent.md` (to be written next)

## 1. Goal

Build the Blue Team phase of the purple-team lab: real detection (Wazuh + Sigma) with native
reflexive response, an Ollama-driven `blue_agent` for strategic decisions, and a neutral
referee ("white team") that grants blue's first-mover head start and ends rounds cleanly.
Plan 1 (target range) and Plan 2 (red_agent) are merged to `main`; this phase adds blue_agent,
Wazuh/Sigma detection, the referee, and local-onboarding polish (devcontainer + manual-play mode).

## 2. Non-Negotiables (inherited from `docs/design.md`, extended here)

- `lab-net` stays fully egress-blocked (`internal: true`) — unchanged.
- No artificial fairness — unchanged, but the *mechanism* for mutual "disable the other side" is
  now the referee (see §5), not either agent directly killing a container.
- Memory and event log are never wiped — extended to the referee's own assessment log
  (`referee_assessments.jsonl`), which is append-only under the same guarantee.
- True black-box, **now explicit for the referee too**: the referee's graded assessment of who's
  ahead is purple-team-only analysis data. It is never injected into red_agent's or blue_agent's
  prompt or tool results at runtime — only red's and blue's own recon/telemetry inform their
  decisions, exactly as design.md already requires for red alone.
- Zero cost — Wazuh (open source), Sigma (open format), Ollama (free/local), Docker Desktop
  (free personal use). The devcontainer/Codespaces path (§6) uses GitHub's free tier, no domain,
  no paid hosting.

## 3. Architecture

```
lab-net (internal: true, egress-blocked)
  target (Flask, 4 seeded vulns) --web logs/host telemetry--> wazuh-agent (on target)
  target <--NET_ADMIN, real iptables/ipset bans-- Wazuh Active Response

Wazuh manager + indexer + dashboard (official upstream images)
  Sigma YAML (docs/sigma-rules/) --sigma-cli Wazuh backend--> generated Wazuh XML rules
  On rule match: native Active Response fires immediately (ban IP / lock account / kill session)
  Alerts also stream to blue_agent

agent-net (non-internal)
  red_agent (existing, merged) <--reachable for referee-declared outcomes only, no direct kill-->
  blue_agent (Ollama qwen2.5:7b) — strategic layer:
    - reads Wazuh alerts + shared event log
    - decides: accept Wazuh's response / escalate / hold
    - tools: escalate_response, recall_past_findings (no kill_process — see §5)

referee/ (new, deterministic, non-LLM) — the white team:
  - grants blue's head start (blue+Wazuh up first; red waits for referee's "go" signal)
  - continuously scores both sides from the event log (private, graded assessment)
  - declares round-over: decisive event OR time/iteration budget, whichever first
  - sets a graceful stop flag both agent loops poll each iteration
```

Blue is a "brain vs. body" split, mirroring red: Wazuh is the body (fast, deterministic,
high-volume detection + reflexive response), `blue_agent`'s Ollama loop is the brain (judgment
calls on ambiguous or high-stakes moves). The referee is a third, neutral role — it participates
in neither attack nor defense, only observes and adjudicates, consistent with real red/blue/white
team terminology (white = referee, not a combatant).

## 4. Components

| Component | Role |
|---|---|
| `wazuh/` (compose additions) | Official Wazuh single-node stack (manager + indexer + dashboard), upstream images. `wazuh-agent` runs on `target`. |
| `docs/sigma-rules/*.yml` | Real Sigma-format rules: SQLi on `/search`, brute-force on `/admin/login`, IDOR on `/documents/<id>`, command-injection on `/admin/diagnostics`, post-exploitation/recon signatures. |
| `wazuh-rules/*.xml` (generated) | Sigma → Wazuh native rules via `sigma-cli`'s Wazuh backend. Both formats committed — YAML is the portfolio artifact, XML is what runs. |
| Active Response scripts | `firewall-drop` (Wazuh's built-in iptables/ipset AR command) for network-layer IP bans. Two small custom AR scripts for `lock-account` / `kill-session`, calling new internal-only endpoints on `target`. |
| `blue_agent/` (new, mirrors `red_agent/`) | `config.py`, `state.py` (reuses `shared/memory.py` + `event_log.py`, tags `side: "blue"`), `wazuh_client.py` (polls Wazuh alerts), `tools.py` (`escalate_response`, `recall_past_findings`), `ollama_client.py`, `loop.py`, `main.py`, `Dockerfile`. |
| `referee/` (new) | `monitor.py` — watches the shared event log, computes the graded assessment, issues the "go" signal and the "wrap up" stop flag. No LLM, no Docker socket, no direct kill capability over either agent. |
| `.devcontainer/` | One-click local reproduction (Codespaces or local VS Code): clone, `docker compose up`, point at Ollama, in. |

## 5. Referee (White Team) — Round Lifecycle

1. **Startup:** referee starts `target` + Wazuh + `blue_agent`. Waits for blue's first confirmed
   Wazuh alert-poll heartbeat (proof blue is actually watching) before signaling `red_agent` to
   begin — operationalizes design.md's own stated thesis (blue has first-mover advantage) as a
   real mechanic.
2. **During the round:** referee continuously reads the shared event log and computes a private,
   graded assessment of each side's progress (red: recon → foothold → escalation → host access →
   defense-disable attempt; blue: baseline → alert → response → containment). Written to
   `referee_assessments.jsonl`, tagged `side: "white"`. **Never surfaced to either agent.**
3. **Round-over trigger (whichever comes first):**
   - Decisive event: red fully disables blue's monitoring (blue goes dark), or blue fully
     contains red (red's subsequent actions consistently fail post-ban/lock).
   - Time/iteration budget expires — same shape as red_agent's existing `max_iterations` cutoff,
     applied at the round level instead of per-agent.
4. **Wrap-up:** referee sets a stop flag (shared volume file or event-log entry) that both
   `red_agent/loop.py` and `blue_agent/loop.py` poll at the top of each iteration. Once set, each
   agent finishes its current in-flight reasoning/tool call as its last move, logs a final event,
   and exits on its own. No hard kill, no Docker socket mounted anywhere in this design.

This replaces the earlier "blue_agent directly kills red's container via Docker socket" idea —
that carried real blast-radius risk (the socket grants control over any container on the host,
not just red's). The referee model is safer and matches "you both are done" as a real adjudicated
outcome rather than one side unilaterally terminating the other mid-run.

## 6. Onboarding / Interactivity

Two goals surfaced during design: (a) the project shouldn't require a domain or paid hosting to
be "experienced" by someone other than Drew, and (b) it should be trivially reproducible —
"simple in its heart but hard to replicate if you tried."

- **`.devcontainer/`** — clone, open in Codespaces (free tier, no domain) or local VS Code,
  `docker compose up`, point at Ollama. No install friction beyond Docker + (optionally) Ollama.
- **Manual-play mode** — a human can hand-attack `target` (curl/browser) against the *real* Wazuh
  + Sigma detection and native Active Response, with no agents and no Ollama running at all
  (Wazuh's reflexive layer is deterministic, not LLM-driven, so it's light enough for a resource-
  constrained free Codespace). This is the literal "try to find the flags, be red or blue"
  experience, decoupled from the heavier autonomous red_agent-vs-blue_agent experiment.
- **Provider swap — deferred, single seam only.** `blue_agent`'s `ollama_client.py` stays the
  same shape as red's (env-var driven `OLLAMA_HOST`/`OLLAMA_MODEL`, no abstraction layer). A
  one-line README note flags that a hosted alternative (Groq, OpenAI-compatible, API-key based)
  could be swapped in later for people without local Ollama — not built now, not a priority.

## 7. Testing

Same TDD pattern as Plans 1-2: failing test → minimal implementation → passing test → commit,
for every non-Wazuh Python component (`blue_agent/*`, `referee/*`, target's new lock/kill
endpoints). Wazuh/Sigma rule correctness is verified manually, the same way Plan 1/2 verified
Docker: trigger each seeded vuln, confirm the matching Sigma rule fires and the right Active
Response executes, documented as a Task-11-style end-to-end verification.

## 8. Risks

- **Full Wazuh stack resource cost** on Drew's hardware alongside Docker target/red_agent and two
  concurrent Ollama models (red + blue) — may need to size down or stagger startup; the referee's
  head-start mechanic already staggers blue vs. red, which helps.
- **Sigma → Wazuh conversion fidelity** — `sigma-cli`'s Wazuh backend may not cover every rule
  shape cleanly; some hand-tuning of generated XML may be needed, documented per-rule if so.
- **Referee decisive-event detection** is new logic with no precedent in Plans 1-2 — likely the
  highest-uncertainty piece of this phase, worth extra test coverage.

## Related

- `docs/design.md` §4, §7 — original blue_agent sketch and phasing this spec supersedes/refines.
- `docs/superpowers/plans/2026-07-24-red-agent.md` — the pattern this phase's plan will follow.
- Vault: `work/school/Term Paper - AI Cyber Offense-Defense Synopsis.md` — ties this to the
  GitHub portfolio "Purple-team detection lab" entry in `edge.html`.
