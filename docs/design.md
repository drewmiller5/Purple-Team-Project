# Purple Team AI Lab — Design Spec

**Course:** IT567 — Global Cybersecurity and Cyber Warfare
**Term paper:** Testing the Balance Between Offense and Defense in AI-Driven Cyber Conflict
**Date:** 2026-07-23
**Status:** Phase 1 (local lab) — approved for planning

## 1. Research Question & Thesis

Offense-defense theory (Garfinkel & Dafoe, 2019) holds that AI-driven capability favors offense when stakes are low and defense when stakes are high. The synopsis's working assumption was that defense would hold the advantage in a live environment, since most AI cyber training and roles skew defensive. This project sharpens that into a testable claim: **a low-stakes, resource-constrained, autonomous red-team agent can still beat a blue-team agent that has first-mover advantage** (built the system, deployed monitoring, and is actively watching before the attack begins).

"Low-stakes" is operationalized literally, not just narratively: both agents run on free, local Ollama models — no paid APIs, no token cost, so the experiment itself is a low-investment attacker/defender by construction.

## 2. Non-Negotiables

- **The target stays fully egress-blocked.** `lab-net` (the network the target container lives on) is `internal: true` — no real internet egress, ever. This is what makes live attack automation safe to build and run at all.
- **No artificial fairness constraint (2026-07-23 revision).** Red and blue are not scripted to leave each other alone. Both agents do their own reconnaissance of the Docker environment they're in, and if one discovers and can reach the other's infrastructure, going after it is fair game — up to and including disabling/killing the other side's running process. If either side "gets a hold of" the other, that run is effectively over for the loser, who has to come back with a different approach. This is closer to a real conflict than a turn-based CTF, which is the point of the experiment (per Drew: "it's not fair in the real world, so why would it be fair for an experiment").
- **Memory and the event log are never wiped, no matter who wins a round.** A side's process/container can be killed, but `red_memory.json` / `blue_memory.json` and the shared event log survive on disk always. This is the one true non-negotiable around persistence — losing a round costs the current run, not the accumulated learning history, because the paper's results section (V0 vs V5 vs V20) depends on that continuity.
- **True black-box for red.** Red starts with nothing but a URL — no source code, no hints, no seeded knowledge of where the vulnerabilities are. It must recon and discover them itself, including any path to host-level access or to blue's own infrastructure.
- **Zero cost.** Ollama (local, free), Docker Desktop (free personal use), Wazuh (open source), Sigma (open format), Atomic Red Team (open source, Red Canary), Flask/SQLite (free). No API keys required for anyone who runs this, ever.

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Docker bridge network (isolated, no internet egress)        │
│                                                                │
│  ┌──────────────┐        ┌──────────────────────────────┐    │
│  │  Target host  │◄──────►│  Blue Agent                   │   │
│  │  Flask site + │  logs/ │  - Wazuh manager + agent      │   │
│  │  seeded vulns │ telemetry - Sigma rules (custom)       │   │
│  │  + DB         │        │  - Ollama decides response     │   │
│  └──────▲───────┘        │  - Active Response: ban IP,    │    │
│         │  attacks        │    lock account, kill session  │   │
│         │                └──────────────────────────────┘    │
│  ┌──────┴───────────────────────────┐                        │
│  │  Red Agent                        │                        │
│  │  - No advance knowledge, just URL │                        │
│  │  - Recon → find seeded vulns →    │                        │
│  │    foothold → Atomic Red Team     │                        │
│  │    techniques on the host         │                        │
│  │  - Runs continuously, async       │                        │
│  └────────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
  Event log (every action/detection/response, timestamped, append-only)
         │
         ▼
  Post-hoc analysis → paper's results/timeline (round-by-round narrative
  reconstructed from timestamps, even though execution is real-time/async)
```

**Why real-time/async over turn-based:** a turn-based "chess" model is easier to build and log, but it's unrealistic — a real attacker or defender that spots an opening acts immediately, not on a scheduled turn. Running both agents fully asynchronously (each on its own continuous loop) is truer to how a real intrusion/response plays out. The event log's precise timestamps let the paper reconstruct a clean round-by-round narrative afterward without sacrificing realism during the actual run.

## 4. Components

| Component | Role |
|---|---|
| `target/` | Flask app + SQLite DB — a small "company info site" with 2-4 realistic, intentionally-planted vulnerabilities (SQLi, exposed admin panel with weak creds, IDOR on a document endpoint). Deliberately vulnerable like a custom mini Juice Shop. Justifies why blue is watching it at all. |
| `red_agent/` | Ollama-driven attacker loop. No advance knowledge. Recon phase (find the seeded vulns) → foothold → pivots to real ATT&CK techniques via Atomic Red Team once it has host access (discovery, persistence, credential access). |
| `blue_agent/` | Wazuh manager + agent, custom Sigma rules watching both web-layer logs (initial-access phase) and host telemetry (ATT&CK phase). Wazuh Active Response triggers automated countermeasures (ban IP, lock account, kill session) on rule match — this is blue's "chess match" reflex, largely native to the tool rather than hand-rolled. |
| `memory/` | `red_memory.json`, `blue_memory.json` — separate, isolated per side. What worked, what got caught, response timing. Continuously updated every run — this is how the system "learns" without needing model fine-tuning (in-context/experiential learning, not parametric). |
| `archive/v0/`, `v1/`, ... | Checkpoint snapshots: memory state + full event log + a run summary (techniques attempted/detected/blocked, time-to-access, time-to-detect, time-to-block) + which Ollama model version was used. V0 = the initial complete build, memory empty, nothing learned yet. V1+ = post-run checkpoints. |
| `docker-compose.yml` | Defines the isolated network and all containers. No internet egress from the target or red agent. |

## 5. Agent Loop (each side, independent, async)

1. **Observe** current state — red: recon results so far; blue: latest log/telemetry stream.
2. **Consult memory** (past attempts, what worked/got caught) + current observation → Ollama call → decide next action.
3. **Execute** — red: an HTTP request or technique; blue: a Sigma-triggered active-response script.
4. **Log** the event (timestamped, append-only) → update memory.

## 6. Measurement (paper's results section)

Per run, and trended across checkpoints (V0 vs. V5 vs. V20 — the actual "does it learn" evidence):

- Time-to-initial-access
- Time-to-first-detection
- Time-to-block
- Techniques attempted vs. detected vs. blocked
- Red's final access level achieved
- Outcome (red fully blocked / red achieved and held foothold / partial)

## 7. Phasing

**Phase 1 (this plan):** Everything above, running locally via Docker Compose. Complete and gradeable on its own — does not depend on Phase 2 to be a finished project.

**Phase 2 (future work, not built now):** GitHub Actions integration — a public "click Actions, watch it run" demo on GitHub's free CI runners. Deferred because Wazuh's normal footprint (manager + indexer + dashboard) is heavy for a free runner alongside two continuously-inferencing Ollama models; the real fix (a slimmed Sigma evaluator for CI, full Wazuh reserved for local runs) gets decided once Phase 1 is proven and mature, not guessed at now. Migrates from this Academic folder into `dev/` at that point, per Drew's existing repo convention.

## 8. Open Risks (carried into Phase 1, not blockers)

- **Red's ability to reliably discover the seeded vulns** depends on how well red_agent's recon/prompting is tuned — may need iteration once built.
- **Wazuh Active Response tuning** — getting rules sensitive enough to catch real attacks without false-positive lockouts on legitimate recon-adjacent behavior will take iteration.
- **Local model choice** (which Ollama model for both agents) is an implementation-phase decision, not fixed here — should be picked for a balance of capability and CPU-inference speed on Drew's hardware.

## Related

- Synopsis: `Synopsis for Term Paper.docx` (this folder)
- Vault reference: `work/school/Term Paper - AI Cyber Offense-Defense Synopsis.md` — ties this to the GitHub portfolio "Purple-team detection lab" concept (Atomic Red Team + Sigma + Wazuh, CySA+/Linux lab value, bank security-eng/SOC-II portfolio artifact)
