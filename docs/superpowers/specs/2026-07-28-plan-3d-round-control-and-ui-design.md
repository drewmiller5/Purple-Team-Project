# Plan 3D Addendum: Round Control, Restart Helper & UI Design

Extends `docs/superpowers/specs/2026-07-28-plan-3d-manual-play-design.md`, which
already specs manual red/blue actions, the purple advisor, and the "found it"
toast. This addendum covers what that spec didn't: (1) an explicit decision
to proceed now rather than wait for 3C's Phase 4, (2) a restart mechanism for
reviving fully-exited round containers, and (3) a real visual design pass —
the existing dashboard is a single hand-rolled dark theme with no design
treatment.

## Sequencing override

The original spec said implementation waits for 3C's Phase 4 (Re-verify) to
complete. User decision, 2026-07-28: proceed now given today's deployment
deadline. 3C's remaining ~21 fix-loop iterations (H3 onward) stay deferred
and resume after this work, per the standing "don't cheat anything" ledger
note in `.superpowers/sdd/2026-07-28-plan-3c-bug-bounty-implementation/progress.md`.

## Problem: rounds can't be revived from the UI

`referee`, `red_agent`, and `blue_agent` have no `restart:` policy. Once a
round ends (decisive win or `REFEREE_MAX_ROUND_SECONDS` budget expiry), all
three processes exit and the containers sit stopped. Today the only way to
start a new round is `docker compose up -d referee red_agent blue_agent`
from a terminal. The dashboard (browser-only, no Docker access) can't do
this, and — as established live during this session — `go.flag`/`stop.flag`
toggling alone can't either, since it assumes the processes are already
running and merely paused on a flag check.

## Design: scoped restart helper

A new minimal service, `round_helper`, is the **only** container in the
stack with `/var/run/docker.sock` mounted. Its entire surface area:

- `POST /restart-round` — runs `docker compose up -d referee red_agent
  blue_agent` (or the Docker SDK equivalent) against a **hardcoded
  allowlist of exactly those three container names**. Any request is
  rejected if it doesn't match the allowlist exactly — there is no
  generic "restart container X" endpoint, no stop/inspect/exec, no way to
  target anything else in the stack.
- No other routes. No auth beyond network placement (see below) — this is
  a lab environment, and the endpoint's own scope restriction *is* the
  security boundary, not a credential.

**Network placement**: `round_helper` joins `agent-net` only (same
reasoning as `purple_dashboard`'s existing network moves in the base 3D
spec) — never `lab-net`, so it has no path to `target` and isn't reachable
from anything red-team-adjacent. `purple_dashboard` calls it over
`agent-net`.

**Why a separate service and not folding this into `purple_dashboard`
directly**: `purple_dashboard` is about to gain a much larger surface
(manual attack forms, raw HTTP request builder, advisor free-text input) —
exactly the kind of thing a real (if simulated) attacker in this project
targets. Keeping the one component with `docker.sock` access small,
single-purpose, and easy to audit in full (it's one route) matters more
here than convenience. This mirrors the referee's own "no direct kill
capability" isolation principle elsewhere in the project.

**Failure handling**: if the restart call fails (Docker unreachable,
container build broken), the dashboard surfaces the error inline —
consistent with the base spec's "don't cheat anything" error-handling rule.

## Round-status visibility fix

Current bug (confirmed live): the event feed renders oldest-first and
auto-scrolls, so a round's final verdict (`round_over` in the white/referee
feed) is the last line at the bottom of a long scrolling panel — easy to
miss entirely if you're not already scrolled down or on that tab. Not a
missing-data bug; `referee_assessments.jsonl` already has the data.

Fix: a persistent result banner in the header (next to the existing
go/stop status badge) showing the most recent round's outcome — winner (or
"timed out") and duration — that updates the moment a `round_over` event
lands, independent of which tab is active or scroll position. The
underlying event feeds can stay chronological (oldest-first still makes
sense for reading a timeline top-to-bottom); the banner solves "don't make
me hunt for the one line that matters."

## UI design pass

The current dashboard (`dashboard/app.py`'s inline `PAGE` template) is a
single hand-rolled CSS theme, functional but not designed — no real
typography scale, spacing system, or visual hierarchy beyond the original
quick build. Given the dashboard is about to become the primary way a human
interacts with the whole exercise (watch, attack, defend, ask the advisor,
control rounds), it gets a real design pass during implementation using the
`ui-ux-pro-max`/`frontend-design` skills — not scoped further here since
that's exactly what those skills are for. Constraints for that pass:
single-file Flask + inline template/CSS/JS stays the deployment model (no
new build toolchain), dark theme stays (matches the "live ops board" feel
already established), and the red/blue/white color coding already in use
stays as the semantic color system.

## Testing

- `round_helper`'s allowlist enforcement gets a unit test: requesting
  restart of a name outside the allowlist is rejected; the three allowed
  names succeed (mocked Docker calls, not a real container restart in
  tests).
- Manual red/blue action endpoints and the round-status banner follow the
  existing base spec's testing approach (integration-style against a
  `target` test double; `monitor.py`'s actor-filter change gets a
  failing-test-first unit test).
- Manual acceptance criterion (extends the base spec's click-through): after
  a round ends via timeout or decisive win, the banner shows the correct
  outcome without needing to switch tabs or scroll; clicking restart from a
  fully-stopped state brings all three containers back up and a new round
  begins.
