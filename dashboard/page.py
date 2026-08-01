PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Purple Team Live View</title>
<style>
  :root {
    color-scheme: dark;
    /* Dark OLED "live ops board": a deep near-black plane with elevated
       surfaces stacked on top. Depth comes from surface steps + hairline
       borders, not shadows -- keeps white emission low and the wire legible. */
    --page-plane:     #08080a;
    --surface-1:      #131316;
    --surface-2:      #1b1b1f;
    --surface-3:      #26262b;
    --text-primary:   #f4f4f2;
    --text-secondary: #c3c2b7;
    --muted:          #86847d;
    --gridline:       #2a2a2e;
    --border:         rgba(255,255,255,0.09);
    --border-strong:  rgba(255,255,255,0.16);
    --series-red:     #e66767;
    --series-blue:    #4a92e8;
    --series-white:   #ffffff;
    --series-purple:  #a855f7;
    --status-good:     #2bb24c;
    --status-critical: #e0483f;
    --status-muted:    #86847d;
    --font-ui:   system-ui, -apple-system, "Segoe UI", sans-serif;
    --font-mono: ui-monospace, "Cascadia Code", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    /* Type scale (px): xs 11 / sm 12 / base 13 / md 15 / lg 18 / xl 22 */
    /* Spacing rhythm: 4 / 8 / 12 / 16 / 20 / 24 on an 8px base */
    --sp-1: 4px; --sp-2: 8px; --sp-3: 12px; --sp-4: 16px; --sp-5: 20px; --sp-6: 24px;
    --radius: 8px; --radius-sm: 5px;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--page-plane); color: var(--text-secondary);
    font-family: var(--font-ui);
    font-size: 13px; line-height: 1.5;
    margin: 0; height: 100vh; display: flex; flex-direction: column;
    -webkit-font-smoothing: antialiased;
  }
  /* Event stream reads as a live log console -- monospace on the data
     itself (timestamps, phase tags, content), UI chrome stays on the
     regular face. Keeps the two registers -- "controls" vs "wire" --
     visually distinct at a glance. */
  button:focus-visible, input:focus-visible, select:focus-visible, [tabindex]:focus-visible {
    outline: 2px solid var(--series-blue); outline-offset: 2px;
  }
  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
  }

  /* --- Command bar -------------------------------------------------- */
  header {
    padding: var(--sp-3) var(--sp-6); background: var(--surface-1);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: var(--sp-4); flex-shrink: 0;
  }
  header h1 {
    font-size: 15px; margin: 0; color: var(--text-primary); font-weight: 700;
    letter-spacing: .02em; display: flex; align-items: center; gap: var(--sp-2);
  }
  header h1::before {
    content: ""; width: 8px; height: 8px; border-radius: 50%;
    background: var(--series-blue);
    box-shadow: 0 0 10px color-mix(in srgb, var(--series-blue) 70%, transparent);
  }
  .spacer { flex: 1; }
  .round-controls { display: flex; gap: var(--sp-2); }
  header button {
    background: var(--surface-2); color: var(--text-secondary);
    border: 1px solid var(--border); border-radius: var(--radius-sm);
    padding: 7px 14px; font: inherit; font-size: 12px; font-weight: 600; cursor: pointer;
    transition: background .16s ease, color .16s ease, border-color .16s ease;
  }
  header button:hover { color: var(--text-primary); background: var(--surface-3); border-color: var(--border-strong); }
  header button.ctrl-go:hover    { border-color: color-mix(in srgb, var(--status-good) 55%, transparent); color: var(--status-good); }
  header button.ctrl-stop:hover  { border-color: color-mix(in srgb, var(--status-critical) 55%, transparent); color: var(--status-critical); }

  .badge {
    padding: 5px 12px; border-radius: 999px; font-size: 11px; font-weight: 700;
    letter-spacing: .06em; text-transform: uppercase;
    display: inline-flex; align-items: center; gap: 7px; border: 1px solid transparent;
  }
  .badge .dot { width: 7px; height: 7px; border-radius: 50%; }
  .badge.go       { color: var(--status-good);     background: color-mix(in srgb, var(--status-good) 14%, transparent);     border-color: color-mix(in srgb, var(--status-good) 40%, transparent); }
  .badge.go .dot  { background: var(--status-good); box-shadow: 0 0 0 3px color-mix(in srgb, var(--status-good) 25%, transparent); animation: pulse 2s ease-in-out infinite; }
  .badge.stop     { color: var(--status-critical); background: color-mix(in srgb, var(--status-critical) 14%, transparent); border-color: color-mix(in srgb, var(--status-critical) 40%, transparent); }
  .badge.stop .dot{ background: var(--status-critical); }
  .badge.idle     { color: var(--status-muted); background: color-mix(in srgb, var(--status-muted) 12%, transparent); border-color: var(--border); }
  .badge.idle .dot{ background: var(--status-muted); }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .45; } }

  /* --- Result banner: a prominent callout, not a text line ---------- */
  #result-banner {
    padding: var(--sp-3) var(--sp-6); font-size: 13px; font-weight: 600;
    background: var(--surface-2); border-bottom: 1px solid var(--border);
    border-left: 4px solid var(--status-muted);
    display: flex; align-items: center; gap: var(--sp-3);
  }
  #result-banner::before {
    content: "LAST ROUND"; font-family: var(--font-ui);
    font-size: 10px; font-weight: 700; letter-spacing: .08em;
    color: var(--muted); padding: 2px 8px; border-radius: 999px;
    background: var(--page-plane); border: 1px solid var(--border); flex-shrink: 0;
  }
  #result-banner.hidden { display: none; }
  #result-banner.good     { color: var(--status-good);     border-left-color: var(--status-good); }
  #result-banner.critical { color: var(--status-critical); border-left-color: var(--status-critical); }
  #result-banner.muted    { color: var(--text-secondary);  border-left-color: var(--status-muted); }

  #found-it-toast {
    position: fixed; bottom: var(--sp-5); right: var(--sp-5); padding: 13px 20px;
    border-radius: var(--radius); color: #fff; font-size: 13px; font-weight: 600; z-index: 100;
    box-shadow: 0 8px 28px rgba(0,0,0,.5); border: 1px solid rgba(255,255,255,.14);
  }
  #found-it-toast.hidden { display: none; }
  #found-it-toast.ok   { background: var(--status-good);     box-shadow: 0 8px 28px color-mix(in srgb, var(--status-good) 35%, transparent); }
  #found-it-toast.fail { background: var(--status-critical); box-shadow: 0 8px 28px color-mix(in srgb, var(--status-critical) 35%, transparent); }

  /* --- Tabs --------------------------------------------------------- */
  nav.tabs { display: flex; gap: 2px; padding: 0 var(--sp-5); background: var(--surface-1); border-bottom: 1px solid var(--border); flex-shrink: 0; }
  nav.tabs button {
    appearance: none; background: none; border: none; cursor: pointer;
    color: var(--muted); font: inherit; font-size: 13px; font-weight: 600;
    padding: 13px 16px 11px; display: flex; align-items: center; gap: 8px;
    border-bottom: 2px solid transparent; letter-spacing: .01em;
    transition: color .16s ease, background .16s ease;
  }
  nav.tabs button .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  nav.tabs button:hover { color: var(--text-secondary); background: rgba(255,255,255,0.03); }
  nav.tabs button.active { color: var(--text-primary); }
  nav.tabs button[data-team="red"].active      { border-bottom-color: var(--series-red); }
  nav.tabs button[data-team="blue"].active     { border-bottom-color: var(--series-blue); }
  nav.tabs button[data-team="white"].active    { border-bottom-color: var(--series-white); }
  nav.tabs button[data-team="advisor"].active  { border-bottom-color: var(--series-purple); }
  nav.tabs button[data-team="combined"].active { border-bottom-color: var(--text-primary); }
  .dot.red    { background: var(--series-red); }
  .dot.blue   { background: var(--series-blue); }
  .dot.white  { background: var(--series-white); }
  .dot.purple { background: var(--series-purple); }
  .dot.combined { background: conic-gradient(var(--series-red), var(--series-blue), var(--series-white), var(--series-red)); }

  /* --- Panels ------------------------------------------------------- */
  main { flex: 1; min-height: 0; position: relative; }
  .panel { position: absolute; inset: 0; overflow-y: auto; padding: var(--sp-5) var(--sp-6); display: none; }
  .panel.active { display: block; }
  .empty { color: var(--muted); font-size: 13px; padding: var(--sp-6) 0; text-align: center; }

  /* Section label above a feed */
  .feed-title, .card-title {
    font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em;
    color: var(--muted); margin: 0 0 var(--sp-3); display: flex; align-items: center; gap: var(--sp-2);
  }
  .feed-title { margin-top: var(--sp-5); padding-bottom: var(--sp-2); border-bottom: 1px solid var(--gridline); }

  /* Cards wrap the interactive controls so they read as a distinct
     "operator console" register above the live wire. */
  .panel-grid { display: grid; grid-template-columns: minmax(320px, 480px) minmax(280px, 1fr); gap: var(--sp-4); align-items: start; }
  @media (max-width: 860px) { .panel-grid { grid-template-columns: 1fr; } }
  .card {
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: var(--radius); padding: var(--sp-4);
  }

  form.action-form { display: flex; flex-direction: column; gap: var(--sp-3); }
  form.action-form label { display: flex; flex-direction: column; gap: 5px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  form.action-form select, form.action-form input {
    background: var(--surface-2); color: var(--text-primary); border: 1px solid var(--border);
    border-radius: var(--radius-sm); padding: 9px 11px; font: inherit; font-size: 13px;
    transition: border-color .16s ease;
  }
  form.action-form select:hover, form.action-form input:hover { border-color: var(--border-strong); }
  form.action-form button {
    align-self: flex-start; margin-top: var(--sp-1);
    background: var(--surface-3); color: var(--text-primary);
    border: 1px solid var(--border-strong); border-radius: var(--radius-sm); padding: 9px 20px; font: inherit;
    font-size: 13px; font-weight: 600; cursor: pointer;
    transition: background .16s ease, border-color .16s ease;
  }
  form.action-form button:hover { background: color-mix(in srgb, var(--series-blue) 22%, var(--surface-3)); border-color: var(--series-blue); }
  #advisor-answer {
    white-space: pre-wrap; margin-top: var(--sp-4); max-width: 760px; font-size: 13px; line-height: 1.6;
    font-family: var(--font-mono); color: var(--text-secondary);
  }
  #advisor-answer:not(:empty) { padding: var(--sp-4); background: var(--surface-1); border: 1px solid var(--border); border-radius: var(--radius); }

  /* --- Attack-frequency view (client-side tally of red actions) ----- */
  .freq { display: flex; flex-direction: column; gap: var(--sp-2); }
  .freq-row { display: grid; grid-template-columns: 128px 1fr 30px; align-items: center; gap: var(--sp-3); font-family: var(--font-mono); font-size: 12px; }
  .freq-label { color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .freq-track { height: 8px; background: var(--surface-3); border-radius: 999px; overflow: hidden; }
  .freq-fill { display: block; height: 100%; background: var(--series-red); border-radius: 999px; transition: width .3s ease; }
  .freq-count { color: var(--text-primary); font-weight: 700; text-align: right; font-variant-numeric: tabular-nums; }

  .combined-controls { margin-bottom: var(--sp-4); display: flex; align-items: center; gap: var(--sp-2); font-size: 12px; }
  .combined-controls label { color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: .04em; font-size: 11px; }
  .combined-controls select {
    background: var(--surface-2); color: var(--text-primary); border: 1px solid var(--border);
    border-radius: var(--radius-sm); padding: 7px 10px; font: inherit; font-size: 12px;
  }

  /* --- Event feed (the wire) ---------------------------------------- */
  .ev { padding: var(--sp-3) 0; border-bottom: 1px solid var(--gridline); max-width: 940px; font-family: var(--font-mono); }
  .ev .meta { display: flex; align-items: baseline; gap: 10px; margin-bottom: 5px; flex-wrap: wrap; }
  .ev .phase {
    font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em;
    color: var(--muted);
  }
  .ev .phase.good { color: var(--status-good); }
  .ev .phase.critical { color: var(--status-critical); }
  .ev .time { color: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
  .ev .round-tag { color: var(--muted); font-size: 11px; padding: 1px 6px; border: 1px solid var(--border); border-radius: 999px; }
  .ev .actor-tag { color: var(--series-white); font-size: 11px; font-weight: 700; }
  .ev .content { white-space: pre-wrap; word-break: break-word; color: var(--text-secondary); font-size: 12.5px; line-height: 1.55; }
  .ev.heartbeat { padding: 4px 0; opacity: .5; }
  .ev.heartbeat .content { font-size: 11px; }
  .ev.narrative .content { color: var(--text-primary); }

  /* Team-tagged rows (combined ledger) get a colored rail + tinted well */
  .ev.team-red   { border-left: 3px solid var(--series-red);   padding-left: var(--sp-3); background: linear-gradient(90deg, color-mix(in srgb, var(--series-red) 7%, transparent), transparent 60%); }
  .ev.team-blue  { border-left: 3px solid var(--series-blue);  padding-left: var(--sp-3); background: linear-gradient(90deg, color-mix(in srgb, var(--series-blue) 7%, transparent), transparent 60%); }
  .ev.team-white { border-left: 3px solid var(--series-white); padding-left: var(--sp-3); background: linear-gradient(90deg, color-mix(in srgb, var(--series-white) 7%, transparent), transparent 60%); }
  .chip {
    font-size: 10px; font-weight: 700; letter-spacing: .05em; padding: 2px 7px; border-radius: 3px;
    color: var(--page-plane);
  }
  .chip-red   { background: var(--series-red); }
  .chip-blue  { background: var(--series-blue); }
  .chip-white { background: var(--series-white); }
</style>
</head>
<body>
<header>
  <h1>Purple Team Live View</h1>
  <div class="spacer"></div>
  <div class="round-controls">
    <button id="btn-start" class="ctrl-go">Clear Flags</button>
    <button id="btn-stop" class="ctrl-stop">Stop Round</button>
    <button id="btn-restart">Restart Round</button>
  </div>
  <span id="round-badge" class="badge idle"><span class="dot"></span>loading&hellip;</span>
</header>
<div id="result-banner" class="hidden"></div>
<div id="found-it-toast" class="hidden"></div>
<nav class="tabs">
  <button data-team="red" class="active"><span class="dot red"></span>Red Team</button>
  <button data-team="blue"><span class="dot blue"></span>Blue Team</button>
  <button data-team="white"><span class="dot white"></span>White Team (Referee)</button>
  <button data-team="advisor"><span class="dot purple"></span>Purple Advisor</button>
  <button data-team="combined"><span class="dot combined"></span>Combined Ledger</button>
</nav>
<main>
  <div id="panel-red" class="panel active">
    <div class="panel-grid">
      <section class="card">
        <h2 class="card-title"><span class="dot red"></span>Fire an attack</h2>
        <form class="action-form" id="red-template-form">
          <label>Attack template
            <select name="template_name">
              <option value="sqli">SQL injection (/search)</option>
              <option value="bruteforce">Login bruteforce (/admin/login)</option>
              <option value="idor">IDOR (/documents/1)</option>
              <option value="command_injection">Command injection (/admin/diagnostics)</option>
            </select>
          </label>
          <button type="submit">Fire</button>
        </form>
      </section>
      <section class="card">
        <h2 class="card-title">Attack frequency</h2>
        <div id="red-frequency" class="freq"></div>
      </section>
    </div>
    <h3 class="feed-title">Event feed</h3>
    <div id="events-red"></div>
  </div>
  <div id="panel-blue" class="panel">
    <section class="card" style="max-width: 480px;">
      <h2 class="card-title"><span class="dot blue"></span>Take a defensive action</h2>
      <form class="action-form" id="blue-action-form">
        <label>Action
          <select name="action">
            <option value="lock_account">Lock account (username)</option>
            <option value="kill_session">Kill session (user_id)</option>
            <option value="block_ip">Block IP (source_ip)</option>
          </select>
        </label>
        <label>Target value <input type="text" name="target" required></label>
        <button type="submit">Defend</button>
      </form>
    </section>
    <h3 class="feed-title">Event feed</h3>
    <div id="events-blue"></div>
  </div>
  <div id="panel-white" class="panel">
    <h3 class="feed-title" style="margin-top: 0;"><span class="dot white"></span>Referee assessments</h3>
    <div id="events-white"></div>
  </div>
  <div id="panel-advisor" class="panel">
    <section class="card" style="max-width: 480px;">
      <h2 class="card-title">Purple Advisor</h2>
      <form class="action-form" id="advisor-form">
        <label>Ask the purple-team advisor
          <input type="text" name="question" required placeholder="What should blue do right now?">
        </label>
        <button type="submit">Ask</button>
      </form>
    </section>
    <div id="advisor-answer"></div>
  </div>
  <div id="panel-combined" class="panel">
    <div class="combined-controls">
      <label for="combined-round-filter">Round</label>
      <select id="combined-round-filter"><option value="">All rounds</option></select>
    </div>
    <div id="events-combined"></div>
  </div>
</main>
<script>
const GOOD_PHASES = new Set(['run_complete', 'go_signal']);
const CRITICAL_PHASES = new Set(['ollama_error', 'stop_signal', 'error']);
const HEARTBEAT_PHASES = new Set(['heartbeat']);

// Friendly names for the known red attack templates (dashboard/actions.py
// RED_TEMPLATES). Keyed by request.path -- the identifier every red
// http_request event carries, manual or autonomous. Unknown paths (an
// autonomous agent can hit anything) fall back to the raw path.
const ATTACK_LABELS = {
  '/search': 'SQL injection',
  '/admin/login': 'Login bruteforce',
  '/documents/1': 'IDOR',
  '/admin/diagnostics': 'Command injection',
};

// Phases that carry no free-text content field -- render a fixed, human
// sentence instead of falling through to a raw JSON dump of whatever's left.
const NARRATIVE = {
  go_signal: () => 'Referee saw blue come alive and released go.flag -- red and blue are now live.',
  round_start: () => 'Blue acknowledged the go signal and started its detection loop.',
  round_stop_acknowledged: () => 'Agent acknowledged the stop signal and exited.',
  round_over: (e) => {
    const secs = Math.round(e.elapsed_seconds || 0);
    const who = { blue: 'Blue won', red: 'Red won', budget_expired: 'Round timed out (no decisive winner)' }[e.outcome] || e.outcome;
    return `Round over after ${secs}s -- ${who}.`;
  },
};

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
// All timestamps are logged in UTC (correct -- keeps every container's
// clock comparable regardless of host timezone or DST). Convert to the
// viewer's local time only here, at render time, using the browser's own
// timezone -- no server-side timezone config needed.
function localTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}
// Agent reasoning content often arrives as a markdown-fenced JSON blob
// straight from the LLM's own output style -- strip the fence and
// pretty-print the JSON if it parses, so the panel reads as text instead
// of a wall of backticks and braces. Falls back to the raw string
// untouched if it isn't fenced JSON.
function unwrapFencedJson(s) {
  const m = /^```(?:json)?\s*\\n([\s\S]*?)\\n?```\s*$/.exec(String(s).trim());
  if (!m) return s;
  try { return JSON.stringify(JSON.parse(m[1]), null, 2); } catch { return m[1]; }
}
// Manual actions (dashboard/actions.py) log a `response` alongside the
// action name -- {status_code, body} on a completed request, or {error}
// when the target couldn't be reached at all. Neither is optional: without
// reading it, "block_ip" renders identically whether the block landed or
// the target was unreachable. Returns '' + failed:false when there's
// nothing to report (e.g. non-action events with no response field).
function actionOutcome(e) {
  if (!e.response) return { text: '', failed: false };
  if (e.response.error) return { text: `error: ${e.response.error}`, failed: true };
  if (e.response.status_code !== undefined) {
    const ok = e.response.status_code >= 200 && e.response.status_code < 300;
    return { text: `status ${e.response.status_code}`, failed: !ok };
  }
  return { text: '', failed: false };
}
// `team` is optional -- when set (combined-ledger tab) adds a colored left
// border and a RED/BLUE/WHITE chip so a merged feed stays scannable at a
// glance. Per-team tabs omit it since the tab itself already says who.
function renderEvent(e, team) {
  const teamClass = team ? ` team-${team}` : '';
  const chip = team ? `<span class="chip chip-${team}">${team.toUpperCase()}</span>` : '';
  const roundTag = (team && e.__round !== undefined) ? `<span class="round-tag">R${e.__round}</span>` : '';
  // Manual (human-fired) actions are stamped actor: "human" server-side
  // (dashboard/actions.py) to distinguish them from autonomous agent
  // events, which carry no actor field at all.
  const actorTag = e.actor === 'human' ? '<span class="actor-tag">[human]</span>' : '';
  if (e.__collapsed) {
    return `<div class="ev heartbeat${teamClass}">
      <div class="meta">${chip}<span class="phase">heartbeat</span><span class="time">alive, idle -- ${e.count} beats, last at ${esc(localTime(e.timestamp))}</span>${roundTag}</div>
    </div>`;
  }
  const phase = e.phase || 'event';
  const outcome = actionOutcome(e);
  const cls = outcome.failed ? 'critical' : GOOD_PHASES.has(phase) ? 'good' : CRITICAL_PHASES.has(phase) ? 'critical' : '';
  const narrator = NARRATIVE[phase];
  let content = e.content || e.reasoning || e.error;
  if (content) content = unwrapFencedJson(content);
  // e.action (e.g. "block_ip") is always truthy on its own -- if it were
  // checked before outcome, a failed escalation would render identically
  // to a successful one. Fold the outcome into the same line instead.
  if (!content && e.action) {
    content = outcome.text ? `${e.action}${e.target ? ' -> ' + e.target : ''} (${outcome.text})` : e.action;
  }
  let isNarrative = false;
  if (!content && narrator) { content = narrator(e); isNarrative = true; }
  if (!content) {
    const extra = Object.fromEntries(Object.entries(e).filter(([k]) => !['side','timestamp','phase','__team','__round'].includes(k)));
    content = Object.keys(extra).length ? JSON.stringify(extra) : '';
  }
  const isHeartbeat = HEARTBEAT_PHASES.has(phase);
  return `<div class="ev${isHeartbeat ? ' heartbeat' : ''}${isNarrative ? ' narrative' : ''}${teamClass}">
    <div class="meta">${chip}<span class="phase ${cls}">${esc(phase)}</span>${actorTag}<span class="time">${esc(localTime(e.timestamp))}</span>${roundTag}</div>
    ${content ? `<div class="content">${esc(content).slice(0,2000)}</div>` : ''}
  </div>`;
}
function collapseHeartbeats(list) {
  // Blue heartbeats every poll (5s) whether or not there's anything to react
  // to -- a long quiet stretch is dozens of identical rows that bury the one
  // reasoning entry that matters. Collapse runs of 3+ consecutive heartbeats
  // into a single "alive, idle" line; leave isolated ones alone.
  const out = [];
  let run = [];
  const flush = () => {
    if (run.length >= 3) {
      out.push({ __collapsed: true, count: run.length, timestamp: run[run.length - 1].timestamp });
    } else {
      out.push(...run);
    }
    run = [];
  };
  for (const e of list) {
    if (e.phase === 'heartbeat') { run.push(e); }
    else { flush(); out.push(e); }
  }
  flush();
  return out;
}
function renderList(el, list, emptyMsg) {
  if (!list.length) { el.innerHTML = `<div class="empty">${emptyMsg}</div>`; return; }
  // Collapse runs on the original chronological order, then reverse for
  // display -- newest first, so the most recent activity is always visible
  // without scrolling.
  el.innerHTML = collapseHeartbeats(list).reverse().map(e => renderEvent(e)).join('');
}
// Attack-frequency tally: count red http_request events by request.path
// (the template/route identifier both manual and autonomous red actions
// carry) and render sorted, most-fired first, as plain CSS bars. Pure
// client-side aggregation over the same red_events array the feed uses --
// no backend change, same pattern as the combined ledger / round filter.
function renderFrequency(list) {
  const el = document.getElementById('red-frequency');
  const counts = {};
  for (const e of list || []) {
    const path = e.request && e.request.path;
    if (!path) continue;
    counts[path] = (counts[path] || 0) + 1;
  }
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!rows.length) { el.innerHTML = '<div class="empty">No attacks fired yet.</div>'; return; }
  const max = rows[0][1];
  el.innerHTML = rows.map(([path, n]) => {
    const label = ATTACK_LABELS[path] || path;
    const pct = Math.max(6, Math.round(n / max * 100));
    return `<div class="freq-row">
      <span class="freq-label" title="${esc(path)}">${esc(label)}</span>
      <span class="freq-track"><span class="freq-fill" style="width:${pct}%"></span></span>
      <span class="freq-count">${n}</span>
    </div>`;
  }).join('');
}
function renderResultBanner(result) {
  const banner = document.getElementById('result-banner');
  if (!result) { banner.className = 'hidden'; return; }
  const who = { blue: 'Blue won', red: 'Red won', budget_expired: 'Round timed out' }[result.outcome] || result.outcome;
  banner.textContent = `${who} (${Math.round(result.elapsed_seconds || 0)}s)`;
  banner.className = result.outcome === 'blue' ? 'good' : result.outcome === 'red' ? 'critical' : 'muted';
}

// -- Combined ledger: merge red_events + blue_events + assessments client
// side (no backend change -- /api/state already returns the three arrays
// separately). Each side is collapsed independently first (same heartbeat
// treatment as the per-team tabs), tagged with its team, merged, sorted
// chronologically, then walked once to derive a round number from the
// go_signal/round_over phase markers (there's no round_number field in the
// event schema -- this is purely a client-side derivation). Reversed for
// display only at render time, same collapse-then-reverse pattern as
// renderList.
function buildCombined(data) {
  const red = collapseHeartbeats(data.red_events || []).map(e => ({ ...e, __team: e.side || 'red' }));
  const blue = collapseHeartbeats(data.blue_events || []).map(e => ({ ...e, __team: e.side || 'blue' }));
  const white = collapseHeartbeats(data.assessments || []).map(e => ({ ...e, __team: e.side || 'white' }));
  const merged = [...red, ...blue, ...white];
  merged.sort((a, b) => new Date(a.timestamp || 0) - new Date(b.timestamp || 0));

  // Round 0 = everything before the first go_signal (setup/pre-round).
  // The counter only increments on go_signal, not round_over -- a timed-out
  // or restarted round can in principle produce back-to-back go_signals
  // without a clean round_over between them, so don't assume alternation.
  let round = 0;
  for (const e of merged) {
    if (e.phase === 'go_signal') round += 1;
    e.__round = round;
  }
  return merged;
}
let lastCombinedChron = [];
function renderCombinedPanel() {
  const container = document.getElementById('events-combined');
  const filterSel = document.getElementById('combined-round-filter');
  const rounds = [...new Set(lastCombinedChron.map(e => e.__round))].sort((a, b) => a - b);
  const prevValue = filterSel.value;
  filterSel.innerHTML = '<option value="">All rounds</option>' +
    rounds.map(r => `<option value="${r}">Round ${r}</option>`).join('');
  filterSel.value = prevValue; // falls back to "All rounds" if that round is gone

  let list = lastCombinedChron;
  if (filterSel.value !== '') {
    const want = Number(filterSel.value);
    list = list.filter(e => e.__round === want);
  }
  if (!list.length) { container.innerHTML = '<div class="empty">No events yet.</div>'; return; }
  container.innerHTML = list.slice().reverse().map(e => renderEvent(e, e.__team)).join('');
}
document.getElementById('combined-round-filter').addEventListener('change', renderCombinedPanel);

for (const btn of document.querySelectorAll('nav.tabs button')) {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav.tabs button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.team).classList.add('active');
  });
}

// HTTP Basic Auth is browser-native: once the browser prompts and the
// operator enters credentials for this origin, it caches and resends them
// automatically on every fetch() below. No Authorization header handling
// needed here.
document.getElementById('btn-start').addEventListener('click', () => fetch('/api/round/start', { method: 'POST' }).then(tick));
document.getElementById('btn-stop').addEventListener('click', () => fetch('/api/round/stop', { method: 'POST' }).then(tick));
document.getElementById('btn-restart').addEventListener('click', () => fetch('/api/round/restart', { method: 'POST' }).then(tick));

function showToast(message, ok) {
  const toast = document.getElementById('found-it-toast');
  toast.textContent = message;
  toast.className = ok ? 'ok' : 'fail';
  setTimeout(() => { toast.className = 'hidden'; }, 4000);
}

document.getElementById('red-template-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const template_name = new FormData(ev.target).get('template_name');
  const res = await fetch('/api/red-action', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ template_name }),
  });
  const data = await res.json();
  if (data.found_it) showToast('Found it! Your red action reproduced a win-condition result.', true);
  else if (data.error) showToast(`Red action failed: ${data.error}`, false);
  tick();
});
document.getElementById('blue-action-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const res = await fetch('/api/blue-action', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: fd.get('action'), target: fd.get('target') }),
  });
  const data = await res.json();
  if (data.found_it) showToast('Found it! Your blue action reproduced a win-condition result.', true);
  else if (data.error) showToast(`Blue action failed: ${data.error}`, false);
  tick();
});
document.getElementById('advisor-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const question = new FormData(ev.target).get('question');
  const res = await fetch('/api/advisor', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question }),
  });
  const data = await res.json();
  document.getElementById('advisor-answer').textContent = data.answer || data.error || '';
});

async function tick() {
  try {
    const res = await fetch('/api/state');
    const data = await res.json();
    const badge = document.getElementById('round-badge');
    if (data.round.stop) { badge.innerHTML = '<span class="dot"></span>STOPPED'; badge.className = 'badge stop'; }
    else if (data.round.go) { badge.innerHTML = '<span class="dot"></span>ROUND LIVE'; badge.className = 'badge go'; }
    else { badge.innerHTML = '<span class="dot"></span>IDLE'; badge.className = 'badge idle'; }

    renderResultBanner(data.latest_round_result);

    renderList(document.getElementById('events-red'), data.red_events, 'No red team activity yet.');
    renderList(document.getElementById('events-blue'), data.blue_events, 'No blue team activity yet.');
    renderList(document.getElementById('events-white'), data.assessments, 'No referee assessments yet.');
    renderFrequency(data.red_events);

    lastCombinedChron = buildCombined(data);
    renderCombinedPanel();
  } catch (err) {
    console.error(err);
  }
}
tick();
setInterval(tick, 2000);
</script>
</body>
</html>
"""
