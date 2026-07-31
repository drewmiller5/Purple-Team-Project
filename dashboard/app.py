import json
import os
from pathlib import Path

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

EVENT_LOG_PATH = os.environ.get("EVENT_LOG_PATH", "/app/shared_logs/events.jsonl")
REFEREE_LOG_PATH = os.environ.get("REFEREE_LOG_PATH", "/app/referee_logs/referee_assessments.jsonl")
REFEREE_STATE_DIR = os.environ.get("REFEREE_STATE_DIR", "/app/referee_state")
MAX_EVENTS = 300
MAX_ASSESSMENTS = 100


def read_jsonl_tail(path: str, limit: int) -> list:
    p = Path(path)
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


@app.route("/api/state")
def api_state():
    events = read_jsonl_tail(EVENT_LOG_PATH, MAX_EVENTS)
    assessments = read_jsonl_tail(REFEREE_LOG_PATH, MAX_ASSESSMENTS)
    go_flag = Path(REFEREE_STATE_DIR, "go.flag").exists()
    stop_flag = Path(REFEREE_STATE_DIR, "stop.flag").exists()

    red_events = [e for e in events if e.get("side") == "red"]
    blue_events = [e for e in events if e.get("side") == "blue"]

    return jsonify(
        {
            "round": {"go": go_flag, "stop": stop_flag},
            "red_events": red_events[-100:],
            "blue_events": blue_events[-100:],
            "assessments": assessments,
        }
    )


PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Purple Team Live View</title>
<style>
  :root {
    color-scheme: dark;
    --page-plane:     #0d0d0d;
    --surface-1:      #1a1a19;
    --surface-2:      #202020;
    --text-primary:   #ffffff;
    --text-secondary: #c3c2b7;
    --muted:          #898781;
    --gridline:       #2c2c2a;
    --border:         rgba(255,255,255,0.10);
    --series-red:     #e66767;
    --series-blue:    #3987e5;
    --series-white:   #c98500;
    --status-good:     #0ca30c;
    --status-critical: #d03b3b;
    --status-muted:    #898781;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--page-plane); color: var(--text-secondary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    margin: 0; height: 100vh; display: flex; flex-direction: column;
  }

  header {
    padding: 14px 24px; background: var(--surface-1); border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 16px; flex-shrink: 0;
  }
  header h1 { font-size: 15px; margin: 0; color: var(--text-primary); font-weight: 600; letter-spacing: .01em; }
  .spacer { flex: 1; }

  .badge {
    padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600;
    display: inline-flex; align-items: center; gap: 6px; border: 1px solid transparent;
  }
  .badge .dot { width: 7px; height: 7px; border-radius: 50%; }
  .badge.go       { color: var(--status-good);     background: color-mix(in srgb, var(--status-good) 14%, transparent);     border-color: color-mix(in srgb, var(--status-good) 40%, transparent); }
  .badge.go .dot  { background: var(--status-good); box-shadow: 0 0 0 3px color-mix(in srgb, var(--status-good) 25%, transparent); }
  .badge.stop     { color: var(--status-critical); background: color-mix(in srgb, var(--status-critical) 14%, transparent); border-color: color-mix(in srgb, var(--status-critical) 40%, transparent); }
  .badge.stop .dot{ background: var(--status-critical); }
  .badge.idle     { color: var(--status-muted); background: color-mix(in srgb, var(--status-muted) 12%, transparent); border-color: var(--border); }
  .badge.idle .dot{ background: var(--status-muted); }

  nav.tabs { display: flex; gap: 4px; padding: 0 20px; background: var(--surface-1); border-bottom: 1px solid var(--border); flex-shrink: 0; }
  nav.tabs button {
    appearance: none; background: none; border: none; cursor: pointer;
    color: var(--muted); font: inherit; font-size: 13px; font-weight: 600;
    padding: 12px 16px 11px; display: flex; align-items: center; gap: 8px;
    border-bottom: 2px solid transparent; letter-spacing: .01em;
  }
  nav.tabs button .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  nav.tabs button:hover { color: var(--text-secondary); background: rgba(255,255,255,0.03); }
  nav.tabs button.active { color: var(--text-primary); }
  nav.tabs button[data-team="red"].active   { border-bottom-color: var(--series-red); }
  nav.tabs button[data-team="blue"].active  { border-bottom-color: var(--series-blue); }
  nav.tabs button[data-team="white"].active { border-bottom-color: var(--series-white); }
  .dot.red   { background: var(--series-red); }
  .dot.blue  { background: var(--series-blue); }
  .dot.white { background: var(--series-white); }

  main { flex: 1; min-height: 0; position: relative; }
  .panel { position: absolute; inset: 0; overflow-y: auto; padding: 20px 28px; display: none; }
  .panel.active { display: block; }
  .empty { color: var(--muted); font-size: 13px; padding: 40px 0; text-align: center; }

  .ev { padding: 12px 0; border-bottom: 1px solid var(--gridline); max-width: 900px; }
  .ev:first-child { padding-top: 0; }
  .ev .meta { display: flex; align-items: baseline; gap: 10px; margin-bottom: 5px; }
  .ev .phase {
    font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em;
    color: var(--muted);
  }
  .ev .phase.good { color: var(--status-good); }
  .ev .phase.critical { color: var(--status-critical); }
  .ev .time { color: var(--muted); font-size: 11px; }
  .ev .content { white-space: pre-wrap; word-break: break-word; color: var(--text-secondary); font-size: 13px; line-height: 1.5; }
  .ev.heartbeat { padding: 3px 0; opacity: .55; }
  .ev.heartbeat .content { font-size: 11px; }
  .ev.narrative .content { color: var(--text-primary); }
</style>
</head>
<body>
<header>
  <h1>Purple Team Live View</h1>
  <div class="spacer"></div>
  <span id="round-badge" class="badge idle"><span class="dot"></span>loading&hellip;</span>
</header>
<nav class="tabs">
  <button data-team="red" class="active"><span class="dot red"></span>Red Team</button>
  <button data-team="blue"><span class="dot blue"></span>Blue Team</button>
  <button data-team="white"><span class="dot white"></span>White Team (Referee)</button>
</nav>
<main>
  <div id="panel-red" class="panel active"></div>
  <div id="panel-blue" class="panel"></div>
  <div id="panel-white" class="panel"></div>
</main>
<script>
const GOOD_PHASES = new Set(['run_complete', 'go_signal']);
const CRITICAL_PHASES = new Set(['ollama_error', 'stop_signal', 'error']);
const HEARTBEAT_PHASES = new Set(['heartbeat']);

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
function renderEvent(e) {
  if (e.__collapsed) {
    return `<div class="ev heartbeat">
      <div class="meta"><span class="phase">heartbeat</span><span class="time">alive, idle -- ${e.count} beats, last at ${esc(localTime(e.timestamp))}</span></div>
    </div>`;
  }
  const phase = e.phase || 'event';
  const cls = GOOD_PHASES.has(phase) ? 'good' : CRITICAL_PHASES.has(phase) ? 'critical' : '';
  const narrator = NARRATIVE[phase];
  let content = e.content || e.action || e.reasoning || e.error;
  if (content) content = unwrapFencedJson(content);
  let isNarrative = false;
  if (!content && narrator) { content = narrator(e); isNarrative = true; }
  if (!content) {
    const extra = Object.fromEntries(Object.entries(e).filter(([k]) => !['side','timestamp','phase'].includes(k)));
    content = Object.keys(extra).length ? JSON.stringify(extra) : '';
  }
  const isHeartbeat = HEARTBEAT_PHASES.has(phase);
  return `<div class="ev${isHeartbeat ? ' heartbeat' : ''}${isNarrative ? ' narrative' : ''}">
    <div class="meta"><span class="phase ${cls}">${esc(phase)}</span><span class="time">${esc(localTime(e.timestamp))}</span></div>
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
  const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  el.innerHTML = collapseHeartbeats(list).map(renderEvent).join('');
  if (atBottom) el.scrollTop = el.scrollHeight;
}

for (const btn of document.querySelectorAll('nav.tabs button')) {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav.tabs button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.team).classList.add('active');
  });
}

async function tick() {
  try {
    const res = await fetch('/api/state');
    const data = await res.json();
    const badge = document.getElementById('round-badge');
    if (data.round.stop) { badge.innerHTML = '<span class="dot"></span>STOPPED'; badge.className = 'badge stop'; }
    else if (data.round.go) { badge.innerHTML = '<span class="dot"></span>ROUND LIVE'; badge.className = 'badge go'; }
    else { badge.innerHTML = '<span class="dot"></span>IDLE'; badge.className = 'badge idle'; }

    renderList(document.getElementById('panel-red'), data.red_events, 'No red team activity yet.');
    renderList(document.getElementById('panel-blue'), data.blue_events, 'No blue team activity yet.');
    renderList(document.getElementById('panel-white'), data.assessments, 'No referee assessments yet.');
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


@app.route("/")
def index():
    return render_template_string(PAGE)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
