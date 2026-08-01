# Code Review: shared/ (Plan 3C, Phase 1 Hunt)

Scope: shared/event_log.py, shared/memory.py, and their tests
(shared/tests/test_event_log.py, shared/tests/test_memory.py). Analysis
only -- no files modified.

## Context verified before reporting

- shared_logs/events.jsonl (env var EVENT_LOG_PATH) is a single Docker
  named volume (event-log in docker-compose.yml), mounted read-write
  into both red_agent and blue_agent containers and read-only into
  referee and purple_dashboard. This confirms a genuine two-writer,
  multi-reader concurrent-access scenario on the exact file log_event/
  read_events operate on -- not a hypothetical.
- memory_path (red/blue) is per-side and per-container (red-memory,
  blue-memory volumes) -- only one single-threaded loop (red_agent/loop.py,
  blue_agent/loop.py, no threading/asyncio anywhere in the repo) ever writes
  to a given memory file, so the read-modify-write pattern in
  append_memory_entry is not currently racing against itself.
- Parent-directory creation (log_event, save_memory) and the missing-file
  case (read_events, load_memory) are both handled correctly -- verified,
  not a finding.
- save_memory temp-file plus os.replace pattern correctly prevents partial
  reads of the memory file; confirmed by
  test_save_memory_leaves_no_temp_file_and_target_always_valid.

## Findings

MEDIUM | read_events crashes on any non-UTF-8 byte instead of gracefully skipping the line | shared/event_log.py:29
open(p, "r", encoding="utf-8") has no errors= handling, and the function
only catches json.JSONDecodeError (line 36). Any invalid UTF-8 byte
anywhere in the file raises an unhandled UnicodeDecodeError while
iterating the file (line 30), which is not caught by the existing
except json.JSONDecodeError -- so instead of the module's own stated
intent (skip corrupt lines, keep valid ones, per
test_read_events_skips_corrupt_line_and_keeps_valid_ones), a single bad
byte anywhere in the multi-writer shared log takes down read_events for
the entire file, not just one line. referee/loop.py:20 calls read_events
every poll iteration with no surrounding try/except, so this would
propagate straight out of the referee's decision loop. Currently latent
rather than proven-live: log_event uses json.dumps with the default
ensure_ascii=True, so its own writes are always pure ASCII and can't
produce this by themselves. It becomes reachable the moment any other
writer, a manual edit, or a future ensure_ascii=False change puts a
non-UTF-8 byte in the file. The same open(..., encoding="utf-8") gap
exists in load_memory (shared/memory.py:21), where a UnicodeDecodeError
would bypass the module's own documented "corrupt file -> clear
ValueError" contract (lines 24-27) and surface as a raw, undocumented
exception type instead.
Suggested fix: catch UnicodeDecodeError alongside JSONDecodeError in
read_events (or open with errors="replace" / read bytes and decode
per-line), and fold it into load_memory's existing ValueError wrapping.

MEDIUM | read_events does not validate that a parsed line is a JSON object | shared/event_log.py:34-37
json.loads(line) succeeding is the only condition checked. A line that is
syntactically valid JSON but not a dict (e.g. a bare number, string, or
list -- plausible from a torn/garbled-but-still-valid write, or any writer
that doesn't conform to the dict contract) is appended to the returned
list as-is. Every known consumer of read_events's output calls .get(...)
on each element (scripts/capture_checkpoint.py:17
_count_events_by_field, and referee/monitor.py's heartbeat/win-condition
checks), so a non-dict entry would raise an unhandled AttributeError
downstream rather than being skipped like other corruption. No test
exercises this case.
Suggested fix: in the parse path, verify isinstance(parsed, dict) and
continue (treat as corrupt) if not.

MEDIUM | append_memory_entry has no schema validation on loaded memory data | shared/memory.py:50-58
load_memory only guarantees the file contains some valid JSON -- it does
not validate the memory schema (side/created_at/entries shape). If the
file at path is valid JSON that doesn't match that shape (e.g. an empty
object, or an object with a side key but no entries key, or entries
present but not a list), data["entries"].append(entry) at line 58 raises
an unhandled KeyError/AttributeError instead of the clear, typed
ValueError the module already uses for JSON-decode corruption
(shared/memory.py:24-27). This is the same "no guard against
malformed-but-parseable input" class already tracked as ledger item K2,
just on the memory side. No test covers a schema-invalid-but-JSON-valid
memory file.
Suggested fix: validate isinstance(data, dict) and
isinstance(data.get("entries"), list) after load_memory returns (or
inside load_memory itself) and raise the same kind of clear ValueError
used for decode errors.

LOW | append_memory_entry load-modify-save cycle has no lock, relies entirely on an unenforced single-writer-per-path convention | shared/memory.py:49-60
There is no file lock or other mutual exclusion around
load_memory -> mutate -> save_memory. Verified not currently triggered:
each side's memory file is only ever written by that side's own
single-threaded loop, and docker-compose.yml gives red/blue distinct
memory volumes. But the function itself enforces nothing -- if that
single-writer assumption is ever violated (parallel tool-call handling,
a retry path, or a future misconfiguration sharing one memory volume
between containers), the loser of a concurrent read-modify-write pair
silently overwrites the winner's appended entry with no error and no
test would catch it (all existing tests are strictly sequential,
single-process). Flagging as a latent, undocumented assumption rather
than a live bug.

LOW | read_events drops corrupt lines with zero diagnostic | shared/event_log.py:36-37
except json.JSONDecodeError: continue -- no log line, counter, or any
signal that a line was discarded. shared_logs/events.jsonl is the sole
channel the referee polls to decide match state (go-signal, blue/red win
conditions per referee/loop.py), so a dropped/corrupted event disappears
with zero audit trail anywhere in the system. Combined with the
UnicodeDecodeError gap above, this means corruption in this file can
silently change round outcomes with no way to reconstruct after the fact.
Suggested fix: at minimum, log (stderr or a side counter) how many lines
were skipped so it is visible in container logs/dashboard.

LOW | No test coverage for concurrent multi-process writers to the same log file | shared/event_log.py:7-19, shared/tests/test_event_log.py
docker-compose.yml mounts the same event-log named volume read-write
into both red_agent and blue_agent, so log_event is called from two
independent OS processes against the same file in production. The
os.open(..., os.O_APPEND | os.O_CREAT | os.O_WRONLY, ...) plus single
os.write pattern is correct for this deployment (a Linux-backed Docker
named volume gives POSIX per-write atomicity against concurrent
appenders), but that correctness is untested and undocumented in the
module -- every existing test (shared/tests/test_event_log.py) exercises
only sequential, single-process appends. Worth flagging because the
property being relied on (O_APPEND atomicity) is a POSIX/filesystem-
specific guarantee, not a Python-level one, and is not the same on all
platforms (e.g. Windows' CRT implements O_APPEND as a separate seek+write,
not atomic), so running these same tests natively on a non-Linux dev
machine would not actually exercise the guarantee production depends on.
No code change required for the current Docker deployment; recommend an
explicit comment plus a multi-process test (e.g. a multiprocessing pool
hammering log_event on one path, asserting line count and no
interleaved/corrupted lines) to make the assumption explicit and
regression-proof.

LOW | log_event has no guard against non-JSON-serializable event values | shared/event_log.py:14
json.dumps(event) with no default= handler. Any caller passing a
non-serializable value in the event dict (an exception object, a set, a
datetime instead of an already-isoformat()'d string, etc.) causes an
unhandled TypeError to propagate out of log_event. All current call
sites happen to pass only primitives/strings (e.g. blue_agent/loop.py:88
stringifies exceptions with str(exc) before logging), so this is not
observed live, but it is an unguarded boundary of the same shape as the
json.loads gaps already tracked as ledger item K2, here on the serialize
side rather than the parse side. No test covers this input class.

## Test coverage gaps (consolidated)

- No test for read_events/load_memory encountering invalid UTF-8 bytes.
- No test for read_events returning a non-dict parsed value.
- No test for append_memory_entry/load_memory given schema-invalid-but-JSON-valid data (e.g. a missing entries key).
- No test for concurrent/multi-process writers to the same event log file.
- No test for log_event given a non-JSON-serializable value.

## Review Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0     | pass   |
| HIGH     | 0     | pass   |
| MEDIUM   | 3     | info   |
| LOW      | 3     | note   |

Verdict: No CRITICAL or HIGH issues found in shared/. All findings share a
root cause: the module's own stated contract (skip corrupt lines / raise a
clear error on corrupt files) is narrower than the actual space of
malformed-but-technically-valid inputs it can receive from a shared,
multi-writer file.
