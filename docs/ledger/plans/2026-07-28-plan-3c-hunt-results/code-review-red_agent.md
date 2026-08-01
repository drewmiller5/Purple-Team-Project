# Phase 1 Hunt -- Code Review: red_agent/

Scope: `red_agent/` only (config.py, loop.py, tools.py, http_tool.py,
ollama_client.py, state.py, main.py, tests/). K1 (no independent
heartbeat / free-rider on blue's go-signal), K2 (unguarded
`json.loads(args)` in tools.py), and K5 (no enforced recon-before-attack
gating) are already tracked in the findings ledger and are not
re-reported here.

| Severity | Summary | File:line | Suggested fix |
|---|---|---|---|
| HIGH | In `run()`, `response["message"]` is assigned inside the guarded `try` (`except (requests.RequestException, KeyError)`), but the following lines that call `.get(...)` on it -- `assistant_message.get("tool_calls")` and `assistant_message.get("content", "")` -- run **outside** that try/except. If Ollama returns a response whose `"message"` value is present but not a dict (e.g. `null`, a string, or a differently-shaped payload from a model/template change), the `"message"` key lookup itself succeeds (no `KeyError`), but `.get()` on the non-dict value raises an uncaught `AttributeError`. The same non-dict-value gap exists one layer down: `tools.py`'s `dispatch_tool_call` calls `call["function"].get("arguments", {})` (line 51), assuming `call["function"]` is always a dict; if a tool_calls entry has `"function"` as a string or other non-dict type, this also raises `AttributeError`, which is outside loop.py's `except (KeyError, TypeError)` around the dispatch call. Either case propagates all the way out of `run()`, and `main.py` has no top-level try/except, so the entire red-agent process dies for the round -- no `ollama_error`/`round_stop_acknowledged` event is logged to mark why. Existing tests (`test_run_handles_ollama_key_error_gracefully`, `test_run_handles_malformed_tool_call_missing_function_key`) only cover the key-missing-entirely case, not present-but-wrong-type. | `red_agent/loop.py:79,85,87` (assignment inside try, `.get()` calls outside); `red_agent/loop.py:91-94` (except clause omits `AttributeError`); `red_agent/tools.py:51` (`call["function"].get(...)`); `red_agent/main.py:5-7` (no top-level guard) | Validate `isinstance(assistant_message, dict)` (and `isinstance(call.get("function"), dict)` in tools.py) before calling `.get()`, treating a bad shape as a loggable `ollama_error`/malformed-call result instead of letting `AttributeError` propagate. Add `AttributeError` to the relevant except clauses as defense-in-depth. |
| MEDIUM | `loop.py`'s tool-dispatch try/except only catches `(KeyError, TypeError)` around `dispatch_tool_call(...)` (line 91-94), on the assumption that failures are argument-shape problems. But the `record_finding` branch of `dispatch_tool_call` calls `state.record_finding(...)` (`tools.py:77`), which calls `shared.memory.append_memory_entry` -> `save_memory`, which does raw file I/O (`open()`, `os.fsync`, `os.replace`) that can raise `OSError`/`PermissionError` (disk full, read-only filesystem, a locked file on Windows). Likewise every `state.log_event(...)` call (used after nearly every tool dispatch, and directly in `loop.py` for `round_stop_acknowledged`/`run_complete`) goes through `shared.event_log.log_event`'s `os.open`/`os.write`, which has the same exposure. Neither is `KeyError` nor `TypeError`, so an OS-level failure in either path is not caught anywhere in the call chain and terminates `run()` (and the whole container, since `main.py` has no top-level exception guard) -- unlike the network-error path for `ollama.chat()`, which is deliberately handled and tested. No test simulates a filesystem failure during `record_finding`/`log_event` to confirm current behavior. | `red_agent/loop.py:91-94`; `red_agent/tools.py:67,77`; `red_agent/state.py:12,16`; `shared/memory.py:30-46`; `shared/event_log.py:15-19` | Broaden the tool-dispatch except clause (or wrap the state-mutation calls specifically) to catch `OSError` and degrade to a logged/skipped tool result rather than crashing the round, matching the resilience already implemented for the Ollama HTTP path. |
| MEDIUM | `run()` calls `state.recall_summary()` (line 62) with no try/except, before the go-flag wait even happens. `recall_summary()` (`state.py:19-27`) calls `shared.memory.load_memory`, which explicitly raises `ValueError` when the memory file's JSON is corrupt (`shared/memory.py:24-27`, with a message noting the file "appears corrupt" -- i.e. the module author anticipated this exact failure and gave it a distinguishable type, but no caller handles it). If `red_memory.json` is ever corrupted (partial write from a killed process, disk issue, manual edit, cross-process interference under Windows where `os.replace` semantics differ), the very first call in `run()` raises an uncaught `ValueError` and the red agent crashes before doing anything for the round -- not even the go/stop flag check runs. `test_state.py` and `test_loop.py` only exercise valid/empty memory files, so this path has no coverage. | `red_agent/loop.py:62`; `red_agent/state.py:19-27`; `shared/memory.py:17-27` | Wrap `recall_summary()`'s `load_memory` call in a try/except for `ValueError`, log the corruption as an event, and continue with an empty history rather than crashing the whole run. |
| LOW | Tool argument values are never validated against the types declared in `TOOL_SCHEMAS`. The `record_finding` branch (`tools.py:70-77`) accepts whatever JSON type the model supplies for `category`/`detail`/`success` (e.g. `success` as a string, number, or nested object instead of the declared `boolean`) and persists it as-is via `state.record_finding` -> `append_memory_entry`, with no coercion or rejection. This can produce misleading history entries fed back to the model in a later run's `recall_past_findings` (e.g. `(success=None)` or `(success='maybe')` instead of a clean `True`/`False`), silently, with no error surfaced anywhere. | `red_agent/tools.py:70-78` | Validate/coerce argument types (at least `success` to `bool`) before recording, or reject with the same clean-error pattern already used for missing required keys. |

## Notes on things checked but NOT flagged

- `ollama_client.py`'s `resp.json()` decode-error path: with the pinned
  `requests>=2.31` (`requirements.txt:2`), `resp.json()` failures raise
  `requests.exceptions.JSONDecodeError`, which **is** a subclass of
  `requests.RequestException` in this requests version, so it's already
  caught by `loop.py`'s existing `except (requests.RequestException, KeyError)`.
  Confirmed not a gap (same reasoning as the sibling blue_agent review).
- `config.py`'s `int(os.environ.get("RED_MAX_ITERATIONS", "50"))` raising
  an uncaught `ValueError` at startup on a non-numeric env var: reviewed
  and looks intentional/acceptable (fail-fast at startup vs. a silent
  swallow at runtime), consistent with how the sibling blue_agent review
  treated the equivalent config-parsing pattern. Not flagged.
- `http_tool.py`'s own `except requests.RequestException` catch around
  the live request: correctly scoped, returns a clean `{"error": ...}`
  dict rather than propagating. No gap found.
- Per-`tool_calls`-entry dispatch in `loop.py` (lines 90-95): each call in
  a multi-call assistant turn is wrapped in its own try/except, so one
  malformed call in a batch doesn't prevent the others in the same turn
  from executing. Correctly scoped; no gap.
- `_wait_for_go`/`_stop_requested` polling and the lack of a red-owned
  heartbeat: this is K1's territory (free-rider on blue's heartbeat) and
  intentionally not re-reported here.
