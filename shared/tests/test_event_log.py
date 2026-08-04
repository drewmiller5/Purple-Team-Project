import json

from shared.event_log import log_event, read_events


def test_read_events_returns_empty_list_when_missing(tmp_path):
    result = read_events(str(tmp_path / "missing.jsonl"))
    assert result == []


def test_log_event_appends_timestamped_line(tmp_path):
    path = str(tmp_path / "events.jsonl")
    event = log_event(path, {"side": "red", "action": "recon", "target": "/search"})
    assert event["side"] == "red"
    assert "timestamp" in event

    events = read_events(path)
    assert len(events) == 1
    assert events[0]["action"] == "recon"


def test_log_event_appends_multiple_events_in_order(tmp_path):
    path = str(tmp_path / "events.jsonl")
    log_event(path, {"side": "red", "action": "recon"})
    log_event(path, {"side": "blue", "action": "alert"})
    log_event(path, {"side": "red", "action": "exploit"})

    events = read_events(path)
    assert [e["action"] for e in events] == ["recon", "alert", "exploit"]


def test_read_events_skips_corrupt_line_and_keeps_valid_ones(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"side": "red", "action": "recon"}\n'
        '{"side": "blue", "action": "alert", "target": tru\n'
        '{"side": "red", "action": "exploit"}\n',
        encoding="utf-8",
    )

    events = read_events(str(path))
    assert [e["action"] for e in events] == ["recon", "exploit"]


def test_read_events_skips_non_dict_json_line_and_keeps_valid_ones(tmp_path):
    # H29: a syntactically-valid-but-non-dict JSON line (bare number, array,
    # string) must be skipped, not passed through to crash a caller's .get().
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"side": "red", "action": "recon"}\n'
        "42\n"
        '["not", "a", "dict"]\n'
        '"just a string"\n'
        '{"side": "red", "action": "exploit"}\n',
        encoding="utf-8",
    )

    events = read_events(str(path))
    assert [e["action"] for e in events] == ["recon", "exploit"]
    assert all(isinstance(e, dict) for e in events)


def test_read_events_skips_invalid_utf8_line_and_keeps_rest_of_file(tmp_path):
    # H30: one bad byte anywhere in the file must not raise an uncaught
    # UnicodeDecodeError and take down the read of the entire file.
    path = tmp_path / "events.jsonl"
    good1 = json.dumps({"side": "red", "action": "recon"}).encode("utf-8") + b"\n"
    bad = b"\xff\xfe not valid utf-8 or json\n"
    good2 = json.dumps({"side": "red", "action": "exploit"}).encode("utf-8") + b"\n"
    path.write_bytes(good1 + bad + good2)

    events = read_events(str(path))
    assert [e["action"] for e in events] == ["recon", "exploit"]
