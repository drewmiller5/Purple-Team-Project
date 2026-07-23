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
