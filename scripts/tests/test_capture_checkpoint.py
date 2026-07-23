import json

from scripts.capture_checkpoint import build_summary, capture_checkpoint


def test_build_summary_counts_correctly():
    red_memory = {"entries": [{"note": "a"}, {"note": "b"}]}
    blue_memory = {"entries": [{"note": "c"}]}
    events = [{"side": "red"}, {"side": "red"}, {"side": "blue"}]

    summary = build_summary(red_memory, blue_memory, events)

    assert summary["red_entry_count"] == 2
    assert summary["blue_entry_count"] == 1
    assert summary["total_events"] == 3
    assert summary["red_actions"] == 2
    assert summary["blue_actions"] == 1


def test_capture_checkpoint_v0_with_no_prior_data(tmp_path, monkeypatch):
    import scripts.capture_checkpoint as cc

    monkeypatch.setattr(cc, "RED_MEMORY_PATH", tmp_path / "memory" / "red_memory.json")
    monkeypatch.setattr(cc, "BLUE_MEMORY_PATH", tmp_path / "memory" / "blue_memory.json")
    monkeypatch.setattr(cc, "EVENT_LOG_PATH", tmp_path / "memory" / "events.jsonl")

    dest = capture_checkpoint("v0", archive_root=tmp_path / "archive")

    assert dest == tmp_path / "archive" / "v0"
    summary = json.loads((dest / "summary.json").read_text(encoding="utf-8"))
    assert summary["version"] == "v0"
    assert summary["red_entry_count"] == 0
    assert summary["blue_entry_count"] == 0
    assert summary["total_events"] == 0
    assert (dest / "red_memory.json").exists()
    assert (dest / "blue_memory.json").exists()
    assert (dest / "events.jsonl").exists()
