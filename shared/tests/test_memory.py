import pytest

from shared.memory import append_memory_entry, load_memory, new_empty_memory, save_memory


def test_new_empty_memory_schema():
    mem = new_empty_memory("red")
    assert mem["side"] == "red"
    assert mem["entries"] == []
    assert "created_at" in mem


def test_new_empty_memory_rejects_invalid_side():
    with pytest.raises(ValueError):
        new_empty_memory("green")


def test_load_memory_returns_none_when_missing(tmp_path):
    result = load_memory(str(tmp_path / "does_not_exist.json"))
    assert result is None


def test_save_and_load_roundtrip(tmp_path):
    path = str(tmp_path / "red_memory.json")
    save_memory(path, new_empty_memory("red"))
    loaded = load_memory(path)
    assert loaded["side"] == "red"
    assert loaded["entries"] == []


def test_append_memory_entry_creates_file_if_missing(tmp_path):
    path = str(tmp_path / "blue_memory.json")
    result = append_memory_entry(path, {"side": "blue", "note": "first observation"})
    assert result["side"] == "blue"
    assert len(result["entries"]) == 1
    assert result["entries"][0]["note"] == "first observation"
    assert "timestamp" in result["entries"][0]


def test_append_memory_entry_appends_to_existing(tmp_path):
    path = str(tmp_path / "red_memory.json")
    append_memory_entry(path, {"side": "red", "note": "attempt 1"})
    result = append_memory_entry(path, {"side": "red", "note": "attempt 2"})
    assert len(result["entries"]) == 2
    assert result["entries"][1]["note"] == "attempt 2"
