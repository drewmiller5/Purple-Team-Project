import json
import re

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


def test_new_empty_memory_accepts_white_side():
    mem = new_empty_memory("white")
    assert mem["side"] == "white"
    assert mem["entries"] == []


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


def test_save_memory_leaves_no_temp_file_and_target_always_valid(tmp_path):
    path = tmp_path / "blue_memory.json"
    save_memory(str(path), new_empty_memory("blue"))

    # No stray temp file left behind in the directory after a successful save.
    leftovers = [p for p in tmp_path.iterdir() if p.name != path.name]
    assert leftovers == []

    # The target file is always fully-formed, valid JSON -- never truncated
    # or half-written, which is what a concurrent reader would need to see.
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["side"] == "blue"

    # Overwriting an existing file behaves the same way: no leftover temp
    # file, and the replaced target is still valid JSON.
    save_memory(str(path), new_empty_memory("blue"))
    leftovers = [p for p in tmp_path.iterdir() if p.name != path.name]
    assert leftovers == []
    with open(path, "r", encoding="utf-8") as f:
        json.load(f)


def test_load_memory_raises_clear_error_on_corrupt_json(tmp_path):
    path = tmp_path / "corrupt_memory.json"
    path.write_text("{not valid json", encoding="utf-8")
    path_pattern = re.escape(str(path))

    with pytest.raises(ValueError, match=path_pattern):
        load_memory(str(path))

    # append_memory_entry must surface the same clear error, not a raw
    # json.JSONDecodeError traceback.
    with pytest.raises(ValueError, match=path_pattern):
        append_memory_entry(str(path), {"side": "red", "note": "n/a"})


def test_load_memory_handles_invalid_utf8_bytes_without_crashing(tmp_path):
    # H30: a single invalid UTF-8 byte must not raise an uncaught
    # UnicodeDecodeError -- it should surface as the module's own typed
    # ValueError (same as any other corrupt-content case), not a crash.
    path = tmp_path / "bad_bytes.json"
    path.write_bytes(b"\xff\xfe not valid json even after decoding")
    path_pattern = re.escape(str(path))

    with pytest.raises(ValueError, match=path_pattern):
        load_memory(str(path))


def test_load_memory_raises_clear_error_on_wrong_shape(tmp_path):
    # H31: valid JSON but wrong shape (e.g. missing 'entries') must raise
    # the module's typed ValueError, not an unhandled KeyError/AttributeError.
    path = tmp_path / "wrong_shape.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    path_pattern = re.escape(str(path))

    with pytest.raises(ValueError, match=path_pattern):
        load_memory(str(path))

    with pytest.raises(ValueError, match=path_pattern):
        append_memory_entry(str(path), {"side": "red", "note": "n/a"})


def test_load_memory_raises_clear_error_on_empty_object(tmp_path):
    path = tmp_path / "empty_object.json"
    path.write_text("{}", encoding="utf-8")
    path_pattern = re.escape(str(path))

    with pytest.raises(ValueError, match=path_pattern):
        load_memory(str(path))
