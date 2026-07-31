import json
from pathlib import Path

from referee.white_memory import KNOWN_FLAGS, prepare_round, select_next_flag


def test_select_next_flag_with_no_history_returns_first_known_flag():
    assert select_next_flag(white_memory=None, red_memory=None) == KNOWN_FLAGS[0]


def test_select_next_flag_skips_flag_red_already_found():
    red_memory = {
        "side": "red",
        "entries": [
            {"category": "SQL Injection", "detail": "...", "success": True},
        ],
    }
    result = select_next_flag(white_memory=None, red_memory=red_memory)
    assert result != "sqli-search"
    assert result in KNOWN_FLAGS


def test_select_next_flag_ignores_unsuccessful_red_findings():
    red_memory = {
        "side": "red",
        "entries": [
            {"category": "SQL Injection", "detail": "attempted, blocked", "success": False},
        ],
    }
    assert select_next_flag(white_memory=None, red_memory=red_memory) == "sqli-search"


def test_select_next_flag_skips_flags_white_already_assigned():
    white_memory = {
        "side": "white",
        "entries": [
            {"phase": "preparation", "assigned_flag": "sqli-search"},
            {"phase": "preparation", "assigned_flag": "bruteforce-admin-login"},
        ],
    }
    result = select_next_flag(white_memory=white_memory, red_memory=None)
    assert result not in ("sqli-search", "bruteforce-admin-login")
    assert result in KNOWN_FLAGS


def test_select_next_flag_round_robins_once_every_flag_has_been_used():
    white_memory = {
        "side": "white",
        "entries": [
            {"phase": "preparation", "assigned_flag": flag} for flag in KNOWN_FLAGS
        ]
        + [{"phase": "preparation", "assigned_flag": KNOWN_FLAGS[0]}],  # flag[0] assigned twice
    }
    result = select_next_flag(white_memory=white_memory, red_memory=None)
    # Every flag has 1 assignment except flag[0], which has 2 -- least-used wins.
    assert result != KNOWN_FLAGS[0]
    assert result in KNOWN_FLAGS


def test_prepare_round_appends_preparation_entry_and_returns_flag(tmp_path):
    white_path = str(tmp_path / "white_memory.json")
    red_path = str(tmp_path / "red_memory.json")
    Path(red_path).write_text(
        json.dumps(
            {
                "side": "red",
                "entries": [
                    {"category": "SQL Injection", "detail": "...", "success": True}
                ],
            }
        ),
        encoding="utf-8",
    )

    flag = prepare_round(white_path, red_path)

    assert flag != "sqli-search"
    data = json.loads(Path(white_path).read_text(encoding="utf-8"))
    assert data["side"] == "white"
    assert len(data["entries"]) == 1
    assert data["entries"][0]["phase"] == "preparation"
    assert data["entries"][0]["assigned_flag"] == flag


def test_prepare_round_works_when_red_memory_file_does_not_exist_yet(tmp_path):
    white_path = str(tmp_path / "white_memory.json")
    red_path = str(tmp_path / "does_not_exist.json")

    flag = prepare_round(white_path, red_path)

    assert flag == KNOWN_FLAGS[0]
