from pathlib import Path
from unittest.mock import patch

import requests

from dashboard.round_control import clear_flags, start_round, stop_round


def test_clear_flags_removes_both_flag_files(tmp_path):
    (tmp_path / "go.flag").touch()
    (tmp_path / "stop.flag").touch()

    clear_flags(str(tmp_path))

    assert not (tmp_path / "go.flag").exists()
    assert not (tmp_path / "stop.flag").exists()


def test_clear_flags_is_safe_when_files_absent(tmp_path):
    clear_flags(str(tmp_path))  # must not raise


def test_stop_round_touches_stop_flag(tmp_path):
    result = stop_round(str(tmp_path))

    assert (tmp_path / "stop.flag").exists()
    assert result == {"stopped": True}


def test_start_round_posts_to_helper_and_returns_its_response():
    with patch("dashboard.round_control.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"started": ["purple-lab-referee", "purple-lab-red", "purple-lab-blue"]}
        result = start_round("http://round_helper:8090", "secret-token")

    mock_post.assert_called_once_with("http://round_helper:8090/start-round", headers={"X-Internal-Action-Token": "secret-token"}, timeout=60)
    assert result == {"started": ["purple-lab-referee", "purple-lab-red", "purple-lab-blue"]}


def test_start_round_surfaces_connection_errors_instead_of_raising():
    with patch("dashboard.round_control.requests.post", side_effect=requests.RequestException("down")):
        result = start_round("http://round_helper:8090", "secret-token")

    assert result == {"error": "down"}


def test_start_round_handles_non_2xx_status_codes_safely():
    with patch("dashboard.round_control.requests.post") as mock_post:
        mock_post.return_value.status_code = 401
        mock_post.return_value.text = "Unauthorized"
        result = start_round("http://round_helper:8090", "invalid-token")

    assert result == {"error": "Unauthorized"}
