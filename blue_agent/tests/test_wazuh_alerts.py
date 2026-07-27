from blue_agent.wazuh_alerts import WazuhAlertsReader


def test_poll_new_alerts_returns_empty_list_when_file_missing(tmp_path):
    reader = WazuhAlertsReader(str(tmp_path / "alerts.json"))
    assert reader.poll_new_alerts() == []


def test_poll_new_alerts_returns_all_lines_on_first_call(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text('{"rule": {"id": "100101"}}\n{"rule": {"id": "100102"}}\n', encoding="utf-8")

    reader = WazuhAlertsReader(str(path))
    alerts = reader.poll_new_alerts()

    assert len(alerts) == 2
    assert alerts[0]["rule"]["id"] == "100101"
    assert alerts[1]["rule"]["id"] == "100102"


def test_poll_new_alerts_only_returns_lines_appended_since_last_call(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text('{"rule": {"id": "100101"}}\n', encoding="utf-8")

    reader = WazuhAlertsReader(str(path))
    reader.poll_new_alerts()

    with open(path, "a", encoding="utf-8") as f:
        f.write('{"rule": {"id": "100103"}}\n')

    second_batch = reader.poll_new_alerts()
    assert len(second_batch) == 1
    assert second_batch[0]["rule"]["id"] == "100103"


def test_poll_new_alerts_returns_empty_list_when_nothing_new(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text('{"rule": {"id": "100101"}}\n', encoding="utf-8")

    reader = WazuhAlertsReader(str(path))
    reader.poll_new_alerts()

    assert reader.poll_new_alerts() == []


def test_poll_new_alerts_skips_malformed_lines(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text('{"rule": {"id": "100101"}}\nnot valid json\n', encoding="utf-8")

    reader = WazuhAlertsReader(str(path))
    alerts = reader.poll_new_alerts()

    assert len(alerts) == 1


def test_poll_new_alerts_does_not_consume_incomplete_trailing_line(tmp_path):
    """Test that an incomplete trailing line (no newline) is not marked as read.

    This prevents silent loss of alerts when Wazuh is mid-write on the last line.
    A line without a trailing newline should not be consumed until it's complete.
    """
    path = tmp_path / "alerts.json"
    # Write one complete line and one incomplete line (no trailing newline)
    path.write_text('{"rule": {"id": "1"}}\n{"rule": {"id": "2"}}', encoding="utf-8")

    reader = WazuhAlertsReader(str(path))
    alerts = reader.poll_new_alerts()

    # Only the complete line should be returned
    assert len(alerts) == 1
    assert alerts[0]["rule"]["id"] == "1"

    # Now complete the second line and add a third one
    with open(path, "a", encoding="utf-8") as f:
        f.write('\n{"rule": {"id": "3"}}\n')

    alerts = reader.poll_new_alerts()

    # Now both the previously-incomplete line and the new line should be returned
    assert len(alerts) == 2
    assert alerts[0]["rule"]["id"] == "2"
    assert alerts[1]["rule"]["id"] == "3"
