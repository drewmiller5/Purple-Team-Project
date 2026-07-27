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
