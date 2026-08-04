from unittest.mock import MagicMock

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


def test_poll_new_alerts_recovers_from_truncation_or_rotation(tmp_path):
    """H19: position must be tracked as a byte offset, not a line count.
    If the alerts file is rotated/truncated shorter than the previously
    read position, the reader must detect that (stored offset > current
    file size) and reset to the start instead of silently returning []
    forever -- which would make blue_agent look alive (still heartbeating)
    while it has permanently stopped seeing new alerts.
    """
    path = tmp_path / "alerts.json"
    path.write_text(
        '{"rule": {"id": "1"}}\n{"rule": {"id": "2"}}\n{"rule": {"id": "3"}}\n',
        encoding="utf-8",
    )

    reader = WazuhAlertsReader(str(path))
    first_batch = reader.poll_new_alerts()
    assert len(first_batch) == 3

    # Simulate log rotation: the file gets replaced with much shorter
    # content, so the previously stored byte offset now points past EOF.
    path.write_text('{"rule": {"id": "100"}}\n', encoding="utf-8")

    second_batch = reader.poll_new_alerts()
    assert len(second_batch) == 1
    assert second_batch[0]["rule"]["id"] == "100"

    # And polling reads only NEW content from then on, not from byte 0.
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"rule": {"id": "101"}}\n')
    third_batch = reader.poll_new_alerts()
    assert len(third_batch) == 1
    assert third_batch[0]["rule"]["id"] == "101"


def test_poll_new_alerts_recovers_from_rotation_when_replacement_is_not_shorter(tmp_path):
    """Reviewer-flagged gap in the original H19 fix: a size-only check
    (`self._offset > file_size`) misses the case where a rotated log is
    replaced by a NEW file that happens to be the same size or larger than
    the old read position. That's still a rotation (a different file, a
    different inode) -- without an identity check, the reader would seek
    into an arbitrary byte position of unrelated content and silently
    skip or mis-parse alerts, the exact "looks healthy, isn't" failure
    class H19 exists to close.
    """
    path = tmp_path / "alerts.json"
    path.write_text('{"rule": {"id": "1"}}\n', encoding="utf-8")

    reader = WazuhAlertsReader(str(path))
    first_batch = reader.poll_new_alerts()
    assert len(first_batch) == 1

    # Simulate rotation via unlink+recreate (a new inode), replaced with
    # content that is the SAME size as the offset already read -- the old
    # size-only check (`offset > file_size`) would not fire here.
    path.unlink()
    path.write_text('{"rule": {"id": "2"}}\n', encoding="utf-8")

    second_batch = reader.poll_new_alerts()
    assert len(second_batch) == 1
    assert second_batch[0]["rule"]["id"] == "2"


def test_poll_new_alerts_logs_rotation_recovery_via_state(tmp_path):
    """H19/H24: when a state/logger is supplied, rotation recovery must be
    logged using the established state.log_event pattern (see
    blue_agent/state.py, blue_agent/loop.py) so the recovery is visible in
    the event log rather than silent.
    """
    path = tmp_path / "alerts.json"
    path.write_text('{"rule": {"id": "1"}}\n{"rule": {"id": "2"}}\n', encoding="utf-8")

    state = MagicMock()
    reader = WazuhAlertsReader(str(path), state=state)
    reader.poll_new_alerts()

    path.write_text('{"rule": {"id": "9"}}\n', encoding="utf-8")
    reader.poll_new_alerts()

    state.log_event.assert_called_once()
    logged = state.log_event.call_args[0][0]
    assert logged["phase"] == "alerts_file_rotated"
