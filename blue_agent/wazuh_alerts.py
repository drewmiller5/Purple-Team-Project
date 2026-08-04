import json
from pathlib import Path


class WazuhAlertsReader:
    def __init__(self, alerts_path: str, state=None):
        self.alerts_path = alerts_path
        self.state = state
        self._offset = 0
        self._inode = None

    def poll_new_alerts(self) -> list:
        path = Path(self.alerts_path)
        if not path.exists():
            return []

        stat = path.stat()
        file_size = stat.st_size

        # H19: position is a byte offset, not a line count. A same-size-or-
        # larger replacement file (log rotated then quickly refilled) isn't
        # caught by a size-only check, so also compare inode identity --
        # a rotated file is a genuinely different file even if its current
        # size happens to be >= our last offset. Either signal means the
        # old offset no longer points at content we've actually read, so
        # reset to the start and log the recovery instead of silently
        # returning [] or seeking into unrelated bytes.
        if self._inode is not None and stat.st_ino != self._inode:
            self._log_rotation(file_size)
            self._offset = 0
        elif self._offset > file_size:
            self._log_rotation(file_size)
            self._offset = 0
        self._inode = stat.st_ino

        # H24: seek to the stored offset and read only the new bytes,
        # instead of re-reading and re-parsing the whole file every poll.
        with open(path, "rb") as f:
            f.seek(self._offset)
            new_bytes = f.read()

        # A trailing line with no newline means the writer may still be
        # mid-write on it -- don't mark it "read" until it's complete, or a
        # line that finishes between polls would be silently skipped forever.
        last_newline = new_bytes.rfind(b"\n")
        complete_bytes = new_bytes[: last_newline + 1] if last_newline != -1 else b""
        self._offset += len(complete_bytes)

        alerts = []
        for line in complete_bytes.decode("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return alerts

    def _log_rotation(self, new_size: int) -> None:
        event = {
            "phase": "alerts_file_rotated",
            "path": self.alerts_path,
            "previous_offset": self._offset,
            "new_size": new_size,
        }
        if self.state is not None:
            self.state.log_event(event)
        else:
            print(f"[wazuh_alerts] alerts file rotated/truncated, resetting read position: {event}")
