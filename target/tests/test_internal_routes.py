# target/tests/test_internal_routes.py
import io
import socket
from unittest.mock import patch

from target.app import create_app
from target.db import get_connection

INTERNAL_ACTION_TOKEN = "test-internal-action-token"


def _make_app(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        log_path=str(tmp_path / "requests.jsonl"),
    )
    app.config["INTERNAL_ACTION_TOKEN"] = INTERNAL_ACTION_TOKEN
    return app


def _make_client(tmp_path):
    return _make_app(tmp_path).test_client()


def _internal_post(client, path, data):
    return client.post(
        path,
        data=data,
        headers={"X-Internal-Action-Token": INTERNAL_ACTION_TOKEN},
    )


def test_internal_actions_require_the_configured_token(tmp_path):
    client = _make_client(tmp_path)

    for path, data in (
        ("/internal/lock-account", {"username": "admin"}),
        ("/internal/kill-session", {"user_id": "1"}),
        ("/internal/block-ip", {"source_ip": "198.51.100.9"}),
    ):
        missing = client.post(path, data=data)
        wrong = client.post(
            path,
            data=data,
            headers={"X-Internal-Action-Token": "wrong-token"},
        )

        assert missing.status_code == 403
        assert wrong.status_code == 403


def test_lock_account_blocks_future_login(tmp_path):
    client = _make_client(tmp_path)
    _internal_post(client, "/internal/lock-account", {"username": "admin"})

    response = client.post(
        "/admin/login", data={"username": "admin", "password": "admin123"}
    )
    assert b"Welcome" not in response.data
    assert b"blocked" in response.data.lower()


def test_lock_account_permanent_blocks_subsequent_admin_requests(tmp_path):
    # H12: renamed from kill_session -- route path (/internal/kill-session)
    # is unchanged, only the Python function name changed to match its real
    # behavior (a permanent block, not a session kill).
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    login_row = client.get("/admin/whoami").get_json()
    _internal_post(client, "/internal/kill-session", {"user_id": login_row["user_id"]})

    response = client.post("/admin/diagnostics", data={"host": "127.0.0.1"})
    assert response.status_code == 403


def test_unblocked_account_logs_in_normally(tmp_path):
    client = _make_client(tmp_path)
    response = client.post(
        "/admin/login", data={"username": "admin", "password": "admin123"}
    )
    assert b"Welcome" in response.data


def test_lock_account_permanent_rejects_missing_or_non_numeric_user_id(tmp_path):
    client = _make_client(tmp_path)
    client.post("/admin/login", data={"username": "admin", "password": "admin123"})

    # Missing user_id entirely.
    response = _internal_post(client, "/internal/kill-session", {})
    assert response.status_code == 400

    # Non-numeric user_id.
    response = _internal_post(client, "/internal/kill-session", {"user_id": "not-a-number"})
    assert response.status_code == 400

    # Confirm no NULL block row was inserted -- the admin session is still
    # live and diagnostics still succeeds (not silently "killed").
    diag_response = client.post("/admin/diagnostics", data={"host": "127.0.0.1"})
    assert diag_response.status_code != 403


def test_lock_account_does_not_duplicate_row_for_already_blocked_username(tmp_path):
    # Final-review fix (finding #5): bruteforce-guard.sh re-invokes
    # lock-account.sh on every subsequent matching event once the window
    # count is >=5, so a real brute-force burst dispatches multiple
    # /internal/lock-account POSTs for the same username. Live-verified:
    # 6 POSTs past threshold used to produce 6 identical ('admin', None)
    # rows. The endpoint must dedup instead of inserting every time.
    app = _make_app(tmp_path)
    client = app.test_client()

    first = _internal_post(client, "/internal/lock-account", {"username": "admin"})
    second = _internal_post(client, "/internal/lock-account", {"username": "admin"})

    assert first.status_code == 200
    assert second.status_code == 200

    conn = get_connection(app.config["DB_PATH"])
    rows = conn.execute(
        "SELECT COUNT(*) FROM blocked_users WHERE username = ?", ("admin",)
    ).fetchone()[0]
    conn.close()

    assert rows == 1


def test_block_ip_rejects_missing_source_ip(tmp_path):
    client = _make_client(tmp_path)
    response = _internal_post(client, "/internal/block-ip", {})
    assert response.status_code == 400


def test_block_ip_rejects_invalid_ip_format(tmp_path):
    client = _make_client(tmp_path)
    response = _internal_post(client, "/internal/block-ip", {"source_ip": "not-an-ip; rm -rf /"})
    assert response.status_code == 400


def test_block_ip_runs_iptables_drop_for_valid_ip(tmp_path):
    client = _make_client(tmp_path)
    with patch(
        "target.routes.internal._protected_source_ips", return_value=(set(), True)
    ), patch("target.routes.internal.subprocess.run") as mock_run:
        # Configure mock to report success (returncode=0).
        mock_run.return_value.returncode = 0
        response = _internal_post(client, "/internal/block-ip", {"source_ip": "172.19.0.5"})

    assert response.status_code == 200
    assert response.get_json() == {"blocked_ip": "172.19.0.5"}
    calls = [c.args[0] for c in mock_run.call_args_list]
    assert ["iptables", "-I", "INPUT", "-s", "172.19.0.5", "-j", "DROP"] in calls
    assert ["iptables", "-I", "FORWARD", "-s", "172.19.0.5", "-j", "DROP"] in calls


def test_block_ip_returns_500_when_iptables_fails(tmp_path):
    client = _make_client(tmp_path)
    with patch(
        "target.routes.internal._protected_source_ips", return_value=(set(), True)
    ), patch("target.routes.internal.subprocess.run") as mock_run:
        # Configure mock to report failure (returncode=1) on first call.
        mock_run.return_value.returncode = 1
        response = _internal_post(client, "/internal/block-ip", {"source_ip": "172.19.0.5"})

    assert response.status_code == 500
    response_data = response.get_json()
    assert "error" in response_data
    assert response_data["blocked_ip"] == "172.19.0.5"


def test_block_ip_returns_503_when_protected_ips_not_fully_resolved(tmp_path):
    """H68: _protected_source_ips() reporting an incomplete allowlist (a
    still-unresolved DNS/route startup race) must not silently let
    block_ip() act on it -- an iptables DROP is real and irreversible
    via any API in this app. Refuse with 503 until resolution has
    succeeded at least once instead."""
    client = _make_client(tmp_path)

    with patch(
        "target.routes.internal._protected_source_ips",
        return_value=(set(), False),
    ), patch("target.routes.internal.subprocess.run") as mock_run:
        response = _internal_post(client, "/internal/block-ip", {"source_ip": "198.51.100.9"})

    assert response.status_code == 503
    mock_run.assert_not_called()


def test_block_ip_proceeds_once_protected_ips_are_fully_resolved(tmp_path):
    client = _make_client(tmp_path)

    with patch(
        "target.routes.internal._protected_source_ips",
        return_value=(set(), True),
    ), patch("target.routes.internal.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        response = _internal_post(client, "/internal/block-ip", {"source_ip": "198.51.100.9"})

    assert response.status_code == 200
    mock_run.assert_called()


def test_block_ip_rejects_resolved_infrastructure_addresses(tmp_path):
    client = _make_client(tmp_path)

    with patch(
        "target.routes.internal._protected_source_ips",
        return_value=({"172.19.0.1", "172.19.0.2", "172.19.0.3", "172.19.0.4"}, True),
    ), patch("target.routes.internal.subprocess.run") as mock_run:
        for source_ip in ("172.19.0.1", "172.19.0.2", "172.19.0.3", "172.19.0.4"):
            response = _internal_post(client, "/internal/block-ip", {"source_ip": source_ip})
            assert response.status_code == 403
            assert response.get_json()["error"] == "source_ip is protected infrastructure"

    mock_run.assert_not_called()


def test_lock_account_rejects_empty_or_whitespace_username(tmp_path):
    # H13: an empty/whitespace-only username was previously accepted and
    # permanently stored with no validation.
    client = _make_client(tmp_path)

    empty = _internal_post(client, "/internal/lock-account", {"username": ""})
    assert empty.status_code == 400
    assert "error" in empty.get_json()

    whitespace = _internal_post(client, "/internal/lock-account", {"username": "   "})
    assert whitespace.status_code == 400
    assert "error" in whitespace.get_json()

    missing = _internal_post(client, "/internal/lock-account", {})
    assert missing.status_code == 400

    conn = get_connection(_make_app(tmp_path).config["DB_PATH"])
    rows = conn.execute("SELECT COUNT(*) FROM blocked_users").fetchone()[0]
    conn.close()
    assert rows == 0


def test_lock_account_handles_unique_constraint_violation_cleanly(tmp_path):
    # H11: blocked_users.username now has a UNIQUE index. The existing
    # is_blocked-then-insert check isn't atomic, so a race can still slip a
    # second INSERT past the check -- that must be handled cleanly (still a
    # 200, "already blocked" outcome), not surfaced as a raw IntegrityError.
    app = _make_app(tmp_path)
    client = app.test_client()

    with patch("target.routes.internal.is_blocked", return_value=False):
        first = _internal_post(client, "/internal/lock-account", {"username": "admin"})
        second = _internal_post(client, "/internal/lock-account", {"username": "admin"})

    assert first.status_code == 200
    assert second.status_code == 200

    conn = get_connection(app.config["DB_PATH"])
    rows = conn.execute(
        "SELECT COUNT(*) FROM blocked_users WHERE username = ?", ("admin",)
    ).fetchone()[0]
    conn.close()
    assert rows == 1


def test_protected_source_ips_caches_dns_lookups(tmp_path):
    # H61: _protected_source_ips() used to call socket.gethostbyname() 3x
    # plus read /proc/net/route on every call. It must now compute once and
    # reuse the cached result.
    from target.routes import internal

    internal._protected_source_ips.cache_clear()
    try:
        with patch("target.routes.internal.socket.gethostbyname", return_value="10.0.0.9") as mock_lookup:
            first, first_resolved = internal._protected_source_ips()
            second, second_resolved = internal._protected_source_ips()

        assert first == second
        assert first_resolved is True
        assert second_resolved is True
        # 4 hostnames resolved on the first call only; the second call must
        # not trigger any additional socket.gethostbyname calls.
        assert mock_lookup.call_count == 4
    finally:
        internal._protected_source_ips.cache_clear()


def test_protected_source_ips_does_not_cache_a_degraded_result_after_dns_failure(tmp_path):
    # Reviewer-flagged gap: a plain lru_cache permanently locks in a
    # DNS-failure-degraded result for the rest of the process's life,
    # unlike the old per-request behavior which would self-correct the
    # next time a call happened to succeed. A security-relevant allowlist
    # (this feeds block_ip's infra-denylist) must not freeze itself into
    # a permanently under-protective state just because the first call
    # happened during a transient startup DNS race.
    from target.routes import internal

    internal._protected_source_ips.cache_clear()
    try:
        with patch("target.routes.internal.socket.gethostbyname", side_effect=socket.gaierror):
            degraded, degraded_resolved = internal._protected_source_ips()
        assert "10.0.0.9" not in degraded
        # H68: an unresolved DNS lookup means block_ip() must refuse to
        # act rather than trust this incomplete snapshot.
        assert degraded_resolved is False

        with patch("target.routes.internal.socket.gethostbyname", return_value="10.0.0.9") as mock_lookup:
            recovered, recovered_resolved = internal._protected_source_ips()
        assert "10.0.0.9" in recovered
        assert recovered_resolved is True
        # A degraded result must not have been cached -- this second call
        # has to actually retry DNS, not skip straight to a stale result.
        assert mock_lookup.call_count == 4
    finally:
        internal._protected_source_ips.cache_clear()


def test_protected_source_ips_derives_gateway_from_local_routes_with_no_default_route(tmp_path):
    # H81/H68-round-2: live-reproduced in production. A container attached
    # ONLY to internal:true networks (e.g. target itself, deliberately
    # egress-blocked per H71) never gets a default route (Destination
    # 0.0.0.0) at all -- Docker only assigns one when a network can
    # actually reach outside. The original design required finding that
    # exact row, so it could NEVER succeed for target's real deployment --
    # block_ip was permanently refusing (H68), not just during a genuine
    # startup race, confirmed live via real /proc/net/route content (two
    # local/direct routes, zero default-route rows). Docker still assigns
    # each such subnet's bridge gateway the lowest usable address in it
    # (network base + 1) -- derive it from EVERY route line instead of
    # requiring one specific "default" line to exist.
    from target.routes import internal

    # Real shape observed live inside the target container: two local
    # routes (lab-net, wazuh-net), Gateway=0 on both (no gateway needed
    # for an on-link subnet), no Destination=0.0.0.0 row anywhere.
    two_internal_networks_no_default = (
        "Iface\tDestination\tGateway\n"
        "eth0\t000015AC\t00000000\n"  # 172.21.0.0/16 -- gateway derived: 172.21.0.1
        "eth1\t000017AC\t00000000\n"  # 172.23.0.0/16 -- gateway derived: 172.23.0.1
    )

    internal._protected_source_ips.cache_clear()
    try:
        with patch("target.routes.internal.socket.gethostbyname", return_value="10.0.0.9"), patch(
            "target.routes.internal.open", return_value=io.StringIO(two_internal_networks_no_default)
        ):
            protected, resolved = internal._protected_source_ips()

        assert resolved is True
        assert "172.21.0.1" in protected
        assert "172.23.0.1" in protected
    finally:
        internal._protected_source_ips.cache_clear()


def test_protected_source_ips_still_uses_explicit_default_route_gateway_when_present(tmp_path):
    # Single-homed-with-real-default-route case must keep working exactly
    # as before -- a route with a real (non-zero) Gateway field is used
    # directly, not overridden by the base+1 derivation.
    from target.routes import internal

    has_default_route = "Iface\tDestination\tGateway\n" "eth0\t00000000\t0100A8C0\n"

    internal._protected_source_ips.cache_clear()
    try:
        with patch("target.routes.internal.socket.gethostbyname", return_value="10.0.0.9"), patch(
            "target.routes.internal.open", return_value=io.StringIO(has_default_route)
        ):
            protected, resolved = internal._protected_source_ips()

        assert resolved is True
        assert "192.168.0.1" in protected
    finally:
        internal._protected_source_ips.cache_clear()


def test_protected_source_ips_does_not_cache_when_route_table_has_no_data_rows_yet(tmp_path):
    # The genuine startup race this must still catch: /proc/net/route is
    # readable but has ONLY the header (no interface has attached to any
    # network yet). That outcome must not be cached, or the allowlist
    # permanently loses route-based protection.
    from target.routes import internal

    header_only = "Iface\tDestination\tGateway\n"
    has_default_route = "Iface\tDestination\tGateway\n" "eth0\t00000000\t0100A8C0\n"

    internal._protected_source_ips.cache_clear()
    try:
        with patch("target.routes.internal.socket.gethostbyname", return_value="10.0.0.9"), patch(
            "target.routes.internal.open", return_value=io.StringIO(header_only)
        ):
            degraded, degraded_resolved = internal._protected_source_ips()
        assert "192.168.0.1" not in degraded
        assert degraded_resolved is False

        with patch(
            "target.routes.internal.socket.gethostbyname", return_value="10.0.0.9"
        ) as mock_lookup, patch("target.routes.internal.open", return_value=io.StringIO(has_default_route)):
            recovered, recovered_resolved = internal._protected_source_ips()
        assert "192.168.0.1" in recovered
        assert recovered_resolved is True
        # A degraded result must not have been cached -- this second call
        # has to actually re-run DNS (and re-read the route table), not
        # skip straight to a stale result.
        assert mock_lookup.call_count == 4
    finally:
        internal._protected_source_ips.cache_clear()


def test_protected_source_ips_does_not_cache_after_a_transient_route_read_error(tmp_path):
    # Second security-reviewer-flagged gap: treating every OSError from
    # opening /proc/net/route as "permanent, doesn't gate caching" is too
    # broad. Only a missing file (FileNotFoundError, e.g. non-Linux dev
    # boxes) is actually permanent. A PermissionError or other transient
    # I/O error is the same class of problem as a startup DNS race and
    # must not get baked into the cache either.
    from target.routes import internal

    has_default_route = "Iface\tDestination\tGateway\n" "eth0\t00000000\t0100A8C0\n"

    internal._protected_source_ips.cache_clear()
    try:
        with patch("target.routes.internal.socket.gethostbyname", return_value="10.0.0.9"), patch(
            "target.routes.internal.open", side_effect=PermissionError
        ):
            degraded, degraded_resolved = internal._protected_source_ips()
        assert "192.168.0.1" not in degraded
        assert degraded_resolved is False

        with patch(
            "target.routes.internal.socket.gethostbyname", return_value="10.0.0.9"
        ) as mock_lookup, patch("target.routes.internal.open", return_value=io.StringIO(has_default_route)):
            recovered, recovered_resolved = internal._protected_source_ips()
        assert "192.168.0.1" in recovered
        assert recovered_resolved is True
        assert mock_lookup.call_count == 4
    finally:
        internal._protected_source_ips.cache_clear()


def test_protected_source_ips_skips_a_malformed_default_route_line_and_checks_later_lines(tmp_path):
    # Second half of the same finding: the route-matching loop broke
    # unconditionally on the first Destination==00000000 line, even when
    # that line's gateway field failed to parse. On a route table with
    # more than one default-route-shaped line (policy routing), a
    # malformed first match would permanently hide a valid later one.
    from target.routes import internal

    first_line_malformed = (
        "Iface\tDestination\tGateway\n" "eth0\t00000000\tZZZZZZZZ\n" "eth1\t00000000\t0100A8C0\n"
    )

    internal._protected_source_ips.cache_clear()
    try:
        with patch("target.routes.internal.socket.gethostbyname", return_value="10.0.0.9"), patch(
            "target.routes.internal.open", return_value=io.StringIO(first_line_malformed)
        ):
            result, resolved = internal._protected_source_ips()
        assert "192.168.0.1" in result
        assert resolved is True
    finally:
        internal._protected_source_ips.cache_clear()
