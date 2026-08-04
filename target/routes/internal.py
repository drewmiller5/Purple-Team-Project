# target/routes/internal.py
import hmac
import ipaddress
import socket
import sqlite3
import subprocess

from flask import Blueprint, current_app, jsonify, request

from target.db import get_connection, is_blocked

internal_bp = Blueprint("internal", __name__, url_prefix="/internal")


def _is_authorized_internal_action():
    expected_token = current_app.config.get("INTERNAL_ACTION_TOKEN")
    supplied_token = request.headers.get("X-Internal-Action-Token")
    return bool(expected_token and supplied_token and hmac.compare_digest(expected_token, supplied_token))


def _protected_source_ips():
    """Return the target and essential lab peers that must never be blocked.

    H61: DNS/file-I/O lookups here are cheap-but-not-free and don't change
    within a process's lifetime, so compute once and cache rather than
    re-resolving on every /internal/block-ip request. A plain lru_cache
    would freeze a DNS-failure-degraded result (e.g. a startup race where
    wazuh.manager isn't yet resolvable) for the rest of the process's
    life -- this is a security-relevant allowlist, so only cache a fully-
    resolved result; a degraded one retries on the next call, matching
    the old per-request behavior's ability to self-correct.
    """
    if _protected_source_ips.cache is not None:
        return _protected_source_ips.cache

    protected = {"127.0.0.1"}
    resolved_all = True
    for hostname in ("target", socket.gethostname(), "wazuh.manager", "blue_agent"):
        try:
            protected.add(socket.gethostbyname(hostname))
        except socket.gaierror:
            resolved_all = False
            continue

    # Docker exposes the bridge gateway as the default route in the target
    # container. Read it rather than assuming a compose-assigned subnet.
    try:
        with open("/proc/net/route", encoding="utf-8") as routes:
            for route in routes:
                fields = route.split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    protected.add(str(ipaddress.IPv4Address(int(fields[2], 16).to_bytes(4, "little"))))
                    break
    except (OSError, ValueError):
        # Expected and permanent on non-Linux dev/test environments (no
        # /proc/net/route at all) -- unlike a DNS gaierror, this will
        # never self-correct by retrying, so it doesn't gate caching.
        pass

    if resolved_all:
        _protected_source_ips.cache = protected
    return protected


_protected_source_ips.cache = None
_protected_source_ips.cache_clear = lambda: setattr(_protected_source_ips, "cache", None)


def _reject_unauthorized_action():
    if not _is_authorized_internal_action():
        return jsonify({"error": "internal action authorization required"}), 403
    return None


@internal_bp.route("/lock-account", methods=["POST"])
def lock_account():
    unauthorized = _reject_unauthorized_action()
    if unauthorized:
        return unauthorized
    username = request.form.get("username", "").strip()
    if not username:
        # H13: an empty/whitespace-only username was previously accepted
        # and stored permanently with no way to identify or undo it.
        return jsonify({"error": "username is required"}), 400
    conn = get_connection(current_app.config["DB_PATH"])
    # Final-review fix (finding #5): bruteforce-guard.sh re-invokes this
    # endpoint on every subsequent matching event once the window count is
    # >=5, so a real brute-force burst dispatches multiple lock-account
    # POSTs for the same username -- live-verified to produce duplicate
    # ('admin', None) rows before this check existed. Skip the insert (but
    # still return 200 -- the caller's desired end state, "this account is
    # blocked", already holds) if already blocked.
    try:
        if not is_blocked(conn, username=username):
            conn.execute("INSERT INTO blocked_users (username) VALUES (?)", (username,))
            conn.commit()
    except sqlite3.IntegrityError:
        # H11: the check-then-insert above still isn't atomic. The UNIQUE
        # constraint on blocked_users.username is the backstop for a
        # concurrent duplicate insert -- treat it the same as "already
        # blocked" rather than surfacing a raw 500.
        conn.rollback()
    conn.close()
    return jsonify({"locked": username}), 200


@internal_bp.route("/kill-session", methods=["POST"])
def lock_account_permanent():
    # H12 (2026-07-28 user decision): renamed from kill_session -- this
    # endpoint doesn't kill a session, it permanently blocks the account's
    # user_id from /admin/diagnostics with no unblock mechanism. Route path
    # stays /internal/kill-session (external contract for blue_agent /
    # AR scripts); only the Python name changes to match real behavior.
    unauthorized = _reject_unauthorized_action()
    if unauthorized:
        return unauthorized
    user_id = request.form.get("user_id", type=int)
    if user_id is None:
        return jsonify({"error": "user_id is required and must be numeric"}), 400
    conn = get_connection(current_app.config["DB_PATH"])
    conn.execute("INSERT INTO blocked_users (user_id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"locked_account_for": user_id}), 200


@internal_bp.route("/block-ip", methods=["POST"])
def block_ip():
    unauthorized = _reject_unauthorized_action()
    if unauthorized:
        return unauthorized
    source_ip = request.form.get("source_ip", "")
    try:
        ipaddress.IPv4Address(source_ip)
    except ValueError:
        return jsonify({"error": "source_ip is required and must be a valid IPv4 address"}), 400

    if source_ip in _protected_source_ips() or ipaddress.IPv4Address(source_ip).is_loopback:
        return jsonify({"error": "source_ip is protected infrastructure"}), 403

    # List-form subprocess.run (never shell=True) -- this is a real,
    # internal-only defensive action, not a seeded vuln like
    # diagnostics.py's deliberately-vulnerable ping. Mirrors exactly what
    # Plan 3A's idor-guard.sh already does at the AR-script layer, just
    # callable directly by blue_agent as an app-level escalation.
    try:
        result_input = subprocess.run(["iptables", "-I", "INPUT", "-s", source_ip, "-j", "DROP"], check=False)
        result_forward = subprocess.run(["iptables", "-I", "FORWARD", "-s", source_ip, "-j", "DROP"], check=False)
    except FileNotFoundError:
        return jsonify({"error": "iptables command not found"}), 400

    # Check exit codes; return error if either call failed.
    if result_input.returncode != 0 or result_forward.returncode != 0:
        return jsonify({"error": "iptables command failed", "blocked_ip": source_ip}), 500

    return jsonify({"blocked_ip": source_ip}), 200
