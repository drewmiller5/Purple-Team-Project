import re
import subprocess

import scripts.bootstrap as bootstrap
from scripts.bootstrap import (
    GENERATED_KEYS,
    build_credentials_block,
    extract_bcrypt_hash,
    generate_complex_password,
    generate_hex_secret,
    render_env_file,
    update_internal_users_hashes,
)


def test_generate_hex_secret_is_64_hex_chars_and_random():
    a = generate_hex_secret()
    b = generate_hex_secret()
    assert re.fullmatch(r"[0-9a-f]{64}", a)
    assert a != b


def test_generate_complex_password_satisfies_wazuh_manager_rule():
    # wazuh.manager's complexity rule: 8+ chars, at least one uppercase,
    # one lowercase, one digit, one of @$!%*?&-_
    for _ in range(20):
        pw = generate_complex_password()
        assert len(pw) >= 8
        assert re.search(r"[A-Z]", pw)
        assert re.search(r"[a-z]", pw)
        assert re.search(r"[0-9]", pw)
        assert re.search(r"[@$!%*?&\-_]", pw)


def test_generate_complex_password_is_random():
    assert generate_complex_password() != generate_complex_password()


def test_render_env_file_fills_only_blank_target_keys():
    template = (
        "# comment stays\n"
        "INTERNAL_ACTION_TOKEN=\n"
        "\n"
        "# OLLAMA_MODEL=qwen2.5:7b\n"
        "DASHBOARD_AUTH_TOKEN=\n"
        "UNRELATED_KEY=\n"
    )
    values = {"INTERNAL_ACTION_TOKEN": "abc123", "DASHBOARD_AUTH_TOKEN": "def456"}

    result = render_env_file(template, values)

    assert "INTERNAL_ACTION_TOKEN=abc123" in result
    assert "DASHBOARD_AUTH_TOKEN=def456" in result
    assert "# comment stays" in result
    assert "# OLLAMA_MODEL=qwen2.5:7b" in result
    assert "UNRELATED_KEY=\n" in result  # not in values -- left blank, untouched


def test_extract_bcrypt_hash_pulls_hash_out_of_noisy_output():
    noisy = (
        "WARNING: some docker log noise\n"
        "Password:\n"
        "$2y$12$V0VNqbU4MQVcz4migwmlyeS5y/gNYuLpxz.PouGMDx6unAfYQyZIG\n"
    )
    assert extract_bcrypt_hash(noisy) == (
        "$2y$12$V0VNqbU4MQVcz4migwmlyeS5y/gNYuLpxz.PouGMDx6unAfYQyZIG"
    )


def test_extract_bcrypt_hash_raises_when_no_hash_present():
    try:
        extract_bcrypt_hash("no hash here\n")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_update_internal_users_hashes_only_touches_admin_and_kibanaserver():
    yml = (
        "admin:\n"
        '  hash: "$2y$12$OLDADMINHASH"\n'
        "  reserved: true\n"
        "\n"
        "kibanaserver:\n"
        '  hash: "$2y$12$OLDKIBANAHASH"\n'
        "  reserved: true\n"
        "\n"
        "kibanaro:\n"
        '  hash: "$2a$12$UNTOUCHEDHASH"\n'
        "  reserved: false\n"
    )

    result = update_internal_users_hashes(
        yml, admin_hash="$2y$12$NEWADMIN", kibanaserver_hash="$2y$12$NEWKIBANA"
    )

    assert '  hash: "$2y$12$NEWADMIN"' in result
    assert '  hash: "$2y$12$NEWKIBANA"' in result
    assert '  hash: "$2a$12$UNTOUCHEDHASH"' in result  # kibanaro untouched
    assert "OLDADMINHASH" not in result
    assert "OLDKIBANAHASH" not in result


def test_build_credentials_block_includes_every_surface():
    env = {
        "DASHBOARD_AUTH_TOKEN": "dashtoken123",
        "WAZUH_INDEXER_PASSWORD": "indexerpass123",
        "WAZUH_API_PASSWORD": "apipass123",
    }

    block = build_credentials_block(env)

    assert "localhost:5000" in block  # target
    assert "admin123" in block  # seeded target staff creds
    assert "localhost:8080" in block  # round control dashboard
    assert "operator" in block and "dashtoken123" in block
    assert "localhost:443" in block or "localhost" in block  # wazuh dashboard
    assert "indexerpass123" in block
    # No raw indexer/manager API endpoints (9200/55000): not published to
    # the host -- debugging convenience only, dropped after the ports
    # themselves were removed from docker-compose.yml for being flaky
    # across Docker Desktop engine restarts and unneeded by the experiment.
    assert "9200" not in block
    assert "55000" not in block


def test_bootstrap_env_is_idempotent_when_env_already_exists(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("INTERNAL_ACTION_TOKEN=existing-value\n", encoding="utf-8")
    monkeypatch.setattr(bootstrap, "ENV_PATH", env_path)

    calls = []
    values = bootstrap.bootstrap_env(run=lambda *a, **k: calls.append(a))

    assert values == {"INTERNAL_ACTION_TOKEN": "existing-value"}
    assert calls == []  # never shells out to docker when .env already exists


def test_bootstrap_env_generates_and_syncs_hashes_when_missing(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_example_path = tmp_path / ".env.example"
    internal_users_path = tmp_path / "internal_users.yml"
    env_example_path.write_text(
        "\n".join(f"{k}=" for k in GENERATED_KEYS) + "\n", encoding="utf-8"
    )
    internal_users_path.write_text(
        'admin:\n  hash: "$2y$12$OLD"\n\nkibanaserver:\n  hash: "$2y$12$OLD"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(bootstrap, "ENV_PATH", env_path)
    monkeypatch.setattr(bootstrap, "ENV_EXAMPLE_PATH", env_example_path)
    monkeypatch.setattr(bootstrap, "INTERNAL_USERS_PATH", internal_users_path)

    def fake_run(argv, **kwargs):
        assert argv[:2] == ["docker", "run"]
        return subprocess.CompletedProcess(argv, 0, stdout="$2y$12$FAKEHASH", stderr="")

    values = bootstrap.bootstrap_env(run=fake_run)

    assert set(values) == set(GENERATED_KEYS)
    assert env_path.exists()
    written = env_path.read_text(encoding="utf-8")
    for key in GENERATED_KEYS:
        assert f"{key}={values[key]}" in written
    assert '"$2y$12$FAKEHASH"' in internal_users_path.read_text(encoding="utf-8")
    assert "OLD" not in internal_users_path.read_text(encoding="utf-8")
