import base64
import hashlib
import hmac
import os
import struct
import time

import pytest

from henry_vault.errors import VaultAlreadyExists, VaultLocked
from henry_vault.store import AttachmentInput, SecretInput, VaultStore


def _current_totp(secret: str, timestamp: int | None = None) -> str:
    timestamp = int(time.time()) if timestamp is None else timestamp
    counter = timestamp // 30
    padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def test_init_add_get_list_delete_secret_round_trip(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)

    store.init("correct horse battery staple")
    store.unlock("correct horse battery staple")
    store.add_secret(
        SecretInput(
            name="OPENAI_API_KEY",
            value="sk-test-123",
            project="discord-bot",
            environment="prod",
            tags=["ai", "discord"],
            notes="primary test key",
        )
    )

    secret = store.get_secret("OPENAI_API_KEY", project="discord-bot", environment="prod")
    assert secret.name == "OPENAI_API_KEY"
    assert secret.value == "sk-test-123"
    assert secret.project == "discord-bot"
    assert secret.environment == "prod"
    assert secret.tags == ["ai", "discord"]
    assert secret.notes == "primary test key"

    metadata = store.list_secrets(project="discord-bot", environment="prod")
    assert len(metadata) == 1
    assert metadata[0].name == "OPENAI_API_KEY"
    assert not hasattr(metadata[0], "value")

    deleted = store.delete_secret("OPENAI_API_KEY", project="discord-bot", environment="prod")
    assert deleted is True
    assert store.get_secret("OPENAI_API_KEY", project="discord-bot", environment="prod") is None


def test_wrong_password_cannot_decrypt_existing_secret(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("good-password")
    store.unlock("good-password")
    store.add_secret(SecretInput(name="TOKEN", value="super-secret"))

    attacker = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        attacker.unlock("bad-password")


def test_two_factor_init_supports_totp_and_recovery_codes(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)

    setup = store.init("good-password", enable_two_factor=True, recovery_code_count=2)

    assert setup.totp_secret
    assert len(setup.recovery_codes) == 2

    locked = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        locked.unlock("good-password")

    code = _current_totp(setup.totp_secret)
    locked.unlock("good-password", totp_code=code)
    locked.add_secret(SecretInput(name="TOKEN", value="super-secret"))
    assert locked.get_secret("TOKEN").value == "super-secret"

    recovery = VaultStore(db_path)
    recovery.unlock(recovery_code=setup.recovery_codes[0])
    assert recovery.get_secret("TOKEN").value == "super-secret"

    second_recovery = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        second_recovery.unlock(recovery_code=setup.recovery_codes[0])


def test_two_factor_recovery_code_is_emergency_unlock_without_password(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    setup = store.init("good-password", enable_two_factor=True, recovery_code_count=2)
    store.add_secret(SecretInput(name="TOKEN", value="super-secret"))

    recovered = VaultStore(db_path)
    recovered.unlock(recovery_code=setup.recovery_codes[0])

    assert recovered.get_secret("TOKEN").value == "super-secret"


def test_two_factor_recovery_code_is_one_time_only(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    setup = store.init("good-password", enable_two_factor=True, recovery_code_count=1)

    first = VaultStore(db_path)
    first.unlock(recovery_code=setup.recovery_codes[0])

    second = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        second.unlock(recovery_code=setup.recovery_codes[0])


def test_two_factor_rejects_missing_and_invalid_totp(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    setup = store.init("good-password", enable_two_factor=True, recovery_code_count=1)

    missing = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        missing.unlock("good-password")

    invalid = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        invalid.unlock("good-password", totp_code="000000")

    valid = VaultStore(db_path)
    valid.unlock("good-password", totp_code=_current_totp(setup.totp_secret))
    assert valid.is_unlocked is True


def test_two_factor_recovery_code_count_is_bounded(tmp_path):
    for count in (0, 21):
        store = VaultStore(tmp_path / f"vault-{count}.db")
        with pytest.raises(ValueError):
            store.init("good-password", enable_two_factor=True, recovery_code_count=count)


def test_enable_two_factor_on_existing_vault_and_regenerate_recovery_codes(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("good-password")
    store.add_secret(SecretInput(name="TOKEN", value="super-secret"))

    setup = store.enable_two_factor("good-password", recovery_code_count=2)

    assert setup.totp_secret
    assert len(setup.recovery_codes) == 2
    assert store.has_two_factor_enabled() is True

    locked = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        locked.unlock("good-password")

    locked.unlock("good-password", totp_code=_current_totp(setup.totp_secret))
    assert locked.get_secret("TOKEN").value == "super-secret"

    new_codes = locked.regenerate_recovery_codes(recovery_code_count=2)
    assert len(new_codes) == 2

    old_recovery = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        old_recovery.unlock(recovery_code=setup.recovery_codes[0])

    new_recovery = VaultStore(db_path)
    new_recovery.unlock(recovery_code=new_codes[0])
    assert new_recovery.get_secret("TOKEN").value == "super-secret"


def test_rotate_and_disable_two_factor_on_existing_vault(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("good-password")
    setup = store.enable_two_factor("good-password", recovery_code_count=1)

    rotated = store.rotate_totp_secret()

    assert rotated.totp_secret
    assert rotated.totp_secret != setup.totp_secret
    old_totp = VaultStore(db_path)
    with pytest.raises(VaultLocked):
        old_totp.unlock("good-password", totp_code=_current_totp(setup.totp_secret))
    new_totp = VaultStore(db_path)
    new_totp.unlock("good-password", totp_code=_current_totp(rotated.totp_secret))

    new_totp.disable_two_factor("good-password")

    assert new_totp.has_two_factor_enabled() is False
    password_only = VaultStore(db_path)
    password_only.unlock("good-password")
    assert password_only.is_unlocked is True


def test_export_env_returns_shell_safe_lines(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="PLAIN", value="abc", project="demo", environment="dev"))
    store.add_secret(SecretInput(name="SPACED", value="hello world", project="demo", environment="dev"))

    lines = store.export_env(project="demo", environment="dev")

    assert "export PLAIN='abc'" in lines
    assert "export SPACED='hello world'" in lines


def test_run_env_contains_project_environment_secrets(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="TOKEN", value="abc", project="demo", environment="dev"))

    env = store.environment(project="demo", environment="dev")

    assert env["TOKEN"] == "abc"
    assert "PATH" in env


def test_list_secrets_filters_by_name_query_and_tags_without_values(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="OPENAI_API_KEY", value="openai-secret", tags=["prod", "ai"]))
    store.add_secret(SecretInput(name="DISCORD_TOKEN", value="discord-secret", tags=["prod", "discord"]))
    store.add_secret(SecretInput(name="OPENAI_DEV_KEY", value="dev-secret", tags=["dev", "ai"]))

    results = store.list_secrets(query="api", tags=["prod"])

    assert [item.name for item in results] == ["OPENAI_API_KEY"]
    assert not hasattr(results[0], "value")


def test_export_and_import_credentials_csv_round_trip(tmp_path):
    source = VaultStore(tmp_path / "source.db")
    source.init("pw")
    source.unlock("pw")
    source.add_secret(SecretInput(name="OPENAI_API_KEY", value="openai-secret", project="demo", environment="prod", tags=["ai", "prod"], notes="primary api key"))
    source.add_password(
        __import__("henry_vault.store", fromlist=["PasswordInput"]).PasswordInput(
            name="GitHub",
            url="https://github.com",
            username="henry",
            password="browser-password",
            note="personal account",
        )
    )

    export_path = tmp_path / "credentials.csv"
    summary = source.export_credentials(export_path)

    assert export_path.exists()
    assert summary.secrets == 1
    assert summary.passwords == 1
    raw = export_path.read_text()
    assert "kind,name,project,environment,url,username,value,note,tags,expires_at,rotation_url,created_at,updated_at" in raw
    assert "OPENAI_API_KEY" in raw
    assert "GitHub" in raw
    assert "openai-secret" in raw
    assert "browser-password" in raw

    restored = VaultStore(tmp_path / "restored.db")
    restored.init("new-pw")
    restored.unlock("new-pw")
    imported = restored.import_credentials(export_path)

    assert imported.secrets == 1
    assert imported.passwords == 1
    secret = restored.get_secret("OPENAI_API_KEY", project="demo", environment="prod")
    password = restored.get_password("GitHub", url="https://github.com", username="henry")
    assert secret.value == "openai-secret"
    assert secret.tags == ["ai", "prod"]
    assert secret.notes == "primary api key"
    assert password.password == "browser-password"
    assert password.note == "personal account"


def test_attachment_round_trip_encrypts_file_content_at_rest(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")

    store.add_attachment(
        AttachmentInput(
            name="SERVICE_ACCOUNT_JSON",
            filename="service-account.json",
            content=b'{"private_key":"super-secret-key"}',
            project="demo",
            environment="prod",
            content_type="application/json",
            notes="gcp service account",
        )
    )

    raw_db = db_path.read_bytes()
    assert b"super-secret-key" not in raw_db
    assert b"SERVICE_ACCOUNT_JSON" in raw_db

    metadata = store.list_attachments(project="demo", environment="prod")
    assert len(metadata) == 1
    assert metadata[0].name == "SERVICE_ACCOUNT_JSON"
    assert metadata[0].filename == "service-account.json"
    assert metadata[0].size == len(b'{"private_key":"super-secret-key"}')
    assert not hasattr(metadata[0], "content")

    attachment = store.get_attachment("SERVICE_ACCOUNT_JSON", project="demo", environment="prod")
    assert attachment.content == b'{"private_key":"super-secret-key"}'
    assert attachment.content_type == "application/json"


def test_init_refuses_to_overwrite_existing_vault(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    with pytest.raises(VaultAlreadyExists):
        store.init("pw2")
