import os

import pytest

from henry_vault.errors import VaultAlreadyExists, VaultLocked
from henry_vault.store import AttachmentInput, SecretInput, VaultStore


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
