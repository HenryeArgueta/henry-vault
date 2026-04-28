import os

import pytest

from henry_vault.errors import VaultAlreadyExists, VaultLocked
from henry_vault.store import SecretInput, VaultStore


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


def test_init_refuses_to_overwrite_existing_vault(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    with pytest.raises(VaultAlreadyExists):
        store.init("pw2")
