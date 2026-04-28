import json

import pytest

from henry_vault.backup import export_backup, import_backup
from henry_vault.errors import VaultLocked
from henry_vault.store import SecretInput, VaultStore


def test_backup_export_does_not_contain_plaintext_secret(tmp_path):
    db_path = tmp_path / "vault.db"
    backup_path = tmp_path / "backup.hv.json"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="TOKEN", value="super-secret", project="demo", environment="prod"))

    export_backup(store, backup_path, backup_password="backup-pw")

    raw = backup_path.read_text()
    payload = json.loads(raw)
    assert payload["format"] == "henry-vault-backup-v1"
    assert "super-secret" not in raw
    assert "TOKEN" not in raw


def test_backup_import_restores_into_new_vault(tmp_path):
    source = VaultStore(tmp_path / "source.db")
    source.init("pw")
    source.unlock("pw")
    source.add_secret(SecretInput(name="TOKEN", value="super-secret", project="demo", environment="prod", tags=["x"]))
    backup_path = tmp_path / "backup.hv.json"
    export_backup(source, backup_path, backup_password="backup-pw")

    restored = VaultStore(tmp_path / "restored.db")
    restored.init("new-pw")
    restored.unlock("new-pw")
    count = import_backup(restored, backup_path, backup_password="backup-pw")

    assert count == 1
    secret = restored.get_secret("TOKEN", project="demo", environment="prod")
    assert secret.value == "super-secret"
    assert secret.tags == ["x"]


def test_backup_import_rejects_wrong_password(tmp_path):
    source = VaultStore(tmp_path / "source.db")
    source.init("pw")
    source.unlock("pw")
    source.add_secret(SecretInput(name="TOKEN", value="super-secret"))
    backup_path = tmp_path / "backup.hv.json"
    export_backup(source, backup_path, backup_password="backup-pw")

    restored = VaultStore(tmp_path / "restored.db")
    restored.init("new-pw")
    restored.unlock("new-pw")
    with pytest.raises(VaultLocked):
        import_backup(restored, backup_path, backup_password="wrong")
