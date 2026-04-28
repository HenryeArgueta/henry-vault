import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from henry_vault.backup import export_backup, import_backup, prune_backups
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


def test_prune_backups_dry_run_reports_only_old_henry_vault_backups(tmp_path):
    now = datetime(2026, 4, 28, tzinfo=UTC)
    old_backup = tmp_path / "old.hv.json"
    recent_backup = tmp_path / "recent.hv.json"
    old_non_backup = tmp_path / "old.txt"
    invalid_backup_name = tmp_path / "invalid.hv.json"
    for path in [old_backup, recent_backup]:
        path.write_text(json.dumps({"format": "henry-vault-backup-v1"}))
    old_non_backup.write_text("do not delete")
    invalid_backup_name.write_text("not json")
    old_time = (now - timedelta(days=45)).timestamp()
    recent_time = (now - timedelta(days=2)).timestamp()
    os.utime(old_backup, (old_time, old_time))
    os.utime(old_non_backup, (old_time, old_time))
    os.utime(invalid_backup_name, (old_time, old_time))
    os.utime(recent_backup, (recent_time, recent_time))

    result = prune_backups(tmp_path, keep_days=30, now=now, dry_run=True)

    assert [item.path for item in result.items] == [old_backup]
    assert result.deleted_count == 0
    assert old_backup.exists()
    assert recent_backup.exists()
    assert old_non_backup.exists()
    assert invalid_backup_name.exists()


def test_prune_backups_delete_removes_only_reported_backup_files(tmp_path):
    now = datetime(2026, 4, 28, tzinfo=UTC)
    old_backup = tmp_path / "old.hv.json"
    old_backup.write_text(json.dumps({"format": "henry-vault-backup-v1"}))
    old_time = (now - timedelta(days=45)).timestamp()
    os.utime(old_backup, (old_time, old_time))

    result = prune_backups(tmp_path, keep_days=30, now=now, dry_run=False)

    assert result.deleted_count == 1
    assert not old_backup.exists()
