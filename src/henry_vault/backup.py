from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

from .errors import VaultLocked
from .store import AttachmentInput, SecretInput, VaultStore

FORMAT = "henry-vault-backup-v1"


@dataclass(frozen=True)
class PrunedBackup:
    path: Path
    age_days: int
    deleted: bool


@dataclass(frozen=True)
class BackupPruneResult:
    items: list[PrunedBackup]

    @property
    def deleted_count(self) -> int:
        return sum(1 for item in self.items if item.deleted)


def export_backup(store: VaultStore, path: str | Path, backup_password: str) -> None:
    salt = os.urandom(16)
    fernet = Fernet(_derive_key(backup_password, salt))
    secrets = []
    for item in store.list_secrets():
        secret = store.get_secret(item.name, project=item.project, environment=item.environment)
        if secret is None:
            continue
        secrets.append(
            {
                "name": secret.name,
                "value": secret.value,
                "project": secret.project,
                "environment": secret.environment,
                "tags": secret.tags,
                "notes": secret.notes,
                "expires_at": secret.expires_at,
                "rotation_url": secret.rotation_url,
            }
        )
    attachments = []
    for item in store.list_attachments():
        attachment = store.get_attachment(item.name, project=item.project, environment=item.environment)
        if attachment is None:
            continue
        attachments.append(
            {
                "name": attachment.name,
                "filename": attachment.filename,
                "content": base64.b64encode(attachment.content).decode(),
                "project": attachment.project,
                "environment": attachment.environment,
                "content_type": attachment.content_type,
                "notes": attachment.notes,
            }
        )
    encrypted = fernet.encrypt(json.dumps({"secrets": secrets, "attachments": attachments}, sort_keys=True).encode()).decode()
    payload = {
        "format": FORMAT,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "kdf": "argon2id",
        "salt": base64.b64encode(salt).decode(),
        "payload": encrypted,
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.chmod(out, 0o600)


def import_backup(store: VaultStore, path: str | Path, backup_password: str) -> int:
    raw = json.loads(Path(path).read_text())
    if raw.get("format") != FORMAT:
        raise ValueError("Unsupported backup format")
    salt = base64.b64decode(raw["salt"])
    fernet = Fernet(_derive_key(backup_password, salt))
    try:
        decrypted = fernet.decrypt(raw["payload"].encode())
    except InvalidToken as exc:
        raise VaultLocked("Wrong backup password") from exc
    data = json.loads(decrypted)
    count = 0
    for item in data.get("secrets", []):
        store.add_secret(
            SecretInput(
                name=item["name"],
                value=item["value"],
                project=item.get("project", "default"),
                environment=item.get("environment", "default"),
                tags=item.get("tags", []),
                notes=item.get("notes", ""),
            )
        )
        store.set_secret_metadata(
            item["name"],
            project=item.get("project", "default"),
            environment=item.get("environment", "default"),
            expires_at=item.get("expires_at"),
            rotation_url=item.get("rotation_url"),
        )
        count += 1
    for item in data.get("attachments", []):
        store.add_attachment(
            AttachmentInput(
                name=item["name"],
                filename=item.get("filename", item["name"]),
                content=base64.b64decode(item["content"]),
                project=item.get("project", "default"),
                environment=item.get("environment", "default"),
                content_type=item.get("content_type", "application/octet-stream"),
                notes=item.get("notes", ""),
            )
        )
        count += 1
    return count


def prune_backups(
    backup_dir: str | Path,
    keep_days: int,
    now: datetime | None = None,
    dry_run: bool = True,
) -> BackupPruneResult:
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=keep_days)
    root = Path(backup_dir)
    items: list[PrunedBackup] = []
    for path in sorted(root.glob("*.hv.json")):
        if not path.is_file() or not _is_henry_vault_backup(path):
            continue
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        if modified >= cutoff:
            continue
        age_days = max(0, int((now - modified).total_seconds() // 86400))
        deleted = False
        if not dry_run:
            path.unlink()
            deleted = True
        items.append(PrunedBackup(path=path, age_days=age_days, deleted=deleted))
    return BackupPruneResult(items=items)


def _is_henry_vault_backup(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False
    return payload.get("format") == FORMAT


def _derive_key(password: str, salt: bytes) -> bytes:
    raw = hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )
    return base64.urlsafe_b64encode(raw)
