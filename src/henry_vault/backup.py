from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

from .errors import VaultLocked
from .store import SecretInput, VaultStore

FORMAT = "henry-vault-backup-v1"


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
    encrypted = fernet.encrypt(json.dumps({"secrets": secrets}, sort_keys=True).encode()).decode()
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
    return count


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
