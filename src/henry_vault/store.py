from __future__ import annotations

import base64
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

from .errors import VaultAlreadyExists, VaultLocked, VaultNotInitialized

DEFAULT_DB_PATH = Path.home() / ".henry-vault" / "vault.db"


@dataclass(frozen=True)
class SecretInput:
    name: str
    value: str
    project: str = "default"
    environment: str = "default"
    tags: list[str] | None = None
    notes: str = ""


@dataclass(frozen=True)
class SecretMetadata:
    id: int
    name: str
    project: str
    environment: str
    tags: list[str]
    notes: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class Secret(SecretMetadata):
    value: str


class VaultStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path).expanduser()
        self._fernet: Fernet | None = None

    @property
    def is_unlocked(self) -> bool:
        return self._fernet is not None

    def init(self, password: str) -> None:
        if self.db_path.exists():
            with self._connect() as conn:
                if self._has_schema(conn):
                    raise VaultAlreadyExists(f"Vault already exists at {self.db_path}")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        verifier_plaintext = b"henry-vault-verifier-v1"
        fernet = Fernet(self._derive_key(password, salt))
        verifier = fernet.encrypt(verifier_plaintext).decode()
        with self._connect() as conn:
            self._create_schema(conn)
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("kdf_salt", base64.b64encode(salt).decode()))
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("verifier", verifier))
        os.chmod(self.db_path, 0o600)

    def unlock(self, password: str) -> None:
        self._ensure_initialized()
        with self._connect() as conn:
            salt_b64 = self._meta(conn, "kdf_salt")
            verifier = self._meta(conn, "verifier")
        salt = base64.b64decode(salt_b64)
        fernet = Fernet(self._derive_key(password, salt))
        try:
            if fernet.decrypt(verifier.encode()) != b"henry-vault-verifier-v1":
                raise VaultLocked("Wrong master password")
        except InvalidToken as exc:
            raise VaultLocked("Wrong master password") from exc
        self._fernet = fernet

    def add_secret(self, secret: SecretInput) -> None:
        fernet = self._require_unlocked()
        now = self._now()
        encrypted_value = fernet.encrypt(secret.value.encode()).decode()
        tags = json.dumps(secret.tags or [])
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO secrets(name, project, environment, encrypted_value, tags, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, project, environment) DO UPDATE SET
                    encrypted_value=excluded.encrypted_value,
                    tags=excluded.tags,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at
                """,
                (secret.name, secret.project, secret.environment, encrypted_value, tags, secret.notes, now, now),
            )

    def get_secret(self, name: str, project: str = "default", environment: str = "default") -> Secret | None:
        fernet = self._require_unlocked()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, name, project, environment, encrypted_value, tags, notes, created_at, updated_at
                FROM secrets WHERE name=? AND project=? AND environment=?
                """,
                (name, project, environment),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_secret(row, fernet)

    def list_secrets(self, project: str | None = None, environment: str | None = None) -> list[SecretMetadata]:
        self._require_unlocked()
        clauses = []
        params = []
        if project is not None:
            clauses.append("project=?")
            params.append(project)
        if environment is not None:
            clauses.append("environment=?")
            params.append(environment)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, name, project, environment, tags, notes, created_at, updated_at
                FROM secrets {where} ORDER BY project, environment, name
                """,
                params,
            ).fetchall()
        return [self._row_to_metadata(row) for row in rows]

    def delete_secret(self, name: str, project: str = "default", environment: str = "default") -> bool:
        self._require_unlocked()
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM secrets WHERE name=? AND project=? AND environment=?", (name, project, environment))
        return cur.rowcount > 0

    def export_env(self, project: str | None = None, environment: str | None = None) -> str:
        env = self.secrets_dict(project=project, environment=environment)
        return "\n".join(f"export {name}={self._single_quote(value)}" for name, value in sorted(env.items()))

    def secrets_dict(self, project: str | None = None, environment: str | None = None) -> dict[str, str]:
        fernet = self._require_unlocked()
        clauses = []
        params = []
        if project is not None:
            clauses.append("project=?")
            params.append(project)
        if environment is not None:
            clauses.append("environment=?")
            params.append(environment)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(f"SELECT name, encrypted_value FROM secrets {where}", params).fetchall()
        return {row["name"]: fernet.decrypt(row["encrypted_value"].encode()).decode() for row in rows}

    def environment(self, project: str | None = None, environment: str | None = None) -> dict[str, str]:
        env = dict(os.environ)
        env.update(self.secrets_dict(project=project, environment=environment))
        return env

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                project TEXT NOT NULL DEFAULT 'default',
                environment TEXT NOT NULL DEFAULT 'default',
                encrypted_value TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(name, project, environment)
            );
            """
        )

    def _has_schema(self, conn: sqlite3.Connection) -> bool:
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
        return row is not None

    def _ensure_initialized(self) -> None:
        if not self.db_path.exists():
            raise VaultNotInitialized(f"Vault does not exist at {self.db_path}")
        with self._connect() as conn:
            if not self._has_schema(conn):
                raise VaultNotInitialized(f"Vault is not initialized at {self.db_path}")

    def _meta(self, conn: sqlite3.Connection, key: str) -> str:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            raise VaultNotInitialized(f"Missing metadata: {key}")
        return str(row["value"])

    def _require_unlocked(self) -> Fernet:
        if self._fernet is None:
            raise VaultLocked("Vault is locked. Call unlock() first.")
        return self._fernet

    def _derive_key(self, password: str, salt: bytes) -> bytes:
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

    def _single_quote(self, value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    def _row_to_metadata(self, row: sqlite3.Row) -> SecretMetadata:
        return SecretMetadata(
            id=int(row["id"]),
            name=str(row["name"]),
            project=str(row["project"]),
            environment=str(row["environment"]),
            tags=json.loads(row["tags"] or "[]"),
            notes=str(row["notes"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def _row_to_secret(self, row: sqlite3.Row, fernet: Fernet) -> Secret:
        value = fernet.decrypt(row["encrypted_value"].encode()).decode()
        return Secret(value=value, **self._row_to_metadata(row).__dict__)

    def _now(self) -> str:
        return datetime.now(UTC).isoformat(timespec="seconds")
