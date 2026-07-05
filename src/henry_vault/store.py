from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

from .errors import VaultAlreadyExists, VaultLocked, VaultNotInitialized
from .envfile import parse_env_file

DEFAULT_DB_PATH = Path.home() / ".henry-vault" / "vault.db"


@dataclass(frozen=True)
class GitHubUnlockInfo:
    github_user_id: int
    github_login: str
    client_id: str


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
    expires_at: str | None = None
    rotation_url: str | None = None


@dataclass(frozen=True)
class Secret(SecretMetadata):
    value: str = ""


@dataclass(frozen=True)
class AttachmentInput:
    name: str
    filename: str
    content: bytes
    project: str = "default"
    environment: str = "default"
    content_type: str = "application/octet-stream"
    notes: str = ""


@dataclass(frozen=True)
class AttachmentMetadata:
    id: int
    name: str
    filename: str
    project: str
    environment: str
    content_type: str
    notes: str
    size: int
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class Attachment(AttachmentMetadata):
    content: bytes = b""


@dataclass(frozen=True)
class PasswordInput:
    name: str
    url: str
    username: str
    password: str
    note: str = ""


@dataclass(frozen=True)
class PasswordMetadata:
    id: int
    name: str
    url: str
    username: str
    note: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class Password(PasswordMetadata):
    password: str = ""


@dataclass(frozen=True)
class CredentialTransferSummary:
    secrets: int = 0
    passwords: int = 0


@dataclass(frozen=True)
class VaultInitSetup:
    totp_secret: str | None = None
    otpauth_uri: str | None = None
    recovery_codes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AuditEvent:
    id: int
    action: str
    secret_name: str | None
    project: str | None
    environment: str | None
    status: str
    message: str
    created_at: str


@dataclass(frozen=True)
class ProjectProfile:
    project: str
    environment: str
    required_secrets: list[str]
    notes: str
    updated_at: str


class VaultStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path).expanduser()
        self._fernet: Fernet | None = None
        self._vault_key: bytes | None = None

    @property
    def is_unlocked(self) -> bool:
        return self._fernet is not None

    def init(
        self,
        password: str,
        *,
        enable_two_factor: bool = False,
        recovery_code_count: int = 8,
    ) -> VaultInitSetup:
        if enable_two_factor and not 1 <= recovery_code_count <= 20:
            raise ValueError("recovery_code_count must be between 1 and 20")
        if self.db_path.exists():
            with self._connect() as conn:
                if self._has_schema(conn):
                    raise VaultAlreadyExists(f"Vault already exists at {self.db_path}")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        now = self._now()
        vault_key = Fernet.generate_key()
        master_wrap = Fernet(self._derive_key(password, salt)).encrypt(vault_key).decode()
        setup = VaultInitSetup()
        with self._connect() as conn:
            self._create_schema(conn)
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("kdf_salt", base64.b64encode(salt).decode()))
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("encryption_scheme", "v2"))
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("master_wrap", master_wrap))
            if enable_two_factor:
                totp_secret = self._generate_totp_secret()
                setup = VaultInitSetup(
                    totp_secret=totp_secret,
                    otpauth_uri=self._build_otpauth_uri(totp_secret),
                    recovery_codes=[],
                )
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                    ("totp_secret", Fernet(vault_key).encrypt(totp_secret.encode()).decode()),
                )
                recovery_codes = self._store_recovery_codes(conn, vault_key, recovery_code_count, now)
                setup = VaultInitSetup(totp_secret=totp_secret, otpauth_uri=self._build_otpauth_uri(totp_secret), recovery_codes=recovery_codes)
        os.chmod(self.db_path, 0o600)
        self._fernet = Fernet(vault_key)
        self._vault_key = vault_key
        return setup

    def unlock(self, password: str | None = None, *, totp_code: str | None = None, recovery_code: str | None = None) -> None:
        self._ensure_initialized()
        with self._connect() as conn:
            self._migrate_schema(conn)
            scheme = self._meta(conn, "encryption_scheme") if self._has_meta_key(conn, "encryption_scheme") else "v1"
            if recovery_code:
                if scheme != "v2":
                    raise VaultLocked("Recovery codes are not available for this vault")
                normalized_code = self._normalize_recovery_code(recovery_code)
                code_hash = hashlib.sha256(normalized_code.encode()).hexdigest()
                row = conn.execute(
                    """
                    SELECT id, salt, wrapped_vault_key
                    FROM recovery_codes
                    WHERE code_hash=? AND used_at IS NULL
                    """,
                    (code_hash,),
                ).fetchone()
                if row is None:
                    raise VaultLocked("Invalid recovery code")
                try:
                    vault_key = Fernet(self._derive_key(normalized_code, base64.b64decode(str(row["salt"])))).decrypt(str(row["wrapped_vault_key"]).encode())
                except InvalidToken as exc:
                    raise VaultLocked("Invalid recovery code") from exc
                cur = conn.execute("UPDATE recovery_codes SET used_at=? WHERE id=? AND used_at IS NULL", (self._now(), int(row["id"])))
                if cur.rowcount != 1:
                    raise VaultLocked("Invalid recovery code")
                self._fernet = Fernet(vault_key)
                self._vault_key = vault_key
                return
            if password is None:
                raise VaultLocked("Missing master password")
            if scheme == "v1":
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
                self._vault_key = self._derive_key(password, salt)
                return
            salt_b64 = self._meta(conn, "kdf_salt")
            master_wrap = self._meta(conn, "master_wrap")
            salt = base64.b64decode(salt_b64)
            try:
                vault_key = Fernet(self._derive_key(password, salt)).decrypt(master_wrap.encode())
            except InvalidToken as exc:
                raise VaultLocked("Wrong master password") from exc
            data_fernet = Fernet(vault_key)
            if self._has_meta_key(conn, "totp_secret"):
                if not totp_code:
                    raise VaultLocked("Missing TOTP code")
                secret = data_fernet.decrypt(self._meta(conn, "totp_secret").encode()).decode()
                if not self._verify_totp(secret, totp_code):
                    raise VaultLocked("Invalid TOTP code")
            self._fernet = data_fernet
            self._vault_key = vault_key

    def enable_two_factor(self, password: str, *, recovery_code_count: int = 8) -> VaultInitSetup:
        vault_key = self.current_vault_key()
        if not 1 <= recovery_code_count <= 20:
            raise ValueError("recovery_code_count must be between 1 and 20")
        with self._connect() as conn:
            self._migrate_schema(conn)
            if self._has_meta_key(conn, "totp_secret"):
                raise ValueError("Two-factor unlock is already enabled")
            salt = base64.b64decode(self._meta(conn, "kdf_salt"))
            self._verify_master_password_for_update(conn, password, salt, vault_key)
            totp_secret = self._generate_totp_secret()
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("encryption_scheme", "v2"))
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("master_wrap", Fernet(self._derive_key(password, salt)).encrypt(vault_key).decode()),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("totp_secret", Fernet(vault_key).encrypt(totp_secret.encode()).decode()),
            )
            conn.execute("DELETE FROM recovery_codes")
            recovery_codes = self._store_recovery_codes(conn, vault_key, recovery_code_count, self._now())
        return VaultInitSetup(totp_secret=totp_secret, otpauth_uri=self._build_otpauth_uri(totp_secret), recovery_codes=recovery_codes)

    def regenerate_recovery_codes(self, *, recovery_code_count: int = 8) -> list[str]:
        vault_key = self.current_vault_key()
        if not 1 <= recovery_code_count <= 20:
            raise ValueError("recovery_code_count must be between 1 and 20")
        with self._connect() as conn:
            self._migrate_schema(conn)
            if not self._has_meta_key(conn, "totp_secret"):
                raise ValueError("Two-factor unlock is not enabled")
            conn.execute("DELETE FROM recovery_codes")
            return self._store_recovery_codes(conn, vault_key, recovery_code_count, self._now())

    def rotate_totp_secret(self) -> VaultInitSetup:
        vault_key = self.current_vault_key()
        with self._connect() as conn:
            self._migrate_schema(conn)
            if not self._has_meta_key(conn, "totp_secret"):
                raise ValueError("Two-factor unlock is not enabled")
            totp_secret = self._generate_totp_secret()
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("totp_secret", Fernet(vault_key).encrypt(totp_secret.encode()).decode()),
            )
        return VaultInitSetup(totp_secret=totp_secret, otpauth_uri=self._build_otpauth_uri(totp_secret), recovery_codes=[])

    def disable_two_factor(self, password: str) -> None:
        vault_key = self.current_vault_key()
        with self._connect() as conn:
            self._migrate_schema(conn)
            salt = base64.b64decode(self._meta(conn, "kdf_salt"))
            self._verify_master_password_for_update(conn, password, salt, vault_key)
            conn.execute("DELETE FROM meta WHERE key=?", ("totp_secret",))
            conn.execute("DELETE FROM recovery_codes")

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
                SELECT id, name, project, environment, encrypted_value, tags, notes, created_at, updated_at, expires_at, rotation_url
                FROM secrets WHERE name=? AND project=? AND environment=?
                """,
                (name, project, environment),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_secret(row, fernet)

    def list_secrets(
        self,
        project: str | None = None,
        environment: str | None = None,
        query: str | None = None,
        tags: list[str] | None = None,
    ) -> list[SecretMetadata]:
        self._require_unlocked()
        clauses = []
        params = []
        if project is not None:
            clauses.append("project=?")
            params.append(project)
        if environment is not None:
            clauses.append("environment=?")
            params.append(environment)
        if query:
            clauses.append("LOWER(name) LIKE ?")
            params.append(f"%{query.lower()}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, name, project, environment, tags, notes, created_at, updated_at, expires_at, rotation_url
                FROM secrets {where} ORDER BY project, environment, name
                """,
                params,
            ).fetchall()
        metadata = [self._row_to_metadata(row) for row in rows]
        required_tags = set(tags or [])
        if required_tags:
            metadata = [item for item in metadata if required_tags.issubset(set(item.tags))]
        return metadata

    def delete_secret(self, name: str, project: str = "default", environment: str = "default") -> bool:
        self._require_unlocked()
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM secrets WHERE name=? AND project=? AND environment=?", (name, project, environment))
        return cur.rowcount > 0

    def list_service_names(self) -> list[str]:
        self._require_unlocked()
        items = self.list_secrets(tags=["service"])
        seen: set[str] = set()
        names: list[str] = []
        for item in items:
            if item.project not in seen:
                seen.add(item.project)
                names.append(item.project)
        return sorted(names)

    def delete_service(self, service: str) -> int:
        self._require_unlocked()
        fields = self.list_secrets(project=service, tags=["service"])
        count = 0
        for field in fields:
            if self.delete_secret(field.name, project=field.project, environment=field.environment):
                count += 1
        return count

    def add_password(self, password: PasswordInput) -> None:
        fernet = self._require_unlocked()
        now = self._now()
        encrypted_password = fernet.encrypt(password.password.encode()).decode()
        with self._connect() as conn:
            self._migrate_schema(conn)
            conn.execute(
                """
                INSERT INTO passwords(name, url, username, encrypted_password, note, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, url, username) DO UPDATE SET
                    encrypted_password=excluded.encrypted_password,
                    note=excluded.note,
                    updated_at=excluded.updated_at
                """,
                (password.name, password.url, password.username, encrypted_password, password.note, now, now),
            )

    def list_passwords(self, query: str | None = None) -> list[PasswordMetadata]:
        self._require_unlocked()
        clauses = []
        params: list[object] = []
        if query:
            clauses.append("LOWER(name || ' ' || url || ' ' || username || ' ' || note) LIKE ?")
            params.append(f"%{query.lower()}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            self._migrate_schema(conn)
            rows = conn.execute(
                f"""
                SELECT id, name, url, username, note, created_at, updated_at
                FROM passwords {where} ORDER BY name, url, username
                """,
                params,
            ).fetchall()
        return [self._row_to_password_metadata(row) for row in rows]

    def delete_password(self, name: str, url: str, username: str) -> bool:
        self._require_unlocked()
        with self._connect() as conn:
            self._migrate_schema(conn)
            cur = conn.execute("DELETE FROM passwords WHERE name=? AND url=? AND username=?", (name, url, username))
        return cur.rowcount > 0

    def get_password(self, name: str, url: str, username: str) -> Password | None:
        fernet = self._require_unlocked()
        with self._connect() as conn:
            self._migrate_schema(conn)
            row = conn.execute(
                """
                SELECT id, name, url, username, encrypted_password, note, created_at, updated_at
                FROM passwords WHERE name=? AND url=? AND username=?
                """,
                (name, url, username),
            ).fetchone()
        if row is None:
            return None
        return Password(password=fernet.decrypt(row["encrypted_password"].encode()).decode(), **self._row_to_password_metadata(row).__dict__)

    def add_attachment(self, attachment: AttachmentInput) -> None:
        fernet = self._require_unlocked()
        now = self._now()
        encrypted_content = fernet.encrypt(attachment.content).decode()
        with self._connect() as conn:
            self._migrate_schema(conn)
            conn.execute(
                """
                INSERT INTO attachments(name, filename, project, environment, encrypted_content, content_type, notes, size, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, project, environment) DO UPDATE SET
                    filename=excluded.filename,
                    encrypted_content=excluded.encrypted_content,
                    content_type=excluded.content_type,
                    notes=excluded.notes,
                    size=excluded.size,
                    updated_at=excluded.updated_at
                """,
                (
                    attachment.name,
                    attachment.filename,
                    attachment.project,
                    attachment.environment,
                    encrypted_content,
                    attachment.content_type,
                    attachment.notes,
                    len(attachment.content),
                    now,
                    now,
                ),
            )

    def list_attachments(
        self,
        project: str | None = None,
        environment: str | None = None,
        query: str | None = None,
    ) -> list[AttachmentMetadata]:
        self._require_unlocked()
        clauses = []
        params = []
        if project is not None:
            clauses.append("project=?")
            params.append(project)
        if environment is not None:
            clauses.append("environment=?")
            params.append(environment)
        if query:
            clauses.append("LOWER(name) LIKE ?")
            params.append(f"%{query.lower()}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            self._migrate_schema(conn)
            rows = conn.execute(
                f"""
                SELECT id, name, filename, project, environment, content_type, notes, size, created_at, updated_at
                FROM attachments {where} ORDER BY project, environment, name
                """,
                params,
            ).fetchall()
        return [self._row_to_attachment_metadata(row) for row in rows]

    def delete_attachment(self, name: str, project: str = "default", environment: str = "default") -> bool:
        self._require_unlocked()
        with self._connect() as conn:
            self._migrate_schema(conn)
            cur = conn.execute("DELETE FROM attachments WHERE name=? AND project=? AND environment=?", (name, project, environment))
        return cur.rowcount > 0

    def get_attachment(self, name: str, project: str = "default", environment: str = "default") -> Attachment | None:
        fernet = self._require_unlocked()
        with self._connect() as conn:
            self._migrate_schema(conn)
            row = conn.execute(
                """
                SELECT id, name, filename, project, environment, encrypted_content, content_type, notes, size, created_at, updated_at
                FROM attachments WHERE name=? AND project=? AND environment=?
                """,
                (name, project, environment),
            ).fetchone()
        if row is None:
            return None
        content = fernet.decrypt(row["encrypted_content"].encode())
        return Attachment(content=content, **self._row_to_attachment_metadata(row).__dict__)

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

    def import_env_file(
        self,
        path: str | Path,
        project: str = "default",
        environment: str = "default",
        tags: list[str] | None = None,
    ) -> list[str]:
        parsed = parse_env_file(path)
        for name, value in parsed.items():
            self.add_secret(SecretInput(name=name, value=value, project=project, environment=environment, tags=tags or []))
        return sorted(parsed.keys())

    def export_credentials(self, path: str | Path) -> CredentialTransferSummary:
        self._require_unlocked()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "kind",
            "name",
            "project",
            "environment",
            "url",
            "username",
            "value",
            "note",
            "tags",
            "expires_at",
            "rotation_url",
            "created_at",
            "updated_at",
        ]
        secret_count = 0
        password_count = 0
        rows: list[dict[str, str]] = []
        for item in self.list_secrets():
            secret = self.get_secret(item.name, project=item.project, environment=item.environment)
            if secret is None:
                continue
            rows.append(
                {
                    "kind": "secret",
                    "name": secret.name,
                    "project": secret.project,
                    "environment": secret.environment,
                    "url": "",
                    "username": "",
                    "value": secret.value,
                    "note": secret.notes,
                    "tags": json.dumps(secret.tags, ensure_ascii=False),
                    "expires_at": secret.expires_at or "",
                    "rotation_url": secret.rotation_url or "",
                    "created_at": secret.created_at,
                    "updated_at": secret.updated_at,
                }
            )
            secret_count += 1
        for item in self.list_passwords():
            password = self.get_password(item.name, url=item.url, username=item.username)
            if password is None:
                continue
            rows.append(
                {
                    "kind": "password",
                    "name": password.name,
                    "project": "",
                    "environment": "",
                    "url": password.url,
                    "username": password.username,
                    "value": password.password,
                    "note": password.note,
                    "tags": "",
                    "expires_at": "",
                    "rotation_url": "",
                    "created_at": password.created_at,
                    "updated_at": password.updated_at,
                }
            )
            password_count += 1
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return CredentialTransferSummary(secrets=secret_count, passwords=password_count)

    def import_credentials(self, path: str | Path) -> CredentialTransferSummary:
        self._require_unlocked()
        path = Path(path)
        if path.suffix.lower() != ".csv":
            raise ValueError("Only .csv credential files are supported")
        secret_count = 0
        password_count = 0
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise ValueError("Missing CSV header")
            for row in reader:
                kind = (row.get("kind") or row.get("type") or "").strip().lower()
                if not kind:
                    kind = "password" if (row.get("url") or row.get("username")) else "secret"
                if kind == "secret":
                    tags_text = (row.get("tags") or "[]").strip()
                    tags = json.loads(tags_text) if tags_text else []
                    if not isinstance(tags, list):
                        raise ValueError("tags must be a JSON array")
                    project = (row.get("project") or "default").strip() or "default"
                    environment = (row.get("environment") or "default").strip() or "default"
                    name = (row.get("name") or "").strip()
                    value = row.get("value") or ""
                    note = row.get("note") or ""
                    self.add_secret(SecretInput(name=name, value=value, project=project, environment=environment, tags=[str(tag) for tag in tags], notes=note))
                    expires_at = (row.get("expires_at") or "").strip() or None
                    rotation_url = (row.get("rotation_url") or "").strip() or None
                    if expires_at or rotation_url:
                        self.set_secret_metadata(name, project=project, environment=environment, expires_at=expires_at, rotation_url=rotation_url)
                    secret_count += 1
                elif kind == "password":
                    url = (row.get("url") or "").strip()
                    username = (row.get("username") or "").strip()
                    name = (row.get("name") or "").strip()
                    if not name and url:
                        from urllib.parse import urlparse
                        try:
                            name = urlparse(url).netloc or url
                        except Exception:
                            name = url
                    value = row.get("value") or row.get("password") or ""
                    note = row.get("note") or ""
                    self.add_password(PasswordInput(name=name, url=url, username=username, password=value, note=note))
                    password_count += 1
                else:
                    raise ValueError(f"Unsupported credential kind: {kind}")
        return CredentialTransferSummary(secrets=secret_count, passwords=password_count)

    def set_secret_metadata(
        self,
        name: str,
        project: str = "default",
        environment: str = "default",
        expires_at: str | None = None,
        rotation_url: str | None = None,
    ) -> bool:
        self._require_unlocked()
        with self._connect() as conn:
            self._migrate_schema(conn)
            cur = conn.execute(
                """
                UPDATE secrets
                SET expires_at=COALESCE(?, expires_at),
                    rotation_url=COALESCE(?, rotation_url),
                    updated_at=?
                WHERE name=? AND project=? AND environment=?
                """,
                (expires_at, rotation_url, self._now(), name, project, environment),
            )
        return cur.rowcount > 0

    def set_project_profile(
        self,
        project: str,
        environment: str,
        required_secrets: list[str],
        notes: str = "",
    ) -> None:
        self._require_unlocked()
        normalized = sorted(dict.fromkeys(name.strip() for name in required_secrets if name.strip()))
        now = self._now()
        with self._connect() as conn:
            self._migrate_schema(conn)
            conn.execute(
                """
                INSERT INTO project_profiles(project, environment, required_secrets, notes, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(project, environment) DO UPDATE SET
                    required_secrets=excluded.required_secrets,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at
                """,
                (project, environment, json.dumps(normalized), notes, now),
            )

    def list_project_profiles(self, project: str | None = None, environment: str | None = None) -> list[ProjectProfile]:
        self._require_unlocked()
        clauses = []
        params: list[object] = []
        if project is not None:
            clauses.append("project=?")
            params.append(project)
        if environment is not None:
            clauses.append("environment=?")
            params.append(environment)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            self._migrate_schema(conn)
            rows = conn.execute(
                f"""
                SELECT project, environment, required_secrets, notes, updated_at
                FROM project_profiles {where} ORDER BY project, environment
                """,
                params,
            ).fetchall()
        return [
            ProjectProfile(
                project=str(row["project"]),
                environment=str(row["environment"]),
                required_secrets=json.loads(row["required_secrets"] or "[]"),
                notes=str(row["notes"]),
                updated_at=str(row["updated_at"]),
            )
            for row in rows
        ]

    def delete_project_profile(self, project: str, environment: str) -> bool:
        self._require_unlocked()
        with self._connect() as conn:
            self._migrate_schema(conn)
            cur = conn.execute("DELETE FROM project_profiles WHERE project=? AND environment=?", (project, environment))
        return cur.rowcount > 0

    def record_audit(
        self,
        action: str,
        secret_name: str | None = None,
        project: str | None = None,
        environment: str | None = None,
        status: str = "success",
        message: str = "",
    ) -> None:
        self._ensure_initialized()
        with self._connect() as conn:
            self._migrate_schema(conn)
            conn.execute(
                """
                INSERT INTO audit_events(action, secret_name, project, environment, status, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (action, secret_name, project, environment, status, message, self._now()),
            )

    def list_audit_events(self, action: str | None = None, limit: int = 50) -> list[AuditEvent]:
        self._ensure_initialized()
        clauses = []
        params: list[object] = []
        if action:
            clauses.append("action=?")
            params.append(action)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            self._migrate_schema(conn)
            rows = conn.execute(
                f"""
                SELECT id, action, secret_name, project, environment, status, message, created_at
                FROM audit_events {where} ORDER BY id DESC LIMIT ?
                """,
                params,
            ).fetchall()
        return [
            AuditEvent(
                id=int(row["id"]),
                action=str(row["action"]),
                secret_name=row["secret_name"],
                project=row["project"],
                environment=row["environment"],
                status=str(row["status"]),
                message=str(row["message"]),
                created_at=str(row["created_at"]),
            )
            for row in rows
        ]

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
                expires_at TEXT,
                rotation_url TEXT,
                UNIQUE(name, project, environment)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                secret_name TEXT,
                project TEXT,
                environment TEXT,
                status TEXT NOT NULL DEFAULT 'success',
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS project_profiles (
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                required_secrets TEXT NOT NULL DEFAULT '[]',
                notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                PRIMARY KEY(project, environment)
            );
            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                filename TEXT NOT NULL,
                project TEXT NOT NULL DEFAULT 'default',
                environment TEXT NOT NULL DEFAULT 'default',
                encrypted_content TEXT NOT NULL,
                content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                notes TEXT NOT NULL DEFAULT '',
                size INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(name, project, environment)
            );
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(name, url, username)
            );
            CREATE TABLE IF NOT EXISTS recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT NOT NULL UNIQUE,
                salt TEXT NOT NULL,
                wrapped_vault_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used_at TEXT
            );
            """
        )


    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        self._create_schema(conn)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(secrets)").fetchall()}
        if "expires_at" not in columns:
            conn.execute("ALTER TABLE secrets ADD COLUMN expires_at TEXT")
        if "rotation_url" not in columns:
            conn.execute("ALTER TABLE secrets ADD COLUMN rotation_url TEXT")

    def _has_schema(self, conn: sqlite3.Connection) -> bool:
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
        return row is not None

    def _ensure_initialized(self) -> None:
        if not self.db_path.exists():
            raise VaultNotInitialized(f"Vault does not exist at {self.db_path}")
        with self._connect() as conn:
            if not self._has_schema(conn):
                raise VaultNotInitialized(f"Vault is not initialized at {self.db_path}")

    def is_initialized(self) -> bool:
        if not self.db_path.exists():
            return False
        with self._connect() as conn:
            return self._has_schema(conn)

    def has_two_factor_enabled(self) -> bool:
        if not self.is_initialized():
            return False
        with self._connect() as conn:
            self._migrate_schema(conn)
            return self._has_meta_key(conn, "totp_secret")

    def enable_github_unlock(self, *, github_user_id: int, github_login: str, client_id: str) -> bytes:
        vault_key = self.current_vault_key()
        device_secret = Fernet.generate_key()
        github_wrap = Fernet(device_secret).encrypt(vault_key).decode()
        with self._connect() as conn:
            self._migrate_schema(conn)
            for key, value in (
                ("github_wrap", github_wrap),
                ("github_user_id", str(github_user_id)),
                ("github_login", github_login),
                ("github_client_id", client_id),
            ):
                conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))
            conn.commit()
        return device_secret

    def disable_github_unlock(self) -> None:
        with self._connect() as conn:
            self._migrate_schema(conn)
            conn.execute(
                "DELETE FROM meta WHERE key IN ('github_wrap', 'github_user_id', 'github_login', 'github_client_id')"
            )
            conn.commit()

    def github_unlock_info(self) -> GitHubUnlockInfo | None:
        if not self.is_initialized():
            return None
        with self._connect() as conn:
            self._migrate_schema(conn)
            if not self._has_meta_key(conn, "github_wrap"):
                return None
            return GitHubUnlockInfo(
                github_user_id=int(self._meta(conn, "github_user_id")),
                github_login=self._meta(conn, "github_login"),
                client_id=self._meta(conn, "github_client_id"),
            )

    def unlock_with_device_secret(self, device_secret: bytes) -> None:
        with self._connect() as conn:
            self._migrate_schema(conn)
            if not self._has_meta_key(conn, "github_wrap"):
                raise VaultLocked("GitHub unlock is not enabled for this vault")
            github_wrap = self._meta(conn, "github_wrap")
        try:
            vault_key = Fernet(device_secret).decrypt(github_wrap.encode())
        except (InvalidToken, ValueError) as exc:
            raise VaultLocked("Invalid GitHub device secret") from exc
        self.unlock_with_vault_key(vault_key)

    def _meta(self, conn: sqlite3.Connection, key: str) -> str:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            raise VaultNotInitialized(f"Missing metadata: {key}")
        return str(row["value"])

    def _has_meta_key(self, conn: sqlite3.Connection, key: str) -> bool:
        return conn.execute("SELECT 1 FROM meta WHERE key=?", (key,)).fetchone() is not None

    def _verify_master_password_for_update(self, conn: sqlite3.Connection, password: str, salt: bytes, vault_key: bytes) -> None:
        scheme = self._meta(conn, "encryption_scheme") if self._has_meta_key(conn, "encryption_scheme") else "v1"
        derived = self._derive_key(password, salt)
        try:
            if scheme == "v1":
                verifier = self._meta(conn, "verifier")
                if Fernet(derived).decrypt(verifier.encode()) != b"henry-vault-verifier-v1":
                    raise VaultLocked("Wrong master password")
            else:
                master_wrap = self._meta(conn, "master_wrap")
                if Fernet(derived).decrypt(master_wrap.encode()) != vault_key:
                    raise VaultLocked("Wrong master password")
        except InvalidToken as exc:
            raise VaultLocked("Wrong master password") from exc

    def _store_recovery_codes(self, conn: sqlite3.Connection, vault_key: bytes, recovery_code_count: int, now: str) -> list[str]:
        recovery_codes: list[str] = []
        for _ in range(recovery_code_count):
            code = self._generate_recovery_code()
            code_salt = os.urandom(16)
            normalized_code = self._normalize_recovery_code(code)
            code_key = Fernet(self._derive_key(normalized_code, code_salt))
            wrapped_vault_key = code_key.encrypt(vault_key).decode()
            conn.execute(
                """
                INSERT INTO recovery_codes(code_hash, salt, wrapped_vault_key, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    hashlib.sha256(normalized_code.encode()).hexdigest(),
                    base64.b64encode(code_salt).decode(),
                    wrapped_vault_key,
                    now,
                ),
            )
            recovery_codes.append(code)
        return recovery_codes

    def _generate_totp_secret(self) -> str:
        return base64.b32encode(os.urandom(20)).decode().rstrip("=")

    def _build_otpauth_uri(self, secret: str, account_name: str = "Henry Vault", issuer: str = "Henry Vault") -> str:
        label = quote(f"{issuer}:{account_name}")
        return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&digits=6&period=30"

    def _normalize_recovery_code(self, code: str) -> str:
        return "".join(character for character in code.upper() if character.isalnum())

    def _generate_recovery_code(self) -> str:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4))

    def _verify_totp(self, secret: str, code: str, window: int = 1) -> bool:
        normalized_code = "".join(character for character in code if character.isdigit())
        if len(normalized_code) != 6:
            return False
        padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(padded_secret, casefold=True)
        now = int(datetime.now(UTC).timestamp())
        for offset in range(-window, window + 1):
            counter = (now // 30) + offset
            digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
            dynamic_offset = digest[-1] & 0x0F
            value = struct.unpack(">I", digest[dynamic_offset:dynamic_offset + 4])[0] & 0x7FFFFFFF
            if f"{value % 1_000_000:06d}" == normalized_code:
                return True
        return False

    def _require_unlocked(self) -> Fernet:
        if self._fernet is None:
            raise VaultLocked("Vault is locked. Call unlock() first.")
        return self._fernet

    def current_vault_key(self) -> bytes:
        if self._vault_key is None:
            raise VaultLocked("Vault is locked. Call unlock() first.")
        return self._vault_key

    def unlock_with_vault_key(self, vault_key: bytes) -> None:
        self._fernet = Fernet(vault_key)
        self._vault_key = vault_key

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
            expires_at=row["expires_at"] if "expires_at" in row.keys() else None,
            rotation_url=row["rotation_url"] if "rotation_url" in row.keys() else None,
        )

    def _row_to_secret(self, row: sqlite3.Row, fernet: Fernet) -> Secret:
        value = fernet.decrypt(row["encrypted_value"].encode()).decode()
        return Secret(value=value, **self._row_to_metadata(row).__dict__)

    def _row_to_attachment_metadata(self, row: sqlite3.Row) -> AttachmentMetadata:
        return AttachmentMetadata(
            id=int(row["id"]),
            name=str(row["name"]),
            filename=str(row["filename"]),
            project=str(row["project"]),
            environment=str(row["environment"]),
            content_type=str(row["content_type"]),
            notes=str(row["notes"]),
            size=int(row["size"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def _row_to_password_metadata(self, row: sqlite3.Row) -> PasswordMetadata:
        return PasswordMetadata(
            id=int(row["id"]),
            name=str(row["name"]),
            url=str(row["url"]),
            username=str(row["username"]),
            note=str(row["note"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def _now(self) -> str:
        return datetime.now(UTC).isoformat(timespec="seconds")
