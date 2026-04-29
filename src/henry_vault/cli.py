from __future__ import annotations

import getpass
import os
import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer

from .backup import export_backup, import_backup, prune_backups
from .doctor import doctor_report
from .errors import VaultAlreadyExists, VaultError, VaultLocked, VaultNotInitialized
from .install import backup_schedule_command, install_cli
from .scanner import scan_path
from .store import DEFAULT_DB_PATH, AttachmentInput, CredentialTransferSummary, PasswordInput, SecretInput, VaultStore

app = typer.Typer(help="Henry Vault: encrypted local secrets manager")


def _password() -> str:
    import os

    password = os.environ.get("HENRY_VAULT_PASSWORD")
    if password:
        return password
    return getpass.getpass("Master password: ")


def _backup_password(value: str | None = None) -> str:
    if value:
        return value
    return getpass.getpass("Backup password: ")


def _store(db: Path) -> VaultStore:
    return VaultStore(db)


def _unlock(db: Path) -> VaultStore:
    store = _store(db)
    store.unlock(_password())
    store.record_audit("vault.unlock", status="success")
    return store


DbOpt = Annotated[Path, typer.Option("--db", help="Vault database path")]
ProjectOpt = Annotated[str, typer.Option("--project", help="Project name")]
EnvOpt = Annotated[str, typer.Option("--env", help="Environment name")]


@app.callback()
def main(ctx: typer.Context, db: DbOpt = DEFAULT_DB_PATH) -> None:
    ctx.obj = {"db": db}


@app.command()
def init(ctx: typer.Context) -> None:
    """Initialize a new encrypted vault."""
    try:
        store = _store(ctx.obj["db"])
        store.init(_password())
        typer.echo(f"Initialized Henry Vault at {store.db_path}")
    except VaultAlreadyExists as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def add(
    ctx: typer.Context,
    name: str,
    value: Annotated[Optional[str], typer.Argument(help="Secret value. Omit to prompt hidden input.")] = None,
    project: ProjectOpt = "default",
    env: EnvOpt = "default",
    tag: Annotated[list[str], typer.Option("--tag", help="Tag for this secret")] = [],
    notes: Annotated[str, typer.Option("--notes", help="Notes for this secret")] = "",
) -> None:
    """Add or update a secret."""
    store = _unlock(ctx.obj["db"])
    if value is None:
        value = getpass.getpass(f"Value for {name}: ")
    store.add_secret(SecretInput(name=name, value=value, project=project, environment=env, tags=list(tag), notes=notes))
    store.record_audit("secret.add", secret_name=name, project=project, environment=env)
    typer.echo(f"Saved {name} [{project}/{env}]")


@app.command("get")
def get_secret(ctx: typer.Context, name: str, project: ProjectOpt = "default", env: EnvOpt = "default") -> None:
    """Print one secret value."""
    store = _unlock(ctx.obj["db"])
    secret = store.get_secret(name, project=project, environment=env)
    if secret is None:
        store.record_audit("secret.get", secret_name=name, project=project, environment=env, status="not_found")
        raise typer.Exit(1)
    store.record_audit("secret.get", secret_name=name, project=project, environment=env)
    typer.echo(secret.value)


@app.command("list")
def list_secrets(
    ctx: typer.Context,
    project: Annotated[Optional[str], typer.Option("--project")] = None,
    env: Annotated[Optional[str], typer.Option("--env")] = None,
    query: Annotated[Optional[str], typer.Option("--query", help="Case-insensitive secret name substring filter")] = None,
    tag: Annotated[list[str], typer.Option("--tag", help="Require this tag; repeat for multiple tags")] = [],
) -> None:
    """List secret metadata without values."""
    store = _unlock(ctx.obj["db"])
    items = store.list_secrets(project=project, environment=env, query=query, tags=list(tag))
    filters = []
    if query:
        filters.append(f"query={query}")
    if tag:
        filters.append(f"tags={','.join(tag)}")
    message = f"count={len(items)}"
    if filters:
        message = f"{message} {' '.join(filters)}"
    store.record_audit("secret.list", project=project, environment=env, message=message)
    if not items:
        typer.echo("No secrets found.")
        return
    for item in items:
        tags = ",".join(item.tags)
        typer.echo(f"{item.project}/{item.environment} {item.name} tags=[{tags}] updated={item.updated_at}")


@app.command("delete")
def delete_secret(ctx: typer.Context, name: str, project: ProjectOpt = "default", env: EnvOpt = "default") -> None:
    """Delete one secret."""
    store = _unlock(ctx.obj["db"])
    deleted = store.delete_secret(name, project=project, environment=env)
    typer.echo("Deleted" if deleted else "Not found")


@app.command("password-add")
def password_add(
    ctx: typer.Context,
    name: str,
    url: str,
    username: str,
    password: Annotated[Optional[str], typer.Argument(help="Password. Omit to prompt hidden input.")] = None,
    note: Annotated[str, typer.Option("--note", help="Note for this password entry")] = "",
) -> None:
    """Add or update a website password entry."""
    store = _unlock(ctx.obj["db"])
    if password is None:
        password = getpass.getpass(f"Password for {name} ({username}): ")
    store.add_password(PasswordInput(name=name, url=url, username=username, password=password, note=note))
    store.record_audit("password.add", secret_name=name, status="success", message=f"url={url} username={username}")
    typer.echo(f"Saved password {name} [{url}] username={username}")


@app.command("password-list")
def password_list(
    ctx: typer.Context,
    query: Annotated[Optional[str], typer.Option("--query", help="Case-insensitive filter for name/url/username/note")] = None,
) -> None:
    """List password entry metadata without revealing passwords."""
    store = _unlock(ctx.obj["db"])
    items = store.list_passwords(query=query)
    store.record_audit("password.list", message=f"count={len(items)}" + (f" query={query}" if query else ""))
    if not items:
        typer.echo("No passwords found.")
        return
    for item in items:
        typer.echo(f"{item.name} url={item.url} username={item.username} note={item.note} updated={item.updated_at}")


@app.command("password-get")
def password_get(ctx: typer.Context, name: str, url: str, username: str) -> None:
    """Print one password value."""
    store = _unlock(ctx.obj["db"])
    password = store.get_password(name, url=url, username=username)
    if password is None:
        store.record_audit("password.get", secret_name=name, status="not_found", message=f"url={url} username={username}")
        raise typer.Exit(1)
    store.record_audit("password.get", secret_name=name, message=f"url={url} username={username}")
    typer.echo(password.password)


@app.command("password-delete")
def password_delete(ctx: typer.Context, name: str, url: str, username: str) -> None:
    """Delete one password entry."""
    store = _unlock(ctx.obj["db"])
    deleted = store.delete_password(name, url=url, username=username)
    store.record_audit("password.delete", secret_name=name, status="success" if deleted else "not_found", message=f"url={url} username={username}")
    typer.echo("Deleted" if deleted else "Not found")


@app.command("attachment-add")
def attachment_add(
    ctx: typer.Context,
    name: str,
    path: Path,
    project: ProjectOpt = "default",
    env: EnvOpt = "default",
    content_type: Annotated[str, typer.Option("--content-type", help="Attachment MIME type")] = "application/octet-stream",
    notes: Annotated[str, typer.Option("--notes", help="Notes for this attachment")] = "",
) -> None:
    """Add or update an encrypted file attachment."""
    store = _unlock(ctx.obj["db"])
    content = path.read_bytes()
    store.add_attachment(
        AttachmentInput(
            name=name,
            filename=path.name,
            content=content,
            project=project,
            environment=env,
            content_type=content_type,
            notes=notes,
        )
    )
    store.record_audit("attachment.add", secret_name=name, project=project, environment=env, message=f"filename={path.name} size={len(content)}")
    typer.echo(f"Saved attachment {name} [{project}/{env}] filename={path.name} size={len(content)}")


@app.command("attachment-list")
def attachment_list(
    ctx: typer.Context,
    project: Annotated[Optional[str], typer.Option("--project")] = None,
    env: Annotated[Optional[str], typer.Option("--env")] = None,
) -> None:
    """List encrypted attachment metadata without content."""
    store = _unlock(ctx.obj["db"])
    items = store.list_attachments(project=project, environment=env)
    store.record_audit("attachment.list", project=project, environment=env, message=f"count={len(items)}")
    if not items:
        typer.echo("No attachments found.")
        return
    for item in items:
        typer.echo(f"{item.project}/{item.environment} {item.name} file={item.filename} type={item.content_type} size={item.size} updated={item.updated_at}")


@app.command("attachment-get")
def attachment_get(
    ctx: typer.Context,
    name: str,
    output_path: Path,
    project: ProjectOpt = "default",
    env: EnvOpt = "default",
) -> None:
    """Write one decrypted attachment to a file."""
    store = _unlock(ctx.obj["db"])
    attachment = store.get_attachment(name, project=project, environment=env)
    if attachment is None:
        store.record_audit("attachment.get", secret_name=name, project=project, environment=env, status="not_found")
        raise typer.Exit(1)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(attachment.content)
    store.record_audit("attachment.get", secret_name=name, project=project, environment=env, message=f"filename={attachment.filename} size={attachment.size}")
    typer.echo(f"Wrote attachment {name} to {output_path}")


@app.command("export-env")
def export_env(ctx: typer.Context, project: Annotated[Optional[str], typer.Option("--project")] = None, env: Annotated[Optional[str], typer.Option("--env")] = None) -> None:
    """Print shell export lines for matching secrets."""
    store = _unlock(ctx.obj["db"])
    typer.echo(store.export_env(project=project, environment=env))


@app.command("import-env")
def import_env(
    ctx: typer.Context,
    path: Path,
    project: ProjectOpt = "default",
    env: EnvOpt = "default",
    tag: Annotated[list[str], typer.Option("--tag", help="Tag for imported secrets")] = [],
) -> None:
    """Import KEY=VALUE pairs from a .env file."""
    store = _unlock(ctx.obj["db"])
    imported = store.import_env_file(path, project=project, environment=env, tags=list(tag))
    typer.echo(f"Imported {len(imported)} secrets into {project}/{env}")


@app.command("export-credentials")
def export_credentials(ctx: typer.Context, path: Path) -> None:
    """Export secrets and passwords to a single CSV file."""
    store = _unlock(ctx.obj["db"])
    summary = store.export_credentials(path)
    store.record_audit("credentials.export", message=f"path={path.name} secrets={summary.secrets} passwords={summary.passwords}")
    typer.echo(f"Exported {summary.secrets} secrets and {summary.passwords} passwords to {path}")


@app.command("import-credentials")
def import_credentials(ctx: typer.Context, path: Path) -> None:
    """Import secrets and passwords from a single CSV file."""
    store = _unlock(ctx.obj["db"])
    summary = store.import_credentials(path)
    store.record_audit("credentials.import", message=f"path={path.name} secrets={summary.secrets} passwords={summary.passwords}")
    typer.echo(f"Imported {summary.secrets} secrets and {summary.passwords} passwords from {path}")


@app.command("backup-export")
def backup_export(
    ctx: typer.Context,
    path: Path,
    backup_password: Annotated[Optional[str], typer.Option("--backup-password", help="Backup encryption password")] = None,
) -> None:
    """Export all secrets to an encrypted backup bundle."""
    store = _unlock(ctx.obj["db"])
    export_backup(store, path, backup_password=_backup_password(backup_password))
    typer.echo(f"Encrypted backup written to {path}")


@app.command("backup-import")
def backup_import(
    ctx: typer.Context,
    path: Path,
    backup_password: Annotated[Optional[str], typer.Option("--backup-password", help="Backup encryption password")] = None,
) -> None:
    """Import secrets from an encrypted backup bundle into the unlocked vault."""
    store = _unlock(ctx.obj["db"])
    count = import_backup(store, path, backup_password=_backup_password(backup_password))
    typer.echo(f"Imported {count} secrets from {path}")


@app.command("backup-prune")
def backup_prune(
    backup_dir: Path,
    keep_days: Annotated[int, typer.Option("--keep-days", help="Delete backups older than this many days")] = 30,
    delete: Annotated[bool, typer.Option("--delete", help="Actually delete files. Without this, performs a dry run.")] = False,
) -> None:
    """Prune old Henry Vault backup files safely. Dry-run by default."""
    result = prune_backups(backup_dir, keep_days=keep_days, dry_run=not delete)
    action = "Deleted" if delete else "Would delete"
    noun = "backup" if len(result.items) == 1 else "backups"
    typer.echo(f"{action} {len(result.items)} {noun} older than {keep_days} days")
    for item in result.items:
        typer.echo(f"{item.path} age_days={item.age_days}")


@app.command("scan")
def scan(
    ctx: typer.Context,
    path: Path,
    match_vault: Annotated[bool, typer.Option("--match-vault", help="Match files against current vault secret values")] = False,
) -> None:
    """Scan files for likely leaked secrets without printing full values."""
    known = None
    if match_vault:
        store = _unlock(ctx.obj["db"])
        known = store.secrets_dict()
    findings = scan_path(path, known_secret_values=known)
    if match_vault:
        store.record_audit("scan.run", status="findings" if findings else "success", message=f"path={path} count={len(findings)}")
    if not findings:
        typer.echo("No findings.")
        return
    for finding in findings:
        matched = f" matched={finding.matched_vault_name}" if finding.matched_vault_name else ""
        typer.echo(f"{finding.path}:{finding.line} {finding.kind}{matched} {finding.preview}")
    raise typer.Exit(2)


@app.command("audit")
def audit(ctx: typer.Context, limit: Annotated[int, typer.Option("--limit", help="Maximum events to show")] = 50) -> None:
    """List recent audit events without secret values."""
    store = _unlock(ctx.obj["db"])
    events = store.list_audit_events(limit=limit)
    for event in events:
        subject = event.secret_name or "-"
        scope = f"{event.project or '-'}/{event.environment or '-'}"
        typer.echo(f"{event.created_at} {event.action} {event.status} {scope} {subject} {event.message}")


@app.command("set-metadata")
def set_metadata(
    ctx: typer.Context,
    name: str,
    project: ProjectOpt = "default",
    env: EnvOpt = "default",
    expires_at: Annotated[Optional[str], typer.Option("--expires-at", help="Expiry date, e.g. YYYY-MM-DD")] = None,
    rotation_url: Annotated[Optional[str], typer.Option("--rotation-url", help="Rotation URL or instructions link")] = None,
) -> None:
    """Set rotation metadata for one secret."""
    store = _unlock(ctx.obj["db"])
    updated = store.set_secret_metadata(name, project=project, environment=env, expires_at=expires_at, rotation_url=rotation_url)
    if not updated:
        raise typer.Exit(1)
    store.record_audit("secret.metadata", secret_name=name, project=project, environment=env)
    typer.echo(f"Updated metadata for {name} [{project}/{env}]")


@app.command("rotate")
def rotate_secret(
    ctx: typer.Context,
    name: str,
    value: Annotated[Optional[str], typer.Argument(help="New secret value. Omit to prompt hidden input.")] = None,
    project: ProjectOpt = "default",
    env: EnvOpt = "default",
    expires_at: Annotated[Optional[str], typer.Option("--expires-at", help="New expiry date, e.g. YYYY-MM-DD")] = None,
    rotation_url: Annotated[Optional[str], typer.Option("--rotation-url", help="Rotation URL or instructions link")] = None,
) -> None:
    """Rotate an existing secret value without printing it."""
    store = _unlock(ctx.obj["db"])
    existing = store.get_secret(name, project=project, environment=env)
    if existing is None:
        store.record_audit("secret.rotate", secret_name=name, project=project, environment=env, status="not_found")
        raise typer.Exit(1)
    if value is None:
        value = getpass.getpass(f"New value for {name}: ")
    store.add_secret(SecretInput(name=name, value=value, project=project, environment=env, tags=existing.tags, notes=existing.notes))
    if expires_at is not None or rotation_url is not None:
        store.set_secret_metadata(name, project=project, environment=env, expires_at=expires_at, rotation_url=rotation_url)
    store.record_audit("secret.rotate", secret_name=name, project=project, environment=env)
    typer.echo(f"Rotated {name} [{project}/{env}]")


@app.command("profile-set")
def profile_set(
    ctx: typer.Context,
    project: ProjectOpt = "default",
    env: EnvOpt = "default",
    required: Annotated[list[str], typer.Option("--required", help="Required secret name for this project/env")] = [],
    notes: Annotated[str, typer.Option("--notes", help="Notes for this profile")] = "",
) -> None:
    """Create or replace a project/environment required-secret profile."""
    store = _unlock(ctx.obj["db"])
    store.set_project_profile(project, env, required_secrets=list(required), notes=notes)
    store.record_audit("profile.set", project=project, environment=env, message=f"required_count={len(set(required))}")
    typer.echo(f"Saved profile {project}/{env}")


@app.command("profile-list")
def profile_list(
    ctx: typer.Context,
    project: Annotated[Optional[str], typer.Option("--project", help="Only list this project")] = None,
    env: Annotated[Optional[str], typer.Option("--env", help="Only list this environment")] = None,
) -> None:
    """List project/environment required-secret profiles."""
    store = _unlock(ctx.obj["db"])
    profiles = store.list_project_profiles(project=project, environment=env)
    store.record_audit("profile.list", project=project, environment=env, message=f"count={len(profiles)}")
    if not profiles:
        typer.echo("No profiles found.")
        return
    for profile in profiles:
        required = ",".join(profile.required_secrets)
        typer.echo(f"{profile.project}/{profile.environment} required=[{required}] updated={profile.updated_at}")


@app.command("profile-delete")
def profile_delete(ctx: typer.Context, project: ProjectOpt = "default", env: EnvOpt = "default") -> None:
    """Delete one project/environment profile."""
    store = _unlock(ctx.obj["db"])
    deleted = store.delete_project_profile(project, env)
    store.record_audit("profile.delete", project=project, environment=env, status="success" if deleted else "not_found")
    typer.echo("Deleted" if deleted else "Not found")


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    expiring_days: Annotated[int, typer.Option("--expiring-days", help="Days ahead to flag expiring secrets")] = 30,
    project: Annotated[Optional[str], typer.Option("--project", help="Only check this project")] = None,
    env: Annotated[Optional[str], typer.Option("--env", help="Only check this environment")] = None,
) -> None:
    """Check vault hygiene: expirations and rotation metadata."""
    store = _unlock(ctx.obj["db"])
    report = doctor_report(store, expiring_days=expiring_days, project=project, environment=env)
    if report.ok:
        scope = f" [{project or '*'}/{env or '*'}]" if project or env else ""
        typer.echo(f"Vault doctor{scope}: OK")
        return
    for issue in report.issues:
        typer.echo(f"{issue.severity} {issue.code} {issue.project}/{issue.environment} {issue.secret_name}: {issue.message}")
    raise typer.Exit(1)


@app.command("install-cli")
def install_cli_command(
    target_dir: Annotated[Optional[Path], typer.Option("--target-dir", help="Directory to place symlink, default ~/.local/bin")] = None,
    name: Annotated[str, typer.Option("--name", help="Command name to install")] = "hv",
) -> None:
    """Install an hv symlink into your user bin directory."""
    link = install_cli(target_dir=target_dir, name=name)
    typer.echo(f"Installed {name} -> {link}")


@app.command("backup-schedule-command")
def backup_schedule_command_cli(
    ctx: typer.Context,
    backup_path: Annotated[Path, typer.Option("--backup-path", help="Encrypted backup output path")],
    vault_password_file: Annotated[Optional[Path], typer.Option("--vault-password-file", help="File containing vault unlock password")] = None,
    backup_password_file: Annotated[Optional[Path], typer.Option("--backup-password-file", help="File containing backup encryption password")] = None,
    password_file: Annotated[Optional[Path], typer.Option("--password-file", help="Deprecated: use the same file for vault and backup passwords")] = None,
    hv_executable: Annotated[Path, typer.Option("--hv-executable", help="Path to hv executable")] = Path("hv"),
) -> None:
    """Print a cron-compatible encrypted backup command."""
    vault_file = vault_password_file or password_file
    backup_file = backup_password_file or password_file
    if vault_file is None or backup_file is None:
        raise typer.BadParameter("Provide --vault-password-file and --backup-password-file, or deprecated --password-file")
    command = backup_schedule_command(
        hv_executable=hv_executable,
        db_path=ctx.obj["db"],
        backup_path=backup_path,
        vault_password_file=vault_file,
        backup_password_file=backup_file,
    )
    typer.echo(command)


@app.command("run")
def run_command(
    ctx: typer.Context,
    command: Annotated[list[str], typer.Argument(help="Command to run after --")],
    project: Annotated[Optional[str], typer.Option("--project")] = None,
    env: Annotated[Optional[str], typer.Option("--env")] = None,
    allow_missing: Annotated[bool, typer.Option("--allow-missing", help="Run even when required profile secrets are missing")] = False,
) -> None:
    """Run a command with matching secrets injected into its environment."""
    if not command:
        raise typer.BadParameter("Provide a command after --")
    store = _unlock(ctx.obj["db"])
    secrets = store.secrets_dict(project=project, environment=env)
    if project is not None and env is not None and not allow_missing:
        profiles = store.list_project_profiles(project=project, environment=env)
        if profiles:
            required = profiles[0].required_secrets
            missing = sorted(name for name in required if name not in secrets)
            if missing:
                message = f"missing={','.join(missing)}"
                store.record_audit("run.blocked", project=project, environment=env, status="missing_required", message=message)
                typer.echo(f"Missing required secrets for {project}/{env}: {', '.join(missing)}")
                raise typer.Exit(1)
    command_env = dict(os.environ)
    command_env.update(secrets)
    result = subprocess.run(command, env=command_env, check=False)
    raise typer.Exit(result.returncode)


@app.command("web")
def web(ctx: typer.Context, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Start the local web UI/API."""
    import uvicorn

    from .web import create_app

    uvicorn.run(create_app(ctx.obj["db"]), host=host, port=port)


if __name__ == "__main__":
    app()
