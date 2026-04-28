from __future__ import annotations

import getpass
import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer

from .backup import export_backup, import_backup
from .doctor import doctor_report
from .errors import VaultAlreadyExists, VaultError, VaultLocked, VaultNotInitialized
from .install import backup_schedule_command, install_cli
from .scanner import scan_path
from .store import DEFAULT_DB_PATH, SecretInput, VaultStore

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
def list_secrets(ctx: typer.Context, project: Annotated[Optional[str], typer.Option("--project")] = None, env: Annotated[Optional[str], typer.Option("--env")] = None) -> None:
    """List secret metadata without values."""
    store = _unlock(ctx.obj["db"])
    items = store.list_secrets(project=project, environment=env)
    store.record_audit("secret.list", project=project, environment=env, message=f"count={len(items)}")
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


@app.command("doctor")
def doctor(ctx: typer.Context, expiring_days: Annotated[int, typer.Option("--expiring-days", help="Days ahead to flag expiring secrets")] = 30) -> None:
    """Check vault hygiene: expirations and rotation metadata."""
    store = _unlock(ctx.obj["db"])
    report = doctor_report(store, expiring_days=expiring_days)
    if report.ok:
        typer.echo("Vault doctor: OK")
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
    password_file: Annotated[Path, typer.Option("--password-file", help="File containing vault/backup password")],
    hv_executable: Annotated[Path, typer.Option("--hv-executable", help="Path to hv executable")] = Path("hv"),
) -> None:
    """Print a cron-compatible encrypted backup command."""
    command = backup_schedule_command(hv_executable=hv_executable, db_path=ctx.obj["db"], backup_path=backup_path, password_file=password_file)
    typer.echo(command)


@app.command("run")
def run_command(
    ctx: typer.Context,
    command: Annotated[list[str], typer.Argument(help="Command to run after --")],
    project: Annotated[Optional[str], typer.Option("--project")] = None,
    env: Annotated[Optional[str], typer.Option("--env")] = None,
) -> None:
    """Run a command with matching secrets injected into its environment."""
    if not command:
        raise typer.BadParameter("Provide a command after --")
    store = _unlock(ctx.obj["db"])
    result = subprocess.run(command, env=store.environment(project=project, environment=env), check=False)
    raise typer.Exit(result.returncode)


@app.command("web")
def web(ctx: typer.Context, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Start the local web UI/API."""
    import uvicorn

    from .web import create_app

    uvicorn.run(create_app(ctx.obj["db"]), host=host, port=port)


if __name__ == "__main__":
    app()
