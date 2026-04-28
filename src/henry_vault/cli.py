from __future__ import annotations

import getpass
import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer

from .backup import export_backup, import_backup
from .errors import VaultAlreadyExists, VaultError, VaultLocked, VaultNotInitialized
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
    typer.echo(f"Saved {name} [{project}/{env}]")


@app.command("get")
def get_secret(ctx: typer.Context, name: str, project: ProjectOpt = "default", env: EnvOpt = "default") -> None:
    """Print one secret value."""
    store = _unlock(ctx.obj["db"])
    secret = store.get_secret(name, project=project, environment=env)
    if secret is None:
        raise typer.Exit(1)
    typer.echo(secret.value)


@app.command("list")
def list_secrets(ctx: typer.Context, project: Annotated[Optional[str], typer.Option("--project")] = None, env: Annotated[Optional[str], typer.Option("--env")] = None) -> None:
    """List secret metadata without values."""
    store = _unlock(ctx.obj["db"])
    items = store.list_secrets(project=project, environment=env)
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
    if not findings:
        typer.echo("No findings.")
        return
    for finding in findings:
        matched = f" matched={finding.matched_vault_name}" if finding.matched_vault_name else ""
        typer.echo(f"{finding.path}:{finding.line} {finding.kind}{matched} {finding.preview}")
    raise typer.Exit(2)


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
