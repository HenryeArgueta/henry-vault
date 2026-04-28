from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path


def install_cli(target_dir: str | Path | None = None, executable: str | Path | None = None, name: str = "hv") -> Path:
    target_dir = Path(target_dir).expanduser() if target_dir else Path.home() / ".local" / "bin"
    executable = Path(executable).expanduser() if executable else Path(sys.argv[0]).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    link = target_dir / name
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(executable)
    return link


def backup_schedule_command(
    hv_executable: str | Path,
    db_path: str | Path,
    backup_path: str | Path,
    vault_password_file: str | Path,
    backup_password_file: str | Path,
) -> str:
    hv = shlex.quote(str(hv_executable))
    db = shlex.quote(str(db_path))
    backup = shlex.quote(str(backup_path))
    vault_pw = shlex.quote(str(vault_password_file))
    backup_pw = shlex.quote(str(backup_password_file))
    return (
        f'HENRY_VAULT_PASSWORD="$(cat {vault_pw})" '
        f"{hv} --db {db} backup-export {backup} "
        f'--backup-password "$(cat {backup_pw})"'
    )
