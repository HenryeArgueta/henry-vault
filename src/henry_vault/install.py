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
    password_file: str | Path,
) -> str:
    hv = shlex.quote(str(hv_executable))
    db = shlex.quote(str(db_path))
    backup = shlex.quote(str(backup_path))
    pw = shlex.quote(str(password_file))
    return f'HENRY_VAULT_PASSWORD="$(cat {pw})" {hv} --db {db} backup-export {backup} --backup-password "$(cat {pw})"'
