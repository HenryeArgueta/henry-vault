from pathlib import Path

from henry_vault.install import install_cli, backup_schedule_command


def test_install_cli_creates_symlink_to_executable(tmp_path):
    target_dir = tmp_path / "bin"
    executable = tmp_path / "hv-source"
    executable.write_text("#!/bin/sh\n")

    link = install_cli(target_dir=target_dir, executable=executable, name="hv-test")

    assert link == target_dir / "hv-test"
    assert link.is_symlink()
    assert link.resolve() == executable


def test_backup_schedule_command_uses_separate_password_files_and_quotes_paths(tmp_path):
    command = backup_schedule_command(
        hv_executable=Path("/opt/henry vault/hv"),
        db_path=Path("/tmp/vault db.sqlite"),
        backup_path=Path("/tmp/backups/henry vault.hv.json"),
        vault_password_file=Path("/tmp/vault pw.txt"),
        backup_password_file=Path("/tmp/backup pw.txt"),
    )

    assert "HENRY_VAULT_PASSWORD=\"$(cat '/tmp/vault pw.txt')\"" in command
    assert "--backup-password \"$(cat '/tmp/backup pw.txt')\"" in command
    assert "'/opt/henry vault/hv' --db '/tmp/vault db.sqlite' backup-export '/tmp/backups/henry vault.hv.json'" in command
    assert "***" not in command
    assert " HENRY_VAULT_PASSWORD=" in f" {command}"
