import os

from typer.testing import CliRunner

from henry_vault.cli import app
from henry_vault.store import VaultStore


runner = CliRunner()


def test_cli_init_add_get_list_export_env(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")

    result = runner.invoke(app, ["--db", str(db_path), "init"])
    assert result.exit_code == 0
    assert "initialized" in result.output.lower()

    result = runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "add",
            "API_KEY",
            "secret-value",
            "--project",
            "demo",
            "--env",
            "dev",
            "--tag",
            "test",
        ],
    )
    assert result.exit_code == 0
    assert "saved" in result.output.lower()

    result = runner.invoke(app, ["--db", str(db_path), "get", "API_KEY", "--project", "demo", "--env", "dev"])
    assert result.exit_code == 0
    assert result.output.strip() == "secret-value"

    result = runner.invoke(app, ["--db", str(db_path), "list", "--project", "demo", "--env", "dev"])
    assert result.exit_code == 0
    assert "API_KEY" in result.output
    assert "secret-value" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "export-env", "--project", "demo", "--env", "dev"])
    assert result.exit_code == 0
    assert "export API_KEY='secret-value'" in result.output


def test_cli_import_env(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=abc\nDB_PASSWORD=secret\n")
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")

    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    result = runner.invoke(
        app,
        ["--db", str(db_path), "import-env", str(env_file), "--project", "demo", "--env", "dev", "--tag", "local"],
    )

    assert result.exit_code == 0
    assert "Imported 2 secrets" in result.output
    result = runner.invoke(app, ["--db", str(db_path), "get", "DB_PASSWORD", "--project", "demo", "--env", "dev"])
    assert result.output.strip() == "secret"


def test_cli_backup_export_and_import(tmp_path, monkeypatch):
    source_db = tmp_path / "source.db"
    restored_db = tmp_path / "restored.db"
    backup_path = tmp_path / "backup.hv.json"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")

    assert runner.invoke(app, ["--db", str(source_db), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(source_db), "add", "TOKEN", "secret", "--project", "demo", "--env", "prod"]).exit_code == 0
    result = runner.invoke(app, ["--db", str(source_db), "backup-export", str(backup_path), "--backup-password", "backup-pw"])
    assert result.exit_code == 0
    assert backup_path.exists()

    assert runner.invoke(app, ["--db", str(restored_db), "init"]).exit_code == 0
    result = runner.invoke(app, ["--db", str(restored_db), "backup-import", str(backup_path), "--backup-password", "backup-pw"])
    assert result.exit_code == 0
    assert "Imported 1 secrets" in result.output
    result = runner.invoke(app, ["--db", str(restored_db), "get", "TOKEN", "--project", "demo", "--env", "prod"])
    assert result.output.strip() == "secret"


def test_cli_scan_reports_findings_without_full_secret(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("API_KEY=known-secret\n")
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "API_KEY", "known-secret"]).exit_code == 0

    result = runner.invoke(app, ["--db", str(db_path), "scan", str(repo), "--match-vault"])

    assert result.exit_code == 2
    assert "known-vault-secret" in result.output
    assert "known-secret" not in result.output


def test_cli_list_filters_by_query_and_tag_without_values(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "OPENAI_API_KEY", "openai-secret", "--tag", "prod", "--tag", "ai"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "DISCORD_TOKEN", "discord-secret", "--tag", "prod", "--tag", "discord"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "OPENAI_DEV_KEY", "dev-secret", "--tag", "dev", "--tag", "ai"]).exit_code == 0

    result = runner.invoke(app, ["--db", str(db_path), "list", "--query", "api", "--tag", "prod"])

    assert result.exit_code == 0
    assert "OPENAI_API_KEY" in result.output
    assert "DISCORD_TOKEN" not in result.output
    assert "OPENAI_DEV_KEY" not in result.output
    assert "openai-secret" not in result.output

    audit = runner.invoke(app, ["--db", str(db_path), "audit", "--limit", "10"])
    assert audit.exit_code == 0
    assert "secret.list" in audit.output
    assert "count=1" in audit.output
    assert "openai-secret" not in audit.output


def test_cli_attachment_add_list_and_get_without_leaking_list_output(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    source = tmp_path / "service-account.json"
    restored = tmp_path / "restored.json"
    source.write_text('{"private_key":"super-secret-key"}')
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0

    result = runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "attachment-add",
            "SERVICE_ACCOUNT_JSON",
            str(source),
            "--project",
            "demo",
            "--env",
            "prod",
            "--content-type",
            "application/json",
        ],
    )
    assert result.exit_code == 0
    assert "Saved attachment SERVICE_ACCOUNT_JSON" in result.output
    assert "super-secret-key" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "attachment-list", "--project", "demo", "--env", "prod"])
    assert result.exit_code == 0
    assert "SERVICE_ACCOUNT_JSON" in result.output
    assert "service-account.json" in result.output
    assert "super-secret-key" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "attachment-get", "SERVICE_ACCOUNT_JSON", str(restored), "--project", "demo", "--env", "prod"])
    assert result.exit_code == 0
    assert restored.read_text() == '{"private_key":"super-secret-key"}'
    assert "super-secret-key" not in result.output

    audit = runner.invoke(app, ["--db", str(db_path), "audit", "--limit", "20"])
    assert audit.exit_code == 0
    assert "attachment.add" in audit.output
    assert "attachment.get" in audit.output
    assert "super-secret-key" not in audit.output


def test_cli_password_add_list_and_get_without_leaking_password(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0

    result = runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "password-add",
            "GitHub",
            "https://github.com",
            "henry",
            "browser-password",
            "--note",
            "personal account",
        ],
    )
    assert result.exit_code == 0
    assert "Saved password GitHub" in result.output
    assert "browser-password" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "password-list"])
    assert result.exit_code == 0
    assert "GitHub" in result.output
    assert "https://github.com" in result.output
    assert "henry" in result.output
    assert "browser-password" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "password-get", "GitHub", "https://github.com", "henry"])
    assert result.exit_code == 0
    assert result.output.strip() == "browser-password"


def test_cli_audit_lists_recent_events(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "TOKEN", "secret"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "get", "TOKEN"]).exit_code == 0

    result = runner.invoke(app, ["--db", str(db_path), "audit", "--limit", "10"])

    assert result.exit_code == 0
    assert "secret.get" in result.output
    assert "TOKEN" in result.output
    assert " default/default TOKEN secret" not in result.output


def test_cli_set_metadata_and_doctor(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "TOKEN", "secret"]).exit_code == 0
    result = runner.invoke(
        app,
        ["--db", str(db_path), "set-metadata", "TOKEN", "--expires-at", "2027-05-01", "--rotation-url", "https://example.com/rotate"],
    )
    assert result.exit_code == 0
    assert "Updated metadata" in result.output

    result = runner.invoke(app, ["--db", str(db_path), "doctor"])
    assert result.exit_code == 0
    assert "TOKEN" not in result.output


def test_cli_rotate_updates_value_metadata_and_audit_without_leaking_values(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "TOKEN", "old-value", "--project", "demo", "--env", "prod"]).exit_code == 0

    result = runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "rotate",
            "TOKEN",
            "new-value",
            "--project",
            "demo",
            "--env",
            "prod",
            "--expires-at",
            "2027-12-31",
            "--rotation-url",
            "https://example.com/rotate",
        ],
    )

    assert result.exit_code == 0
    assert "Rotated TOKEN" in result.output
    assert "old-value" not in result.output
    assert "new-value" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "get", "TOKEN", "--project", "demo", "--env", "prod"])
    assert result.exit_code == 0
    assert result.output.strip() == "new-value"

    result = runner.invoke(app, ["--db", str(db_path), "list", "--project", "demo", "--env", "prod"])
    assert result.exit_code == 0
    assert "TOKEN" in result.output
    assert "new-value" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "audit", "--limit", "20"])
    assert result.exit_code == 0
    assert "secret.rotate" in result.output
    assert "TOKEN" in result.output
    assert "old-value" not in result.output
    assert "new-value" not in result.output


def test_cli_password_add_list_get_and_delete(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")

    result = runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "password-add",
            "GitHub",
            "https://github.com",
            "henry",
            "secret-pass",
            "--note",
            "personal account",
        ],
    )
    assert result.exit_code == 0
    assert "Saved password GitHub" in result.output
    assert "secret-pass" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "password-list"])
    assert result.exit_code == 0
    assert "GitHub" in result.output
    assert "https://github.com" in result.output
    assert "secret-pass" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "password-get", "GitHub", "https://github.com", "henry"])
    assert result.exit_code == 0
    assert result.output.strip() == "secret-pass"

    result = runner.invoke(app, ["--db", str(db_path), "password-delete", "GitHub", "https://github.com", "henry"])
    assert result.exit_code == 0
    assert "Deleted" in result.output

    result = runner.invoke(app, ["--db", str(db_path), "password-list"])
    assert result.exit_code == 0
    assert "No passwords found." in result.output


def test_cli_install_cli_creates_link(tmp_path):
    target_dir = tmp_path / "bin"
    result = runner.invoke(app, ["install-cli", "--target-dir", str(target_dir), "--name", "hv-test"])

    assert result.exit_code == 0
    assert (target_dir / "hv-test").exists()
    assert "Installed" in result.output


def test_cli_backup_schedule_command(tmp_path):
    vault_password_file = tmp_path / "vault-pw.txt"
    backup_password_file = tmp_path / "backup-pw.txt"
    result = runner.invoke(
        app,
        [
            "backup-schedule-command",
            "--backup-path",
            str(tmp_path / "backup.hv.json"),
            "--vault-password-file",
            str(vault_password_file),
            "--backup-password-file",
            str(backup_password_file),
            "--hv-executable",
            "/tmp/hv",
        ],
    )

    assert result.exit_code == 0
    assert "backup-export" in result.output
    assert str(vault_password_file) in result.output
    assert str(backup_password_file) in result.output
    assert "***" not in result.output


def test_cli_backup_prune_dry_run_and_delete(tmp_path):
    old_backup = tmp_path / "old.hv.json"
    old_backup.write_text('{"format":"henry-vault-backup-v1"}')
    old_time = 1_700_000_000
    os.utime(old_backup, (old_time, old_time))

    result = runner.invoke(app, ["backup-prune", str(tmp_path), "--keep-days", "1"])
    assert result.exit_code == 0
    assert "Would delete 1 backup" in result.output
    assert old_backup.exists()

    result = runner.invoke(app, ["backup-prune", str(tmp_path), "--keep-days", "1", "--delete"])
    assert result.exit_code == 0
    assert "Deleted 1 backup" in result.output
    assert not old_backup.exists()


def test_cli_doctor_filters_project_and_env(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "BAD", "secret", "--project", "demo", "--env", "prod"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "OTHER", "secret", "--project", "other", "--env", "prod"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "DEV", "secret", "--project", "demo", "--env", "dev"]).exit_code == 0

    result = runner.invoke(app, ["--db", str(db_path), "doctor", "--project", "demo", "--env", "prod"])

    assert result.exit_code == 1
    assert "BAD" in result.output
    assert "OTHER" not in result.output
    assert "DEV" not in result.output


def test_cli_profile_set_list_and_doctor_missing_required_secret(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "API_KEY", "secret-value", "--project", "demo", "--env", "prod"]).exit_code == 0

    result = runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "profile-set",
            "--project",
            "demo",
            "--env",
            "prod",
            "--required",
            "API_KEY",
            "--required",
            "DATABASE_URL",
        ],
    )
    assert result.exit_code == 0
    assert "Saved profile demo/prod" in result.output

    result = runner.invoke(app, ["--db", str(db_path), "profile-list"])
    assert result.exit_code == 0
    assert "demo/prod required=[API_KEY,DATABASE_URL]" in result.output

    result = runner.invoke(app, ["--db", str(db_path), "doctor", "--project", "demo", "--env", "prod"])
    assert result.exit_code == 1
    assert "missing_required_secret demo/prod DATABASE_URL" in result.output
    assert "secret-value" not in result.output


def test_cli_run_refuses_missing_required_profile_secret_without_starting_command(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "API_KEY", "secret-value", "--project", "demo", "--env", "prod"]).exit_code == 0
    assert runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "profile-set",
            "--project",
            "demo",
            "--env",
            "prod",
            "--required",
            "API_KEY",
            "--required",
            "DATABASE_URL",
        ],
    ).exit_code == 0

    result = runner.invoke(
        app,
        ["--db", str(db_path), "run", "--project", "demo", "--env", "prod", "--", "python3", "-c", "print('COMMAND_RAN')"],
    )

    assert result.exit_code == 1
    assert "Missing required secrets for demo/prod: DATABASE_URL" in result.output
    assert "COMMAND_RAN" not in result.output
    assert "secret-value" not in result.output


def test_cli_run_allow_missing_starts_command_with_partial_profile(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    output_path = tmp_path / "run-output.txt"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0
    assert runner.invoke(app, ["--db", str(db_path), "add", "API_KEY", "secret-value", "--project", "demo", "--env", "prod"]).exit_code == 0
    assert runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "profile-set",
            "--project",
            "demo",
            "--env",
            "prod",
            "--required",
            "API_KEY",
            "--required",
            "DATABASE_URL",
        ],
    ).exit_code == 0

    result = runner.invoke(
        app,
        [
            "--db",
            str(db_path),
            "run",
            "--project",
            "demo",
            "--env",
            "prod",
            "--allow-missing",
            "--",
            "python3",
            "-c",
            f"import os, pathlib; pathlib.Path({str(output_path)!r}).write_text(os.environ['API_KEY'])",
        ],
    )

    assert result.exit_code == 0
    assert output_path.read_text() == "secret-value"
    assert "secret-value" not in result.output
