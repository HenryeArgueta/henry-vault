import os

from typer.testing import CliRunner

from henry_vault.cli import app


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
