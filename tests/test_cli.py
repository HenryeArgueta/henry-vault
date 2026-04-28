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
