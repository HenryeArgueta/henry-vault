from henry_vault.scanner import scan_path


def test_scan_path_detects_env_file_and_common_tokens(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("OPENAI_API_KEY=sk-" + "a" * 48 + "\n")
    (repo / "app.py").write_text('DISCORD_TOKEN = "MTA' + 'A' * 58 + '.BBB.CCC' + 'D' * 24 + '"\n')
    (repo / ".git").mkdir()
    (repo / ".git" / "ignored").write_text("sk-" + "b" * 48)

    findings = scan_path(repo)

    kinds = {finding.kind for finding in findings}
    assert "dotenv-file" in kinds
    assert "openai-api-key" in kinds
    assert "discord-bot-token" in kinds
    assert all(".git" not in str(finding.path) for finding in findings)
    assert all("aaaa" not in finding.preview for finding in findings)


def test_scan_path_supports_known_secret_matching(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.txt").write_text("TOKEN=known-secret-value\n")

    findings = scan_path(repo, known_secret_values={"TOKEN": "known-secret-value"})

    assert len(findings) == 1
    assert findings[0].kind == "known-vault-secret"
    assert findings[0].matched_vault_name == "TOKEN"
