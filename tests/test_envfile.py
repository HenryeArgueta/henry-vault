from henry_vault.envfile import parse_env_file
from henry_vault.store import VaultStore


def test_parse_env_file_handles_comments_quotes_and_export(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        """
# comment
PLAIN=abc
export QUOTED="hello world"
SINGLE='one two'
EMPTY=
IGNORED_LINE
INLINE=value # keep this comment out
""".strip()
    )

    parsed = parse_env_file(env_file)

    assert parsed == {
        "PLAIN": "abc",
        "QUOTED": "hello world",
        "SINGLE": "one two",
        "EMPTY": "",
        "INLINE": "value",
    }


def test_import_env_file_adds_secrets_to_project_environment(tmp_path):
    db_path = tmp_path / "vault.db"
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=abc\nDB_PASSWORD='secret password'\n")
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")

    imported = store.import_env_file(env_file, project="demo", environment="dev", tags=["imported"])

    assert imported == ["API_KEY", "DB_PASSWORD"]
    assert store.get_secret("API_KEY", project="demo", environment="dev").value == "abc"
    db_password = store.get_secret("DB_PASSWORD", project="demo", environment="dev")
    assert db_password.value == "secret password"
    assert db_password.tags == ["imported"]
