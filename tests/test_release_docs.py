import re
from pathlib import Path


def _package_version() -> str:
    pyproject = Path("pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"$', pyproject, flags=re.MULTILINE)
    assert match, "pyproject.toml must declare a version"
    return match.group(1)


def test_package_version_and_changelog_are_release_aligned():
    version = _package_version()
    changelog = Path("CHANGELOG.md").read_text()
    readme = Path("README.md").read_text()

    assert f"## [{version}] - " in changelog, f"CHANGELOG.md has no dated entry for {version}"
    assert "## [Unreleased]" not in changelog
    assert f"@v{version}" in readme, f"README install examples still pin an older tag than v{version}"
