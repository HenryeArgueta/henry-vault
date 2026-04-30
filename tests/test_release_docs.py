from pathlib import Path


def test_package_version_and_changelog_are_release_aligned():
    pyproject = Path("pyproject.toml").read_text()
    changelog = Path("CHANGELOG.md").read_text()
    readme = Path("README.md").read_text()

    assert 'version = "0.3.0"' in pyproject
    assert "## [0.3.0] - 2026-04-30" in changelog
    assert "## [Unreleased]" not in changelog
    assert "@v0.3.0" in readme
