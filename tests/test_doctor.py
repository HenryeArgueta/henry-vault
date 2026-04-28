from datetime import UTC, datetime, timedelta

from henry_vault.doctor import doctor_report
from henry_vault.store import SecretInput, VaultStore


def test_set_secret_metadata_tracks_expiry_and_rotation_url(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="TOKEN", value="secret", project="demo", environment="prod"))

    store.set_secret_metadata("TOKEN", project="demo", environment="prod", expires_at="2026-05-01", rotation_url="https://example.com/rotate")

    secret = store.get_secret("TOKEN", project="demo", environment="prod")
    assert secret.expires_at == "2026-05-01"
    assert secret.rotation_url == "https://example.com/rotate"


def test_doctor_report_flags_expired_expiring_and_missing_metadata(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    now = datetime(2026, 4, 28, tzinfo=UTC)
    store.add_secret(SecretInput(name="EXPIRED", value="secret"))
    store.set_secret_metadata("EXPIRED", expires_at="2026-04-01", rotation_url="https://example.com/expired")
    store.add_secret(SecretInput(name="SOON", value="secret"))
    store.set_secret_metadata("SOON", expires_at="2026-05-05", rotation_url="https://example.com/soon")
    store.add_secret(SecretInput(name="NO_META", value="secret"))

    report = doctor_report(store, now=now, expiring_days=14)

    codes = {(issue.code, issue.secret_name) for issue in report.issues}
    assert ("expired", "EXPIRED") in codes
    assert ("expiring_soon", "SOON") in codes
    assert ("missing_expiry", "NO_META") in codes
    assert ("missing_rotation_url", "NO_META") in codes


def test_doctor_report_filters_by_project_and_environment(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    now = datetime(2026, 4, 28, tzinfo=UTC)
    store.add_secret(SecretInput(name="BAD", value="secret", project="demo", environment="prod"))
    store.add_secret(SecretInput(name="OTHER", value="secret", project="other", environment="prod"))
    store.add_secret(SecretInput(name="DEV", value="secret", project="demo", environment="dev"))

    report = doctor_report(store, now=now, project="demo", environment="prod")

    names = {issue.secret_name for issue in report.issues}
    assert "BAD" in names
    assert "OTHER" not in names
    assert "DEV" not in names


def test_doctor_report_flags_missing_required_profile_secrets(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    now = datetime(2026, 4, 28, tzinfo=UTC)
    store.set_project_profile("demo", "prod", required_secrets=["API_KEY", "DATABASE_URL"])
    store.add_secret(SecretInput(name="API_KEY", value="secret", project="demo", environment="prod"))

    report = doctor_report(store, now=now, project="demo", environment="prod")

    issues = {(issue.code, issue.secret_name, issue.project, issue.environment) for issue in report.issues}
    assert ("missing_required_secret", "DATABASE_URL", "demo", "prod") in issues
    assert ("missing_required_secret", "API_KEY", "demo", "prod") not in issues
