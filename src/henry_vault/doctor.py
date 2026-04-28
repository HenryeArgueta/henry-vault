from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .store import VaultStore


@dataclass(frozen=True)
class DoctorIssue:
    code: str
    severity: str
    secret_name: str
    project: str
    environment: str
    message: str


@dataclass(frozen=True)
class DoctorReport:
    issues: list[DoctorIssue]

    @property
    def ok(self) -> bool:
        return not self.issues


def doctor_report(
    store: VaultStore,
    now: datetime | None = None,
    expiring_days: int = 30,
    project: str | None = None,
    environment: str | None = None,
) -> DoctorReport:
    now = now or datetime.now(UTC)
    cutoff = now + timedelta(days=expiring_days)
    issues: list[DoctorIssue] = []
    for item in store.list_secrets(project=project, environment=environment):
        if not item.expires_at:
            issues.append(_issue("missing_expiry", "warning", item, "No expiry date set"))
        else:
            expires = _parse_date(item.expires_at)
            if expires < now:
                issues.append(_issue("expired", "critical", item, f"Expired on {item.expires_at}"))
            elif expires <= cutoff:
                issues.append(_issue("expiring_soon", "warning", item, f"Expires on {item.expires_at}"))
        if not item.rotation_url:
            issues.append(_issue("missing_rotation_url", "info", item, "No rotation URL/instructions set"))
    for profile in store.list_project_profiles(project=project, environment=environment):
        existing = {item.name for item in store.list_secrets(project=profile.project, environment=profile.environment)}
        for required in profile.required_secrets:
            if required not in existing:
                issues.append(
                    DoctorIssue(
                        code="missing_required_secret",
                        severity="critical",
                        secret_name=required,
                        project=profile.project,
                        environment=profile.environment,
                        message="Required by project profile but not found in vault",
                    )
                )
    return DoctorReport(issues=issues)


def _parse_date(value: str) -> datetime:
    if len(value) == 10:
        return datetime.fromisoformat(value).replace(tzinfo=UTC)
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _issue(code: str, severity: str, item, message: str) -> DoctorIssue:
    return DoctorIssue(
        code=code,
        severity=severity,
        secret_name=item.name,
        project=item.project,
        environment=item.environment,
        message=message,
    )
