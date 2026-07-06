from fastapi.testclient import TestClient

import base64
import hashlib
import hmac
import struct
import time

from henry_vault.store import PasswordInput, SecretInput, VaultStore
from henry_vault.web import create_app


def test_web_health_list_and_reveal(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    password = "pw"
    store.init(password)
    store.unlock(password)
    store.add_secret(SecretInput(name="TOKEN", value="secret", project="demo", environment="dev"))

    client = TestClient(create_app(db_path))

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["ok"] is True

    login = client.post("/api/login", json={"password": "pw"})
    assert login.status_code == 200
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    listed = client.get("/api/secrets", params={"project": "demo", "environment": "dev"}, headers=headers)
    assert listed.status_code == 200
    payload = listed.json()
    assert payload[0]["name"] == "TOKEN"
    assert "value" not in payload[0]

    revealed = client.get("/api/secrets/reveal", params={"name": "TOKEN", "project": "demo", "environment": "dev"}, headers=headers)
    assert revealed.status_code == 200
    assert revealed.json()["value"] == "secret"

    denied = client.get("/api/secrets", headers={"Authorization": "Bearer wrong"})
    assert denied.status_code == 401


def _current_totp(secret: str) -> str:
    normalized = secret.strip().upper()
    normalized += "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized, casefold=True)
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def test_web_login_supports_totp_and_recovery_codes(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    setup = store.init("pw", enable_two_factor=True, recovery_code_count=2)

    store.unlock("pw", totp_code=_current_totp(setup.totp_secret))
    store.add_secret(SecretInput(name="TOKEN", value="secret", project="demo", environment="dev"))

    client = TestClient(create_app(db_path))

    login = client.post("/api/login", json={"password": "pw", "totp_code": _current_totp(setup.totp_secret)})
    assert login.status_code == 200
    token = login.json()["token"]
    listed = client.get("/api/secrets", params={"project": "demo", "environment": "dev"}, headers={"Authorization": f"Bearer {token}"})
    assert listed.status_code == 200
    assert listed.json()[0]["name"] == "TOKEN"

    recovery_login = client.post("/api/login", json={"recovery_code": setup.recovery_codes[0]})
    assert recovery_login.status_code == 200
    recovery_token = recovery_login.json()["token"]
    recovery_listed = client.get("/api/secrets", params={"project": "demo", "environment": "dev"}, headers={"Authorization": f"Bearer {recovery_token}"})
    assert recovery_listed.status_code == 200
    assert recovery_listed.json()[0]["name"] == "TOKEN"

    reused = client.post("/api/login", json={"recovery_code": setup.recovery_codes[0]})
    assert reused.status_code == 401



def test_web_login_sets_httponly_cookie_and_cookie_auth_works(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="TOKEN", value="secret", project="demo", environment="dev"))

    client = TestClient(create_app(db_path))

    login = client.post("/api/login", json={"password": "pw"})

    assert login.status_code == 200
    csrf_token = login.json()["csrf_token"]
    assert csrf_token
    cookie_header = login.headers["set-cookie"]
    assert "hv_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=strict" in cookie_header

    listed = client.get("/api/secrets", params={"project": "demo", "environment": "dev"})
    assert listed.status_code == 200
    assert listed.json()[0]["name"] == "TOKEN"

    missing_csrf = client.post("/api/logout")
    assert missing_csrf.status_code == 403

    logout = client.post("/api/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout.status_code == 200

    denied = client.get("/api/secrets", params={"project": "demo", "environment": "dev"})
    assert denied.status_code == 401


def test_web_bearer_logout_does_not_require_csrf_header(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]

    logout = client.post("/api/logout", headers={"Authorization": f"Bearer {token}"})

    assert logout.status_code == 200


def test_web_login_rate_limits_failed_attempts(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path, max_failed_logins=2, lockout_seconds=60))

    assert client.post("/api/login", json={"password": "***"}).status_code == 401
    assert client.post("/api/login", json={"password": "***"}).status_code == 401
    locked = client.post("/api/login", json={"password": "***"})

    assert locked.status_code == 429


def test_web_login_rejects_wrong_password_with_generic_error_and_audit(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))

    denied = client.post("/api/login", json={"password": "***"})

    assert denied.status_code == 401
    assert denied.json()["detail"] == "Invalid unlock credentials"
    events = VaultStore(db_path).list_audit_events(action="web.login", limit=5)
    assert events[0].status == "failed"
    assert events[0].message == "invalid unlock credentials"


def test_web_doctor_endpoint_reports_sanitized_issues(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="API_KEY", value="secret-value", project="demo", environment="prod"))
    store.set_project_profile("demo", "prod", required_secrets=["API_KEY", "DATABASE_URL"])

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    response = client.get("/api/doctor", params={"project": "demo", "environment": "prod"}, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is False
    assert any(issue["code"] == "missing_required_secret" and issue["secret_name"] == "DATABASE_URL" for issue in payload["issues"])
    assert "secret-value" not in response.text


def test_web_audit_endpoint_lists_sanitized_events(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="TOKEN", value="secret-value", project="demo", environment="prod"))
    store.record_audit("secret.add", secret_name="TOKEN", project="demo", environment="prod")

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    response = client.get("/api/audit", params={"limit": 10}, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    payload = response.json()
    assert any(event["action"] == "secret.add" and event["secret_name"] == "TOKEN" for event in payload)
    assert "secret-value" not in response.text


def test_web_responses_include_security_headers(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))

    response = client.get("/")

    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert "script-src 'self' 'nonce-" in csp
    assert "style-src 'self' 'nonce-" in csp
    assert "<script nonce=" in response.text
    assert "<style nonce=" in response.text


def test_web_index_avoids_inline_event_handlers_and_styles(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))

    response = client.get("/")

    assert response.status_code == 200
    assert " onclick=" not in response.text
    assert " onsubmit=" not in response.text
    assert " onchange=" not in response.text
    assert " style=" not in response.text
    assert "data-action=" in response.text


def test_web_index_includes_doctor_and_audit_controls(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    response = client.get("/")

    assert response.status_code == 200
    assert "Doctor" in response.text
    assert "Audit" in response.text
    assert "/api/doctor" in response.text
    assert "/api/audit" in response.text
    assert 'id="doctor-issues"' in response.text
    assert 'id="audit-events"' in response.text
    assert 'id="doctor"' not in response.text
    assert 'id="audit"' not in response.text


def test_web_index_renders_unlock_form_visible_for_initialized_vault(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    response = client.get("/")

    assert response.status_code == 200
    assert '<div class="card" id="login-card">' in response.text
    assert '<input id="password" class="fixed" type="password"' in response.text
    assert '<div class="card hidden" id="setup-card">' in response.text


def test_web_index_renders_setup_visible_for_uninitialized_vault(tmp_path):
    db_path = tmp_path / "vault.db"

    client = TestClient(create_app(db_path))
    response = client.get("/")

    assert response.status_code == 200
    assert '<div class="card" id="setup-card">' in response.text
    assert '<div class="card hidden" id="login-card">' in response.text


def test_web_init_flow_exposes_setup_qr_and_recovery_codes(tmp_path):
    db_path = tmp_path / "vault.db"
    client = TestClient(create_app(db_path))

    status = client.get("/api/status")
    assert status.status_code == 200
    assert status.json()["initialized"] is False

    index = client.get("/")
    assert index.status_code == 200
    assert "Create a new vault" in index.text
    assert "scan the QR code in your authenticator app" in index.text
    assert "Recovery codes are shown once" in index.text
    assert 'id="setup-qr"' in index.text

    created = client.post(
        "/api/init",
        json={"password": "pw", "enable_two_factor": True, "recovery_code_count": 3},
    )
    assert created.status_code == 200
    payload = created.json()
    assert payload["token"]
    assert payload["csrf_token"]
    assert payload["setup"]["otpauth_uri"].startswith("otpauth://totp/")
    assert payload["setup"]["qr_svg"].startswith("<svg")
    assert len(payload["setup"]["recovery_codes"]) == 3

    initialized = client.get("/api/status")
    assert initialized.status_code == 200
    assert initialized.json()["initialized"] is True
    assert "two_factor_enabled" not in initialized.json()

    second_init = client.post(
        "/api/init",
        json={"password": "***", "enable_two_factor": False},
    )
    assert second_init.status_code == 409


def test_web_status_does_not_disclose_two_factor_state_before_login(tmp_path):
    db_path = tmp_path / "vault.db"
    setup = VaultStore(db_path).init("***", enable_two_factor=True)
    client = TestClient(create_app(db_path))

    public_status = client.get("/api/status")
    assert public_status.status_code == 200
    assert public_status.json() == {"initialized": True, "github_unlock": False}
    assert "two_factor" not in public_status.text

    login = client.post("/api/login", json={"password": "***", "totp_code": _current_totp(setup.totp_secret)})
    token = login.json()["token"]
    private_status = client.get("/api/session/status", headers={"Authorization": f"Bearer {token}"})
    assert private_status.status_code == 200
    assert private_status.json()["two_factor_enabled"] is True


def test_web_init_without_two_factor_does_not_return_empty_recovery_panel_data(tmp_path):
    db_path = tmp_path / "vault.db"
    client = TestClient(create_app(db_path))

    created = client.post("/api/init", json={"password": "***", "enable_two_factor": False})

    assert created.status_code == 200
    assert created.json()["setup"] is None


def test_web_init_recovery_code_count_is_bounded(tmp_path):
    db_path = tmp_path / "vault.db"
    client = TestClient(create_app(db_path))

    too_many = client.post(
        "/api/init",
        json={"password": "***", "enable_two_factor": True, "recovery_code_count": 21},
    )

    assert too_many.status_code == 422


def test_web_can_download_attachment_via_api(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/attachments",
        data={"name": "RECOVERY_CODES", "project": "demo", "environment": "prod", "content_type": "text/plain"},
        files={"file": ("recovery-codes.txt", b"code-1\ncode-2", "text/plain")},
        headers=headers,
    )

    download = client.get("/api/attachments/download", params={"name": "RECOVERY_CODES", "project": "demo", "environment": "prod"}, headers=headers)
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/plain")
    assert "attachment" in download.headers["content-disposition"]
    assert download.content == b"code-1\ncode-2"


def test_web_can_delete_attachment_via_api(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/attachments",
        data={"name": "RECOVERY_CODES", "project": "demo", "environment": "prod", "content_type": "text/plain"},
        files={"file": ("recovery-codes.txt", b"code-1\ncode-2", "text/plain")},
        headers=headers,
    )

    deleted = client.delete("/api/attachments", params={"name": "RECOVERY_CODES", "project": "demo", "environment": "prod"}, headers=headers)
    assert deleted.status_code == 200
    assert deleted.json()["ok"] is True

    remaining = client.get("/api/attachments", params={"project": "demo", "environment": "prod"}, headers=headers)
    assert all(item["name"] != "RECOVERY_CODES" for item in remaining.json())


def test_web_api_search_filters_secrets_and_attachments(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="API_KEY", value="secret", project="demo", environment="prod"))
    store.add_secret(SecretInput(name="OTHER_TOKEN", value="secret", project="demo", environment="prod"))
    store.add_attachment(
        __import__("henry_vault.store", fromlist=["AttachmentInput"]).AttachmentInput(
            name="API_DOCS",
            filename="docs.txt",
            content=b"docs",
            project="demo",
            environment="prod",
            content_type="text/plain",
            notes="",
        )
    )
    store.add_attachment(
        __import__("henry_vault.store", fromlist=["AttachmentInput"]).AttachmentInput(
            name="OTHER_FILE",
            filename="other.txt",
            content=b"other",
            project="demo",
            environment="prod",
            content_type="text/plain",
            notes="",
        )
    )

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    secrets = client.get("/api/secrets", params={"project": "demo", "environment": "prod", "query": "API"}, headers=headers)
    assert [item["name"] for item in secrets.json()] == ["API_KEY"]

    attachments = client.get("/api/attachments", params={"project": "demo", "environment": "prod", "query": "API"}, headers=headers)
    assert [item["name"] for item in attachments.json()] == ["API_DOCS"]


def test_web_index_includes_edit_search_and_attachment_controls(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    response = client.get("/")

    assert response.status_code == 200
    assert "Add secret" in response.text
    assert "Add attachment" in response.text
    assert "Edit" in response.text
    assert "Search" in response.text
    assert "Clear filters" in response.text
    assert "Clear edit mode" in response.text
    assert "Toggle theme" in response.text
    assert 'id="theme-toggle"' in response.text
    assert 'id="density-toggle"' in response.text
    assert 'Compact mode' in response.text
    assert 'DarkLuxury' in response.text
    assert 'Pearl Light' in response.text
    assert 'Royal Indigo' in response.text
    assert 'Emerald Velvet' in response.text
    assert 'Rose Quartz' in response.text
    assert 'Sunset Amber' in response.text
    assert 'id="topbar"' in response.text
    assert 'position: sticky' in response.text
    assert 'class="hero-title"' in response.text
    assert 'class="muted hero-subtitle"' in response.text
    assert '.topbar .card {' in response.text
    assert '.topbar .shortcuts {' in response.text
    assert '.topbar .top-group +' in response.text
    assert '.section-label {' in response.text
    assert '.topbar .split-row:first-of-type' in response.text
    assert '.topbar .split-row:last-of-type' in response.text
    assert 'Search and actions' in response.text
    assert '#passwords .row {' in response.text
    assert '#passwords .subgroup + .subgroup {' in response.text
    assert '#passwords .credentials-tools .row {' in response.text
    assert '#passwords table {' in response.text
    assert 'table-layout: fixed' in response.text
    assert '#passwords th:nth-child(1),' in response.text
    # Action columns are 7 (Copy) and 8 (Manage) since the Password column was added.
    assert '#passwords th:nth-child(7),' in response.text
    assert '#passwords td:nth-child(7) button,' in response.text
    assert '#passwords td:nth-child(8) button {' in response.text
    assert 'type="button" data-action="copy-password"' in response.text
    assert 'type="button" data-action="delete-password"' in response.text
    assert 'navigator.clipboard.writeText' in response.text
    assert 'setSelectionRange(0, textarea.value.length)' in response.text
    assert 'class="section-label"' in response.text
    assert 'Credentials tools' in response.text
    assert 'New password' in response.text
    assert 'Saved passwords' in response.text
    assert '#add-password-form {' in response.text
    assert 'Shortcuts:' in response.text
    assert '<kbd>/</kbd> focus search' in response.text
    assert '<kbd>g</kbd>' in response.text
    assert '<kbd>d</kbd> doctor' in response.text
    assert '<kbd>a</kbd> audit' in response.text
    assert '<kbd>t</kbd> theme' in response.text
    assert '<kbd>c</kbd> clear filters' in response.text
    assert ':focus-visible' in response.text
    assert 'button:hover' in response.text
    assert '@media (max-width: 820px)' in response.text
    assert 'tbody tr:nth-child(even)' in response.text
    assert 'id="filter-form"' in response.text
    assert 'id="secret-search"' in response.text
    assert 'id="attachment-search"' in response.text
    assert 'id="project-options"' in response.text
    assert 'id="environment-options"' in response.text
    assert 'Delete' in response.text
    assert 'Download' in response.text
    assert '<details open>' in response.text
    assert 'role="status"' in response.text
    assert 'id="toast"' in response.text
    assert 'background: var(--panel-bg)' in response.text
    assert 'margin: 2rem auto' in response.text
    assert '/api/secrets' in response.text
    assert '/api/attachments' in response.text


def test_web_can_add_secret_and_attachment_via_api(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    added_secret = client.post(
        "/api/secrets",
        json={
            "name": "API_KEY",
            "value": "new-secret",
            "project": "demo",
            "environment": "prod",
            "tags": ["ai", "web"],
            "notes": "created from web ui",
        },
        headers=headers,
    )
    assert added_secret.status_code == 200
    assert added_secret.json()["ok"] is True

    listed = client.get("/api/secrets", params={"project": "demo", "environment": "prod"}, headers=headers)
    assert any(item["name"] == "API_KEY" for item in listed.json())

    added_attachment = client.post(
        "/api/attachments",
        data={
            "name": "RECOVERY_CODES",
            "project": "demo",
            "environment": "prod",
            "content_type": "text/plain",
            "notes": "uploaded from web ui",
        },
        files={"file": ("recovery-codes.txt", b"code-1\ncode-2", "text/plain")},
        headers=headers,
    )
    assert added_attachment.status_code == 200
    assert added_attachment.json()["ok"] is True

    attachments = client.get("/api/attachments", params={"project": "demo", "environment": "prod"}, headers=headers)
    assert any(item["name"] == "RECOVERY_CODES" for item in attachments.json())


def test_web_can_delete_secret_via_api(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/secrets",
        json={"name": "API_KEY", "value": "new-secret", "project": "demo", "environment": "prod"},
        headers=headers,
    )

    deleted = client.delete("/api/secrets", params={"name": "API_KEY", "project": "demo", "environment": "prod"}, headers=headers)
    assert deleted.status_code == 200
    assert deleted.json()["ok"] is True

    listed = client.get("/api/secrets", params={"project": "demo", "environment": "prod"}, headers=headers)
    assert all(item["name"] != "API_KEY" for item in listed.json())


def test_web_can_download_attachment_via_api(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/attachments",
        data={"name": "RECOVERY_CODES", "project": "demo", "environment": "prod", "content_type": "text/plain"},
        files={"file": ("recovery-codes.txt", b"code-1\ncode-2", "text/plain")},
        headers=headers,
    )

    download = client.get("/api/attachments/download", params={"name": "RECOVERY_CODES", "project": "demo", "environment": "prod"}, headers=headers)
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/plain")
    assert "attachment" in download.headers["content-disposition"]
    assert download.content == b"code-1\ncode-2"


def test_web_can_add_and_retrieve_password_via_api(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    added = client.post(
        "/api/passwords",
        json={
            "name": "GitHub",
            "url": "https://github.com",
            "username": "henry",
            "password": "secret-pass",
            "note": "personal account",
        },
        headers=headers,
    )
    assert added.status_code == 200
    assert added.json()["ok"] is True

    listed = client.get("/api/passwords", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["name"] == "GitHub"
    assert listed.json()[0]["url"] == "https://github.com"
    assert "password" not in listed.json()[0]

    reveal = client.get(
        "/api/passwords/reveal",
        params={"name": "GitHub", "url": "https://github.com", "username": "henry"},
        headers=headers,
    )
    assert reveal.status_code == 200
    assert reveal.json()["password"] == "secret-pass"

    deleted = client.delete(
        "/api/passwords",
        params={"name": "GitHub", "url": "https://github.com", "username": "henry"},
        headers=headers,
    )
    assert deleted.status_code == 200
    assert deleted.json()["ok"] is True

    listed_again = client.get("/api/passwords", headers=headers)
    assert listed_again.json() == []


def test_web_can_export_and_import_credentials_via_api(tmp_path):
    db_path = tmp_path / "vault.db"
    export_path = tmp_path / "credentials.csv"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="API_KEY", value="secret-value", project="demo", environment="prod", tags=["alpha"], notes="secret note"))
    store.add_password(PasswordInput(name="GitHub", url="https://github.com", username="henry", password="secret-pass", note="personal account"))

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    export_response = client.get("/api/credentials/export", headers=headers)
    assert export_response.status_code == 200
    assert export_response.headers["content-type"].startswith("text/csv")
    assert "attachment" in export_response.headers["content-disposition"]
    export_path.write_bytes(export_response.content)
    assert b"API_KEY" in export_response.content
    assert b"GitHub" in export_response.content

    client.delete("/api/secrets", params={"name": "API_KEY", "project": "demo", "environment": "prod"}, headers=headers)
    client.delete("/api/passwords", params={"name": "GitHub", "url": "https://github.com", "username": "henry"}, headers=headers)

    import_response = client.post(
        "/api/credentials/import",
        headers=headers,
        files={"file": ("credentials.csv", export_path.read_bytes(), "text/csv")},
    )
    assert import_response.status_code == 200
    assert import_response.json()["ok"] is True
    assert import_response.json()["secrets"] == 1
    assert import_response.json()["passwords"] == 1

    secrets = client.get("/api/secrets", params={"project": "demo", "environment": "prod"}, headers=headers).json()
    passwords = client.get("/api/passwords", headers=headers).json()
    assert [item["name"] for item in secrets] == ["API_KEY"]
    assert [item["name"] for item in passwords] == ["GitHub"]


def test_web_index_includes_credential_transfer_controls(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))
    response = client.get("/")

    assert response.status_code == 200
    assert "Export credentials CSV" in response.text
    assert "Import credentials CSV" in response.text
    assert 'id="credentials-export"' in response.text
    assert 'id="credentials-import-form"' in response.text
    assert 'id="credentials-import-file"' in response.text
    assert '/api/credentials/export' in response.text
    assert '/api/credentials/import' in response.text


def test_web_secrets_api_filters_by_tag(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="BOT_TOKEN", value="tok", project="discord", tags=["service"]))
    store.add_secret(SecretInput(name="PLAIN", value="plain", project="default", tags=[]))

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    service_only = client.get("/api/secrets?tags=service", headers=headers).json()
    assert any(s["name"] == "BOT_TOKEN" for s in service_only)
    assert all(s["name"] != "PLAIN" for s in service_only)


def test_web_index_includes_service_sections(tmp_path):
    db_path = tmp_path / "vault.db"
    VaultStore(db_path).init("pw")
    client = TestClient(create_app(db_path))
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="add-service-form"' in response.text
    assert 'id="service-name"' in response.text
    assert 'id="service-fields"' in response.text
    assert 'data-action="add-service-field"' in response.text
    assert 'id="service-groups"' in response.text
    assert 'Add API Service' in response.text
    assert 'API Services' in response.text


def test_web_index_includes_service_js(tmp_path):
    db_path = tmp_path / "vault.db"
    VaultStore(db_path).init("pw")
    client = TestClient(create_app(db_path))
    response = client.get("/")
    assert response.status_code == 200
    assert 'function addServiceField' in response.text
    assert 'function loadServices' in response.text
    assert 'function renderServiceGroups' in response.text
    assert 'function deleteService' in response.text
    assert 'tags=service' in response.text
    assert 'add-service-form' in response.text


def test_web_serves_favicon(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    client = TestClient(create_app(db_path))

    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert "image" in response.headers["content-type"]


def test_web_index_hides_dashboard_until_unlocked(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    client = TestClient(create_app(db_path))

    response = client.get("/")
    assert response.status_code == 200
    # Dashboard sections are tagged and hidden by CSS until the body is marked unlocked.
    assert "body:not(.unlocked) .dashboard-only" in response.text
    assert response.text.count("dashboard-only") >= 8
    # Session indicator with lock control exists for the unlocked state.
    assert 'id="session-chip"' in response.text


class FakeGitHubAuth:
    def __init__(self, client_id, *, user_id=777, login="henry", fail_mode=None, pending_polls=0):
        from henry_vault.github_auth import DeviceCode, GitHubUser

        self.client_id = client_id
        self._user = GitHubUser(id=user_id, login=login)
        self._fail_mode = fail_mode
        self._pending_polls = pending_polls
        self._device_code_cls = DeviceCode

    def request_device_code(self):
        from henry_vault.github_auth import GitHubUnreachable

        if self._fail_mode == "unreachable":
            raise GitHubUnreachable("no internet")
        return self._device_code_cls(
            device_code="dc123",
            user_code="ABCD-1234",
            verification_uri="https://github.com/login/device",
            expires_in=900,
            interval=0,
        )

    def poll_token(self, device_code):
        from henry_vault.github_auth import GitHubAuthError

        if self._fail_mode == "expired":
            raise GitHubAuthError("GitHub device flow failed: expired_token")
        if self._pending_polls > 0:
            self._pending_polls -= 1
            return None
        return "gho_token"

    def fetch_user(self, token):
        return self._user


def _github_enrolled_app(tmp_path, *, fake_factory=None, init_kwargs=None):
    from henry_vault.github_auth import write_device_secret

    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw", **(init_kwargs or {}))
    store.add_secret(SecretInput(name="TOKEN", value="secret", project="demo", environment="dev"))
    device_secret = store.enable_github_unlock(github_user_id=777, github_login="henry", client_id="Iv1.x")
    write_device_secret(db_path, device_secret)
    factory = fake_factory or (lambda client_id: FakeGitHubAuth(client_id))
    return TestClient(create_app(db_path, github_auth_factory=factory)), db_path


def test_web_status_reports_github_unlock(tmp_path):
    client, _ = _github_enrolled_app(tmp_path)
    assert client.get("/api/status").json() == {"initialized": True, "github_unlock": True}

    plain_db = tmp_path / "plain.db"
    VaultStore(plain_db).init("pw")
    plain_client = TestClient(create_app(plain_db))
    assert plain_client.get("/api/status").json() == {"initialized": True, "github_unlock": False}


def test_web_github_unlock_happy_path(tmp_path):
    client, _ = _github_enrolled_app(tmp_path)

    started = client.post("/api/auth/github/start")
    assert started.status_code == 200
    body = started.json()
    assert body["user_code"] == "ABCD-1234"
    assert body["verification_uri"] == "https://github.com/login/device"
    ticket = body["ticket"]

    polled = client.post("/api/auth/github/poll", json={"ticket": ticket})
    assert polled.status_code == 200
    payload = polled.json()
    assert payload["status"] == "complete"
    token = payload["token"]

    listed = client.get(
        "/api/secrets",
        params={"project": "demo", "environment": "dev"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert listed.status_code == 200
    assert listed.json()[0]["name"] == "TOKEN"


def test_web_github_unlock_rejects_wrong_account(tmp_path):
    client, _ = _github_enrolled_app(
        tmp_path, fake_factory=lambda client_id: FakeGitHubAuth(client_id, user_id=999, login="stranger")
    )
    ticket = client.post("/api/auth/github/start").json()["ticket"]
    polled = client.post("/api/auth/github/poll", json={"ticket": ticket})
    assert polled.status_code == 403
    assert "not linked" in polled.json()["detail"].lower()


def test_web_github_unlock_unreachable_returns_503(tmp_path):
    client, _ = _github_enrolled_app(
        tmp_path, fake_factory=lambda client_id: FakeGitHubAuth(client_id, fail_mode="unreachable")
    )
    started = client.post("/api/auth/github/start")
    assert started.status_code == 503
    assert "master password" in started.json()["detail"].lower()


def test_web_github_unlock_expired_code_returns_410(tmp_path):
    client, _ = _github_enrolled_app(
        tmp_path, fake_factory=lambda client_id: FakeGitHubAuth(client_id, fail_mode="expired")
    )
    ticket = client.post("/api/auth/github/start").json()["ticket"]
    polled = client.post("/api/auth/github/poll", json={"ticket": ticket})
    assert polled.status_code == 410


def test_web_github_start_requires_enrollment(tmp_path):
    db_path = tmp_path / "plain.db"
    VaultStore(db_path).init("pw")
    client = TestClient(create_app(db_path))
    assert client.post("/api/auth/github/start").status_code == 400


def test_web_github_unlock_skips_totp(tmp_path):
    client, _ = _github_enrolled_app(tmp_path, init_kwargs={"enable_two_factor": True, "recovery_code_count": 2})
    ticket = client.post("/api/auth/github/start").json()["ticket"]
    polled = client.post("/api/auth/github/poll", json={"ticket": ticket})
    assert polled.status_code == 200
    assert polled.json()["status"] == "complete"


def test_web_index_has_password_view_toggle(tmp_path):
    db_path = tmp_path / "vault.db"
    VaultStore(db_path).init("pw")
    client = TestClient(create_app(db_path))

    response = client.get("/")
    assert response.status_code == 200
    assert 'data-action="view-password"' in response.text
    assert "<th>Password</th>" in response.text
