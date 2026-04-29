from fastapi.testclient import TestClient

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


def test_web_login_rejects_wrong_password(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))

    denied = client.post("/api/login", json={"password": "***"})
    assert denied.status_code == 401


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
