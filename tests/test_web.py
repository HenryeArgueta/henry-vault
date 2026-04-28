from fastapi.testclient import TestClient

from henry_vault.store import SecretInput, VaultStore
from henry_vault.web import create_app


def test_web_health_list_and_reveal(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
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
    cookie_header = login.headers["set-cookie"]
    assert "hv_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=strict" in cookie_header

    listed = client.get("/api/secrets", params={"project": "demo", "environment": "dev"})
    assert listed.status_code == 200
    assert listed.json()[0]["name"] == "TOKEN"

    logout = client.post("/api/logout")
    assert logout.status_code == 200

    denied = client.get("/api/secrets", params={"project": "demo", "environment": "dev"})
    assert denied.status_code == 401


def test_web_login_rate_limits_failed_attempts(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path, max_failed_logins=2, lockout_seconds=60))

    assert client.post("/api/login", json={"password": "wrong-1"}).status_code == 401
    assert client.post("/api/login", json={"password": "wrong-2"}).status_code == 401
    locked = client.post("/api/login", json={"password": "pw"})

    assert locked.status_code == 429


def test_web_login_rejects_wrong_password(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))

    denied = client.post("/api/login", json={"password": "wrong"})
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
