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


def test_web_login_rejects_wrong_password(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")

    client = TestClient(create_app(db_path))

    denied = client.post("/api/login", json={"password": "wrong"})
    assert denied.status_code == 401
