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

    listed = client.post("/api/secrets", json={"password": "pw", "project": "demo", "environment": "dev"})
    assert listed.status_code == 200
    payload = listed.json()
    assert payload[0]["name"] == "TOKEN"
    assert "value" not in payload[0]

    revealed = client.post(
        "/api/secrets/reveal",
        json={"password": "pw", "name": "TOKEN", "project": "demo", "environment": "dev"},
    )
    assert revealed.status_code == 200
    assert revealed.json()["value"] == "secret"

    denied = client.post(
        "/api/secrets/reveal",
        json={"password": "wrong", "name": "TOKEN", "project": "demo", "environment": "dev"},
    )
    assert denied.status_code == 401
