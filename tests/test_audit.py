from henry_vault.store import SecretInput, VaultStore


def test_audit_records_events_without_secret_values(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="TOKEN", value="super-secret", project="demo", environment="dev"))
    store.record_audit("secret.reveal", secret_name="TOKEN", project="demo", environment="dev", status="success")

    events = store.list_audit_events()

    assert len(events) >= 1
    event = events[0]
    assert event.action == "secret.reveal"
    assert event.secret_name == "TOKEN"
    assert event.project == "demo"
    assert event.environment == "dev"
    assert event.status == "success"
    assert "super-secret" not in repr(event)


def test_list_audit_events_can_filter_by_action(tmp_path):
    store = VaultStore(tmp_path / "vault.db")
    store.init("pw")
    store.unlock("pw")
    store.record_audit("vault.unlock", status="success")
    store.record_audit("secret.list", status="success")

    events = store.list_audit_events(action="secret.list")

    assert [event.action for event in events] == ["secret.list"]
