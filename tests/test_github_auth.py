import json

import httpx
import pytest

from henry_vault.github_auth import (
    DeviceCode,
    GitHubAuthError,
    GitHubDeviceAuth,
    GitHubUnreachable,
    GitHubUser,
    device_secret_path,
    read_device_secret,
    write_device_secret,
)


def _auth_with_responses(handler) -> GitHubDeviceAuth:
    return GitHubDeviceAuth("Iv1.testclient", transport=httpx.MockTransport(handler))


def test_request_device_code_parses_response():
    def handler(request):
        assert request.url == "https://github.com/login/device/code"
        assert b"client_id=Iv1.testclient" in request.read()
        return httpx.Response(200, json={
            "device_code": "dc123",
            "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5,
        })

    code = _auth_with_responses(handler).request_device_code()
    assert code == DeviceCode(
        device_code="dc123",
        user_code="ABCD-1234",
        verification_uri="https://github.com/login/device",
        expires_in=900,
        interval=5,
    )


def test_poll_token_pending_returns_none():
    def handler(request):
        return httpx.Response(200, json={"error": "authorization_pending"})

    assert _auth_with_responses(handler).poll_token("dc123") is None


def test_poll_token_success_returns_token():
    def handler(request):
        body = request.read().decode()
        assert "device_code=dc123" in body
        assert "grant_type=urn" in body
        return httpx.Response(200, json={"access_token": "gho_token", "token_type": "bearer"})

    assert _auth_with_responses(handler).poll_token("dc123") == "gho_token"


def test_poll_token_expired_raises():
    def handler(request):
        return httpx.Response(200, json={"error": "expired_token"})

    with pytest.raises(GitHubAuthError):
        _auth_with_responses(handler).poll_token("dc123")


def test_fetch_user_returns_id_and_login():
    def handler(request):
        assert request.url == "https://api.github.com/user"
        assert request.headers["Authorization"] == "Bearer gho_token"
        return httpx.Response(200, json={"id": 12345, "login": "henry"})

    user = _auth_with_responses(handler).fetch_user("gho_token")
    assert user == GitHubUser(id=12345, login="henry")


def test_network_error_raises_unreachable():
    def handler(request):
        raise httpx.ConnectError("no internet")

    with pytest.raises(GitHubUnreachable):
        _auth_with_responses(handler).request_device_code()


def test_device_secret_file_round_trip(tmp_path):
    db_path = tmp_path / "vault.db"
    write_device_secret(db_path, b"secret-key-material")

    path = device_secret_path(db_path)
    assert path == tmp_path / "github-device.secret"
    assert path.stat().st_mode & 0o777 == 0o600
    assert read_device_secret(db_path) == b"secret-key-material"


def test_read_device_secret_missing_returns_none(tmp_path):
    assert read_device_secret(tmp_path / "vault.db") is None
