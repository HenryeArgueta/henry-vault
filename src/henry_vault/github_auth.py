from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import httpx

DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


class GitHubAuthError(Exception):
    """Device flow failed (expired, denied, or malformed response)."""


class GitHubUnreachable(GitHubAuthError):
    """GitHub could not be reached, e.g. no internet."""


@dataclass(frozen=True)
class DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class GitHubUser:
    id: int
    login: str


class GitHubDeviceAuth:
    """Minimal GitHub OAuth device-flow client. No scopes are requested; the
    access token is only ever used to read the authenticated user's identity."""

    def __init__(self, client_id: str, *, transport: httpx.BaseTransport | None = None, timeout: float = 10.0) -> None:
        self.client_id = client_id
        self._transport = transport
        self._timeout = timeout

    def _post(self, url: str, data: dict[str, str]) -> dict:
        try:
            with httpx.Client(transport=self._transport, timeout=self._timeout) as client:
                response = client.post(url, data=data, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise GitHubUnreachable(f"Could not reach GitHub: {exc}") from exc
        if response.status_code != 200:
            raise GitHubAuthError(f"GitHub returned HTTP {response.status_code}")
        return response.json()

    def request_device_code(self) -> DeviceCode:
        payload = self._post(DEVICE_CODE_URL, {"client_id": self.client_id})
        try:
            return DeviceCode(
                device_code=str(payload["device_code"]),
                user_code=str(payload["user_code"]),
                verification_uri=str(payload["verification_uri"]),
                expires_in=int(payload["expires_in"]),
                interval=int(payload.get("interval", 5)),
            )
        except KeyError as exc:
            raise GitHubAuthError(f"Malformed device-code response: missing {exc}") from exc

    def poll_token(self, device_code: str) -> str | None:
        """Returns the access token, or None while authorization is still pending."""
        payload = self._post(
            ACCESS_TOKEN_URL,
            {"client_id": self.client_id, "device_code": device_code, "grant_type": GRANT_TYPE},
        )
        error = payload.get("error")
        if error in ("authorization_pending", "slow_down"):
            return None
        if error:
            raise GitHubAuthError(f"GitHub device flow failed: {error}")
        token = payload.get("access_token")
        if not token:
            raise GitHubAuthError("GitHub returned no access token")
        return str(token)

    def fetch_user(self, access_token: str) -> GitHubUser:
        try:
            with httpx.Client(transport=self._transport, timeout=self._timeout) as client:
                response = client.get(
                    USER_URL,
                    headers={"Accept": "application/json", "Authorization": f"Bearer {access_token}"},
                )
        except httpx.HTTPError as exc:
            raise GitHubUnreachable(f"Could not reach GitHub: {exc}") from exc
        if response.status_code != 200:
            raise GitHubAuthError(f"GitHub user lookup returned HTTP {response.status_code}")
        payload = response.json()
        try:
            return GitHubUser(id=int(payload["id"]), login=str(payload["login"]))
        except KeyError as exc:
            raise GitHubAuthError(f"Malformed user response: missing {exc}") from exc


def device_secret_path(db_path: Path | str) -> Path:
    return Path(db_path).parent / "github-device.secret"


def write_device_secret(db_path: Path | str, device_secret: bytes) -> Path:
    path = device_secret_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with 0600 from the start; a plain write-then-chmod leaves a window
    # where the secret is readable via the process umask.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(device_secret)
    os.chmod(path, 0o600)
    return path


def read_device_secret(db_path: Path | str) -> bytes | None:
    path = device_secret_path(db_path)
    if not path.exists():
        return None
    return path.read_bytes()


def remove_device_secret(db_path: Path | str) -> None:
    device_secret_path(db_path).unlink(missing_ok=True)
