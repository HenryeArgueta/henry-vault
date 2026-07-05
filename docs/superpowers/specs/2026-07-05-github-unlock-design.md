# GitHub Unlock for the Web UI — Design

Date: 2026-07-05
Status: Approved by Henry

## Goal

Let Henry unlock the henry-vault web UI by signing in with his GitHub account when
internet is available, with the master password always working as the offline
fallback. Web UI only; the CLI keeps password unlock and gains only enrollment
management commands.

## Non-goals

- CLI unlock via GitHub.
- Multiple GitHub accounts or per-user vault separation.
- Web-based enrollment (one-time action, done via CLI).
- Storing GitHub access tokens.

## Security model

GitHub proves identity; it provides no key material. Therefore:

- Enrollment generates a random **device secret** (a Fernet key).
- The vault key gets a third wrap, `github_wrap` = Fernet(device_secret).encrypt(vault_key),
  stored in `vault.db` meta alongside `github_user_id`, `github_login`, `github_client_id`.
- The device secret is written to `~/.henry-vault/github-device.secret` (same directory
  as the DB in the default case; always `<db_dir>/github-device.secret`), chmod 0600.
- Unlock requires the DB wrap **and** the secret file **and** a successful GitHub
  device-flow login whose immutable user **ID** (not login name) matches the enrolled ID.
- Exposure class is identical to recovery codes: an attacker with local root can combine
  the file and DB to unlock without GitHub. The master password remains the only
  cryptographic root. This trade-off was explicitly accepted.
- GitHub unlock skips vault TOTP (GitHub's own account 2FA covers that factor).
- The GitHub access token is used once (GET /user) and discarded.

## Enrollment lifecycle (CLI)

- `hv github-link --client-id <ID>`: prompts master password (verifies + obtains vault
  key), runs the GitHub device flow in the terminal (prints `XXXX-XXXX` code and
  https://github.com/login/device), on approval fetches the user profile, stores the
  meta rows + `github_wrap`, writes the device secret file. Re-linking overwrites any
  previous enrollment. `--client-id` may be omitted when re-linking (reuses stored one).
- `hv github-unlink`: requires master password; deletes the meta rows and the secret file.
- `hv github-status`: prints enrollment state (login, user id, client id present) without
  requiring unlock; metadata is not secret.
- Audit events: `github.link`, `github.unlink`.

Prerequisite (manual, one-time): Henry creates a free GitHub OAuth App with
"Enable Device Flow" checked; no callback URL or client secret is needed. Only the
public client ID is used.

## Web unlock flow

1. `/api/status` additionally reports `github_unlock: true|false` (enrolled and secret
   file present).
2. Lock screen: when `github_unlock` is true, show a "Sign in with GitHub" button above
   the password form. Password form always remains visible.
3. `POST /api/auth/github/start` → server calls `https://github.com/login/device/code`
   (client_id, no scopes) → returns `{ticket, user_code, verification_uri, expires_in}`.
   The GitHub `device_code` stays server-side in an in-memory dict keyed by a random
   ticket, with expiry.
4. Lock screen displays the code + link; browser polls `POST /api/auth/github/poll
   {ticket}` every few seconds. The server polls GitHub's token endpoint no faster than
   GitHub's `interval`, tracking `authorization_pending` / `slow_down` / `expired_token`.
5. On an access token: `GET https://api.github.com/user`; if `id` == enrolled
   `github_user_id`, read the device secret file, unwrap the vault key, create a normal
   session (HttpOnly cookie + CSRF + bearer token, same 15-minute TTL). Response is the
   same shape as `/api/login`.
6. Failures return distinct statuses the UI renders as friendly messages:
   - GitHub unreachable → "GitHub not reachable — unlock with your master password instead."
   - Wrong account → "That GitHub account is not linked to this vault." (audited)
   - Expired/denied code → "GitHub sign-in timed out — try again."
7. Audit events: `web.login.github` with success/failure status. Failed attempts count
   toward the existing in-memory login rate limiter.

## Implementation shape

- `store.py`: four methods mirroring the recovery-code pattern —
  `enable_github_unlock(github_user_id, github_login, client_id) -> device_secret`
  (requires unlocked store), `disable_github_unlock()`, `github_unlock_info()`
  (works on a locked store), `unlock_with_device_secret(device_secret)`.
- New module `github_auth.py`: `GitHubDeviceAuth` class wrapping the three HTTP calls
  (device code request, token poll, user fetch) via `httpx`, injectable/fakeable.
- `web.py`: the two endpoints + lock-screen HTML/JS (button, code panel, poll loop),
  `create_app(db_path, github_auth=None)` accepts an injected fake for tests.
- `cli.py`: `github-link`, `github-unlink`, `github-status` sharing the device-flow
  helper.
- Dependency: `httpx` promoted to a runtime dependency (already present via the test
  stack).

## Testing

- Store: wrap/unwrap round trip; unlink removes access; unlock fails with wrong secret.
- Web (fake GitHub client): happy path issues a working session; wrong account rejected;
  GitHub down → clear error; expired code → retry error; `/api/status` reflects
  enrollment; TOTP-enabled vault still unlocks via GitHub without a TOTP code.
- CLI: link/status/unlink round trip with mocked device flow.
- Final headless-browser pass of the lock screen against the fake GitHub path.
