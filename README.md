# Henry Vault

Henry Vault is a local-first encrypted secrets manager with both a CLI and a web UI/API.

Install from the latest release:

```bash
pipx install 'git+https://github.com/HenryeArgueta/henry-vault.git@v0.4.0'
```

Or install from the latest branch tip:

```bash
pipx install 'git+https://github.com/HenryeArgueta/henry-vault.git'
```

It stores secrets in an encrypted SQLite database at `~/.henry-vault/vault.db` by default.
Secret values and attachment contents are encrypted at rest with Fernet. New vaults use a random vault encryption key that is wrapped by credentials derived from your master password and, if enabled, one-time recovery codes. Older vaults that have not been migrated may still derive the data-encryption key directly from the master password.

## Get started

The quickest path is:

1. Install Henry Vault.
2. Initialize a vault.
3. Add a secret.
4. Open the web UI.

```bash
hv init
hv add API_KEY 'your-secret-value' --project demo --env dev
hv list --project demo --env dev
hv get API_KEY --project demo --env dev
hv web --host 127.0.0.1 --port 8787
```

`add`, `get`, `list`, and `delete` are shorthand aliases for `secret-add`, `secret-get`, `secret-list`, and `secret-delete`.

Open `http://127.0.0.1:8787`.

If the vault already exists, log in with your master password. If TOTP 2FA is enabled, enter the current authenticator code too. If you ever need emergency recovery, use one of the one-time recovery codes.

If this is a brand-new vault, the web UI shows a first-run setup screen that walks you through creating the master password, scanning the authenticator QR code, and saving the recovery codes. Save the recovery codes immediately; they are shown only once.

If you are on another computer, keep the server bound to `127.0.0.1` and use an SSH tunnel.

From there, you can explore profiles, attachments, passwords, backups, and CSV import/export.

## Features

- Initialize an encrypted vault.
- Add/update secrets by name, project, and environment.
- Import `KEY=VALUE` pairs from `.env` files.
- List and filter secret metadata without printing secret values.
- Reveal a secret only after unlocking with the master password.
- Export project/environment secrets as shell `export` lines.
- Run commands with secrets injected into the process environment, with required-profile preflight checks.
- Store encrypted file attachments such as service account JSON, certs, private keys, and recovery codes.
- Export/import encrypted backup bundles with a separate backup password.
- Export/import all secrets and passwords in a single CSV file.
- Use the same CSV export/import workflow from the web UI.
- Prune old Henry Vault backup bundles safely with dry-run by default.
- Scan repos for likely leaked secrets and known vault secret values.
- Start a local FastAPI web UI/API with short-lived HttpOnly browser sessions and bearer-token API compatibility.
- Enable, rotate, regenerate, or disable authenticator-app 2FA and recovery codes from the CLI.
- View doctor issues and sanitized audit events from the web UI/API.
- Record audit events for unlocks, adds, gets, lists, scans, web logins, and web reveals.
- Track rotation metadata: expiry date and rotation URL/instructions.
- Rotate existing secrets without leaking old or new values in output/audit logs.
- Define project/environment profiles with required secret manifests.
- `doctor` can focus on a project and/or environment.
- Install a user-level `hv` symlink.
- Emit a cron-compatible encrypted backup command.

## Install for local development

```bash
cd /path/to/henry-vault
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

Install a convenient `hv` symlink:

```bash
.venv/bin/hv install-cli
```

If `~/.local/bin` is on your `PATH`, `hv` will work from anywhere.

## CLI quickstart

For interactive use, omit `HENRY_VAULT_PASSWORD` and the CLI will prompt.

If you want a simple copy/paste demo, use a throwaway vault database and walk through the basics:

```bash
export HENRY_VAULT_PASSWORD='***'

hv --db /tmp/henry-vault-demo.db init
hv --db /tmp/henry-vault-demo.db add OPENAI_API_KEY 'your-secret-value' --project demo --env dev --tag ai
hv --db /tmp/henry-vault-demo.db list --project demo --env dev
hv --db /tmp/henry-vault-demo.db get OPENAI_API_KEY --project demo --env dev
hv --db /tmp/henry-vault-demo.db export-env --project demo --env dev
```

To initialize from the CLI with authenticator-app 2FA and one-time recovery codes:

```bash
hv init --with-2fa --recovery-codes 8
```

Save the printed provisioning URI and recovery codes immediately. For future CLI unlocks, enter the TOTP code when prompted, or pass it non-interactively with `--totp-code` / `HENRY_VAULT_TOTP_CODE`. Recovery codes are emergency unlock credentials; each code can be used once with `--recovery-code` / `HENRY_VAULT_RECOVERY_CODE`.

For an existing vault, use the 2FA lifecycle commands:

```bash
hv two-factor-enable --recovery-codes 8
hv recovery-codes-regenerate --recovery-codes 8
hv totp-rotate
hv two-factor-disable
```

Regenerating recovery codes invalidates old unused codes. Rotating TOTP prints a new provisioning URI; scan it in your authenticator app before relying on the new code. Disabling 2FA invalidates all recovery codes.

When you're ready for a real project vault, the common workflow looks like this:

```bash
export HENRY_VAULT_PASSWORD='***'

hv init
hv add OPENAI_API_KEY 'your-secret-value' --project discord-bot --env prod --tag ai
hv rotate OPENAI_API_KEY 'your-new-secret-value' --project discord-bot --env prod --expires-at 2027-05-01 --rotation-url 'https://platform.example/keys'
hv profile-set --project discord-bot --env prod --required OPENAI_API_KEY --required DISCORD_TOKEN
hv list --project discord-bot --env prod
hv list --project discord-bot --env prod --query api --tag ai
hv get OPENAI_API_KEY --project discord-bot --env prod
hv export-env --project discord-bot --env prod
hv run --project discord-bot --env prod -- python bot.py
# Use this only when you intentionally want to run despite missing profile requirements:
hv run --project discord-bot --env prod --allow-missing -- python bot.py
```

## Encrypted file attachments

Use attachments for sensitive files that should stay encrypted at rest, such as service account JSON, certificates, private keys, and recovery codes.

```bash
hv attachment-add SERVICE_ACCOUNT_JSON ./service-account.json \
  --project discord-bot \
  --env prod \
  --content-type application/json

hv attachment-list --project discord-bot --env prod
hv attachment-get SERVICE_ACCOUNT_JSON ./service-account.restored.json --project discord-bot --env prod
```

`attachment-list` prints metadata only. Attachment contents are encrypted in the vault database and included inside encrypted backup bundles.

Use an isolated test database:

```bash
hv --db /tmp/henry-vault-test.db init
hv --db /tmp/henry-vault-test.db add TOKEN secret --project demo --env dev
```

## Find secrets safely

`hv list` only prints metadata, never secret values. Use `--query` for a case-insensitive name substring and repeat `--tag` to require one or more tags:

```bash
hv list --query api
hv list --project discord-bot --env prod --query token --tag prod --tag discord
```

These filters are useful when a vault has many project/environment entries but you do not want to reveal values just to locate the right secret.

## Import a .env file

```bash
hv import-env /path/to/.env --project discord-bot --env prod --tag imported
```

Supported syntax:

```text
KEY=value
export KEY=value
QUOTED="hello world"
SINGLE='hello world'
```

## Export/import credentials as CSV

Export all secrets and passwords into one CSV file:

```bash
hv export-credentials ~/henry-vault-credentials.csv
```

Import the same CSV into a fresh vault:

```bash
hv import-credentials ~/henry-vault-credentials.csv
```

The CSV includes plaintext values for portability, so keep it encrypted-at-rest or delete it after use.

The same export/import flow is available in the web UI under the Passwords section.

## Audit log

Show recent audit events without secret values:

```bash
hv audit --limit 25
```

Events include actions like:

- `vault.unlock`
- `secret.add`
- `secret.get`
- `secret.list`
- `secret.rotate`
- `secret.metadata`
- `profile.set`
- `profile.list`
- `profile.delete`
- `scan.run`
- `web.login`
- `web.secret.list`
- `web.secret.reveal`
- `web.doctor`
- `web.audit.list`

## Doctor checks and project profiles

Define the required secrets for a project/environment:

```bash
hv profile-set \
  --project discord-bot \
  --env prod \
  --required DISCORD_TOKEN \
  --required OPENAI_API_KEY \
  --required DATABASE_URL \
  --notes 'Production Discord bot runtime requirements'

hv profile-list --project discord-bot
```

Profiles store required secret names only, not secret values. `hv doctor --project ... --env ...` uses them to flag missing deployment requirements before you start a service. `hv run --project ... --env ...` also refuses to start when the exact project/environment profile is missing required secrets; pass `--allow-missing` only for intentional break-glass runs.

Delete a profile when it is no longer needed:

```bash
hv profile-delete --project discord-bot --env prod
```

Set metadata without changing the value:

```bash
hv set-metadata OPENAI_API_KEY \
  --project discord-bot \
  --env prod \
  --expires-at 2027-05-01 \
  --rotation-url 'https://platform.example/keys'
```

Rotate an existing secret value without printing the old or new value in command output or audit logs:

```bash
hv rotate OPENAI_API_KEY \
  --project discord-bot \
  --env prod \
  --expires-at 2027-05-01 \
  --rotation-url 'https://platform.example/keys'
```

You can also pass the new value as an argument for automation, but interactive prompting is safer for normal terminal use.

Run hygiene checks:

```bash
hv doctor
hv doctor --expiring-days 60
hv doctor --project discord-bot --env prod
```

Doctor flags:

- missing required secrets from project profiles
- expired secrets
- secrets expiring soon
- missing expiry dates
- missing rotation URLs/instructions

## Encrypted backups

Backups are encrypted JSON bundles. Use a separate strong backup password.

```bash
hv backup-export ~/henry-vault-backup.hv.json
hv backup-import ~/henry-vault-backup.hv.json
```

For automation/testing, you can pass the backup password directly:

```bash
hv backup-export /tmp/backup.hv.json --backup-password 'strong-backup-password'
hv backup-import /tmp/backup.hv.json --backup-password 'strong-backup-password'
```

Prune old backup bundles safely. This only considers valid Henry Vault `*.hv.json` backup files and runs as a dry run unless `--delete` is passed:

```bash
hv backup-prune ~/backups --keep-days 30
hv backup-prune ~/backups --keep-days 30 --delete
```

Emit a cron-compatible backup command using separate files for vault unlock and backup encryption passwords:

```bash
hv backup-schedule-command \
  --backup-path ~/backups/henry-vault-$(date +%F).hv.json \
  --vault-password-file ~/.henry-vault/vault-password.txt \
  --backup-password-file ~/.henry-vault/backup-password.txt \
  --hv-executable ~/.local/bin/hv
```

`--password-file` is still accepted as a deprecated shortcut when you intentionally want one file to serve both purposes, but separate files are safer.

Example crontab entry for 2:15 AM daily:

```cron
15 2 * * * HENRY_VAULT_PASSWORD="$(cat "$HOME/.henry-vault/vault-password.txt")" "$HOME/.local/bin/hv" --db "$HOME/.henry-vault/vault.db" backup-export "$HOME/backups/henry-vault-$(date +\%F).hv.json" --backup-password "$(cat "$HOME/.henry-vault/backup-password.txt")"
```

## Scan for leaked secrets

Basic pattern scan:

```bash
hv scan /path/to/your/target-repo
```

Match files against current vault values too:

```bash
hv scan /path/to/your/target-repo --match-vault
```

Exit codes:

- `0`: no findings
- `2`: findings detected

The scanner masks secret values in output.

## Web UI

```bash
hv web --host 127.0.0.1 --port 8787
```

Then open:

```text
http://127.0.0.1:8787
```

The web UI unlocks via `/api/login`, stores the browser session in a short-lived HttpOnly `hv_session` cookie, and supports `/api/logout`. Login accepts the master password plus optional TOTP or recovery code factors. Login also returns a per-session CSRF token; the browser sends it as `X-CSRF-Token` for cookie-authenticated unsafe requests. API clients can still use the returned bearer token in the `Authorization` header. Repeated failed login attempts are rate-limited in memory.

The dashboard includes buttons for listing secret metadata, running doctor checks, viewing sanitized audit events, and managing passwords. The Passwords section also supports CSV export/import from the browser.

First-run onboarding flow:

1. Open the web UI.
2. Create the vault master password.
3. Scan the QR code with your authenticator app.
4. Save the one-time recovery codes immediately.
5. Use the login screen for future unlocks with your master password plus TOTP, or a recovery code if needed.

Important: keep this local-only by default. Do not expose it to the public internet without TLS, stronger rate limiting, and network controls such as Tailscale, WireGuard, or Cloudflare Access.

## Unlock with GitHub (web UI)

When internet is available, you can unlock the web UI by signing in with your GitHub account instead of typing the master password. If GitHub is unreachable, the master password (and recovery codes) always still work — GitHub can never lock you out.

One-time setup:

1. Create a free GitHub OAuth App (github.com → Settings → Developer settings → OAuth Apps → New). Any name/URL; check **Enable Device Flow**. No callback URL or client secret is needed — only the public client ID.
2. Link your account (prompts for your master password, then walks you through a one-time GitHub device sign-in):

```bash
hv github-link --client-id YOUR_CLIENT_ID
hv github-status
```

After that, the web lock screen shows a "Sign in with GitHub" button: click it, enter the short code at github.com/login/device, and the vault unlocks. Only the exact GitHub account you linked (matched by immutable user ID) can unlock. Remove it any time with `hv github-unlink`.

How it works and what it protects: enrollment wraps the vault key with a random device secret stored in `~/.henry-vault/github-device.secret` (chmod 0600), and a successful GitHub sign-in releases it — the same trust model as recovery codes. GitHub receives no vault data and no scopes are requested; the GitHub token is used once to read your user ID and then discarded. GitHub unlock skips the vault TOTP prompt since your GitHub account brings its own 2FA. Someone with full access to this machine could bypass GitHub by combining the secret file with the database, so the master password remains the real cryptographic protection.

## API examples

```bash
curl http://127.0.0.1:8787/api/health

LOGIN_JSON=$(curl -s -X POST http://127.0.0.1:8787/api/login \
  -H 'Content-Type: application/json' \
  -d '{"password": "your-master-password", "totp_code": "123456"}')

TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["token"])' "$LOGIN_JSON")
CSRF_TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["csrf_token"])' "$LOGIN_JSON")

curl "http://127.0.0.1:8787/api/secrets?project=demo&environment=dev" \
  -H "Authorization: Bearer $TOKEN"

curl "http://127.0.0.1:8787/api/secrets/reveal?name=API_KEY&project=demo&environment=dev" \
  -H "Authorization: Bearer $TOKEN"

curl "http://127.0.0.1:8787/api/doctor?project=demo&environment=dev" \
  -H "Authorization: Bearer $TOKEN"

curl "http://127.0.0.1:8787/api/audit?limit=25" \
  -H "Authorization: Bearer $TOKEN"

curl -X POST http://127.0.0.1:8787/api/logout \
  -H "Authorization: Bearer $TOKEN"
```

If you enabled TOTP 2FA and need emergency access, use one of your one-time recovery codes as the `recovery_code` field when logging in. Cookie-authenticated browser requests use `X-CSRF-Token`; bearer-token API requests do not need the CSRF header.

## Install/update with pipx or a GitHub release

From a local checkout:

```bash
pipx install /path/to/henry-vault
pipx upgrade henry-vault
```

From GitHub, use the published tag for a stable install:

```bash
pipx install 'git+https://github.com/HenryeArgueta/henry-vault.git@v0.4.0'
```

You can also install from the latest branch tip:

```bash
pipx install 'git+https://github.com/HenryeArgueta/henry-vault.git'
pipx upgrade henry-vault
```

Tagged releases are built by `.github/workflows/release.yml`. Push a tag like `v0.2.0` to run tests, build the wheel/source distribution, and attach `dist/*` to a GitHub release.

## Tests

```bash
.venv/bin/pytest
```

## Security model

Henry Vault is designed as a local-first personal vault. It is useful for a single-user workstation or a private server you control, but it is not a hardened multi-user/team vault.

What is encrypted:

- secret values
- password entries
- attachment contents
- encrypted backup bundle contents
- TOTP setup secret when authenticator-app 2FA is enabled
- recovery-code key material used for emergency unlock

What is intentionally not encrypted:

- secret names, projects, environments, tags, notes, timestamps, expiry dates, and rotation URLs
- attachment names, filenames, content types, sizes, and notes
- password entry names, URLs, usernames, notes, and timestamps
- sanitized audit log metadata

Unlock model:

- The master password is the primary vault secret.
- The vault encryption key is wrapped with a key derived from the master password using Argon2id and a per-vault random salt.
- Without 2FA, normal unlock requires the master password.
- With TOTP 2FA enabled, normal unlock requires the master password plus a current RFC 6238 authenticator code.
- TOTP protects normal unlock attempts, but it does not encrypt the vault data by itself.
- One-time recovery codes are emergency unlock credentials. A valid unused recovery code can unlock the vault by itself, without the master password, so store them with the same care you would give an emergency vault key.
- Each recovery code can be used once and is shown only once during setup.
- If you forget the master password and do not have an unused recovery code, there is no reset path for that vault. Restore from an encrypted backup or CSV export if you have one, then create a new vault password.

Local web security defaults:

- web server defaults to `127.0.0.1`
- browser sessions use short-lived HttpOnly cookies
- bearer-token API compatibility is available for scripts
- cookie-authenticated unsafe requests require a per-session CSRF token
- repeated failed login attempts are rate-limited in memory
- login failure responses are intentionally generic
- unauthenticated `/api/status` only reports whether a vault exists; 2FA state is available after login via `/api/session/status`
- security headers include a hash-based Content Security Policy, `X-Content-Type-Options`, `Referrer-Policy`, and clickjacking protection
- the web UI avoids sending the master password on every reveal/list call after login

Operational safety defaults:

- database file chmod `0600`
- list operations hide secret values
- scanner output masks secrets
- backup bundles encrypt plaintext values and attachment contents
- audit log avoids storing secret values
- doctor reports operational hygiene issues

Important: keep the web UI local-only by default. Do not expose it to the public internet without TLS, stronger rate limiting, and network controls such as Tailscale, WireGuard, or Cloudflare Access.

Future hardening ideas:

- passkeys/WebAuthn or YubiKey unlock
- team sharing with per-secret access control
- signed release artifacts and published checksums
