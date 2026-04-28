# Henry Vault

Henry Vault is a local-first encrypted secrets manager with both a CLI and a web UI/API.

It stores secrets in an encrypted SQLite database at `~/.henry-vault/vault.db` by default.
Secret values are encrypted at rest with Fernet. The vault encryption key is derived from your master password with Argon2id and a per-vault random salt.

## Features

- Initialize an encrypted vault.
- Add/update secrets by name, project, and environment.
- Import `KEY=VALUE` pairs from `.env` files.
- List secret metadata without printing secret values.
- Reveal a secret only after unlocking with the master password.
- Export project/environment secrets as shell `export` lines.
- Run commands with secrets injected into the process environment.
- Export/import encrypted backup bundles with a separate backup password.
- Scan repos for likely leaked secrets and known vault secret values.
- Start a local FastAPI web UI/API with short-lived HttpOnly browser sessions and bearer-token API compatibility.
- Record audit events for unlocks, adds, gets, lists, scans, web logins, and web reveals.
- Track rotation metadata: expiry date and rotation URL/instructions.
- Rotate existing secrets without leaking old or new values in output/audit logs.
- `doctor` can focus on a project and/or environment.
- Install a user-level `hv` symlink.
- Emit a cron-compatible encrypted backup command.

## Install for local development

```bash
cd /home/henry/.openclaw/workspace/henry-vault
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

```bash
export HENRY_VAULT_PASSWORD='choose...word'

hv init
hv add OPENAI_API_KEY 'sk-your-key' --project discord-bot --env prod --tag ai
hv rotate OPENAI_API_KEY 'sk-new-key' --project discord-bot --env prod --expires-at 2027-05-01 --rotation-url 'https://platform.example/keys'
hv list --project discord-bot --env prod
hv get OPENAI_API_KEY --project discord-bot --env prod
hv export-env --project discord-bot --env prod
hv run --project discord-bot --env prod -- python bot.py
```

Use an isolated test database:

```bash
hv --db /tmp/henry-vault-test.db init
hv --db /tmp/henry-vault-test.db add TOKEN secret --project demo --env dev
```

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
- `scan.run`
- `web.login`
- `web.secret.list`
- `web.secret.reveal`

## Doctor checks and rotation metadata

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
15 2 * * * HENRY_VAULT_PASSWORD="$(cat /home/henry/.henry-vault/vault-password.txt)" /home/henry/.local/bin/hv --db /home/henry/.henry-vault/vault.db backup-export /home/henry/backups/henry-vault-$(date +\%F).hv.json --backup-password "$(cat /home/henry/.henry-vault/backup-password.txt)"
```

## Scan for leaked secrets

Basic pattern scan:

```bash
hv scan /home/henry/.openclaw/workspace/Discord
```

Match files against current vault values too:

```bash
hv scan /home/henry/.openclaw/workspace/Discord --match-vault
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

The web UI unlocks via `/api/login`, stores the browser session in a short-lived HttpOnly `hv_session` cookie, and supports `/api/logout`. API clients can still use the returned bearer token in the `Authorization` header. Repeated failed login attempts are rate-limited in memory.

Important: keep this local-only for now. Do not expose it to the public internet without TLS, CSRF protection, stronger rate limiting, and network controls such as Tailscale, WireGuard, or Cloudflare Access.

## API examples

```bash
curl http://127.0.0.1:8787/api/health

TOKEN=$(curl -s -X POST http://127.0.0.1:8787/api/login \
  -H 'Content-Type: application/json' \
  -d '{"password": "your-master-password"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

curl "http://127.0.0.1:8787/api/secrets?project=discord-bot&environment=prod" \
  -H "Authorization: Bearer $TOKEN"

curl "http://127.0.0.1:8787/api/secrets/reveal?name=OPENAI_API_KEY&project=discord-bot&environment=prod" \
  -H "Authorization: Bearer $TOKEN"

curl -X POST http://127.0.0.1:8787/api/logout \
  -H "Authorization: Bearer $TOKEN"
```

## Tests

```bash
.venv/bin/pytest
```

## Current security notes

This is a useful local-first vault, not a hardened team vault yet.

Good defaults already included:

- encrypted secret values at rest
- Argon2id key derivation
- per-vault salt
- database file chmod `0600`
- web server defaults to `127.0.0.1`
- list operations hide secret values
- scanner output masks secrets
- backup bundles encrypt plaintext values
- web UI uses short-lived HttpOnly browser sessions plus bearer-token API compatibility
- web login has in-memory failed-attempt lockout
- web UI avoids sending the master password on every reveal/list call after login
- audit log avoids storing secret values
- doctor reports operational hygiene issues

Future hardening ideas:

- passkeys/WebAuthn or YubiKey unlock
- CSRF protection for non-local deployments
- team sharing with per-secret access control
- packaged release via pipx or a private GitHub release
