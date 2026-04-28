# Henry Vault

Henry Vault is a local-first encrypted secrets manager with both a CLI and a web UI/API.

It stores secrets in an encrypted SQLite database at `~/.henry-vault/vault.db` by default.
Secret values are encrypted at rest with Fernet. The encryption key is derived from your master password with Argon2id and a per-vault random salt.

## MVP features

- Initialize an encrypted vault.
- Add/update secrets by name, project, and environment.
- List secret metadata without printing secret values.
- Reveal a secret only after unlocking with the master password.
- Export project/environment secrets as shell `export` lines.
- Run commands with secrets injected into the process environment.
- Start a local FastAPI web UI/API.

## Install for local development

```bash
cd /home/henry/.openclaw/workspace/henry-vault
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

## CLI quickstart

For interactive use, omit `HENRY_VAULT_PASSWORD` and the CLI will prompt.

```bash
export HENRY_VAULT_PASSWORD='choose-a-strong-master-password'

hv init
hv add OPENAI_API_KEY 'sk-your-key' --project discord-bot --env prod --tag ai
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

## Web UI

```bash
hv web --host 127.0.0.1 --port 8787
```

Then open:

```text
http://127.0.0.1:8787
```

Important: keep this local-only for now. Do not expose it to the public internet without TLS, stronger auth/session handling, rate limiting, and network controls such as Tailscale, WireGuard, or Cloudflare Access.

## API examples

```bash
curl http://127.0.0.1:8787/api/health

curl -X POST http://127.0.0.1:8787/api/secrets \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-master-password","project":"discord-bot","environment":"prod"}'

curl -X POST http://127.0.0.1:8787/api/secrets/reveal \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-master-password","name":"OPENAI_API_KEY","project":"discord-bot","environment":"prod"}'
```

## Tests

```bash
.venv/bin/pytest
```

## Current security notes

This is a solid MVP, not a hardened team vault yet.

Good defaults already included:

- encrypted secret values at rest
- Argon2id key derivation
- per-vault salt
- database file chmod `0600`
- web server defaults to `127.0.0.1`
- list operations hide secret values

Future hardening ideas:

- passkeys/WebAuthn or YubiKey unlock
- session-based web auth instead of sending password per request
- audit log
- secret rotation reminders
- repo secret scanner
- backup/export encrypted vault bundle
- team sharing with per-secret access control
