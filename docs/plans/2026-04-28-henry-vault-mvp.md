# Henry Vault MVP Implementation Plan

> **For Hermes:** Use test-driven-development skill while implementing this plan task-by-task.

**Goal:** Build a hybrid encrypted secrets vault that works as both a CLI and a local web UI/API.

**Architecture:** Python package with a shared encrypted SQLite core, Typer CLI, and FastAPI web app. Secrets are encrypted with Fernet using a key derived from a master password via Argon2id and a per-vault random salt.

**Tech Stack:** Python 3.12, Typer, FastAPI, SQLite, cryptography, argon2-cffi, pytest.

---

## MVP Scope

1. Initialize an encrypted vault database.
2. Add/list/get/delete secrets grouped by project and environment.
3. Export secrets as shell env lines.
4. Run a command with vault secrets injected as environment variables.
5. Start a local FastAPI web UI/API for browsing metadata and revealing secrets after authentication.
6. Keep real secret values encrypted at rest.

## Security Defaults

- Local-first by default.
- Database path defaults to `~/.henry-vault/vault.db`.
- Master password comes from interactive prompt or `HENRY_VAULT_PASSWORD` for automation.
- Encrypted values are not printed during list operations.
- Web app binds to `127.0.0.1` by default.
- `.gitignore` blocks database files and `.env` files.

## Task Breakdown

1. Write core behavior tests for vault initialization, add/get/list/delete, environment export, and wrong-password failure.
2. Implement crypto and SQLite storage to pass core tests.
3. Write CLI tests for `init`, `add`, `get`, `list`, and `export-env`.
4. Implement Typer CLI.
5. Write web API tests for health, metadata listing, and authenticated reveal.
6. Implement FastAPI app and minimal HTML dashboard.
7. Add docs, Dockerfile, compose file, and verification commands.
