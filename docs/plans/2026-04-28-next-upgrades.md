# Henry Vault Next Upgrades Implementation Plan

> **For Hermes:** Use test-driven-development skill to implement this plan task-by-task.

**Goal:** Add the highest-value follow-up Henry Vault capabilities: .env import, encrypted backup/restore, repo secret scanning, and safer web session login.

**Architecture:** Keep the shared `VaultStore` core as the source of truth. Add separate modules for `.env` parsing, backup bundles, and scanning. Extend Typer CLI commands and FastAPI endpoints/UI. Preserve local-first defaults.

**Tech Stack:** Python 3.12, Typer, FastAPI, SQLite, cryptography/Fernet, pytest.

---

## Tasks

1. Add `.env` import/export helpers and CLI command `import-env`.
2. Add encrypted JSON backup bundle export/import commands.
3. Add repo scanner that detects common token patterns and `.env` files without printing full secrets.
4. Replace web password-per-request flow with short-lived in-memory bearer sessions while keeping old endpoints compatible if useful.
5. Update README and run full tests.
