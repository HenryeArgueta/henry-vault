# Henry Vault Hardening Upgrades Implementation Plan

> **For Hermes:** Use test-driven-development skill to implement this plan task-by-task.

**Goal:** Add operational hardening features to Henry Vault: audit logs, rotation metadata/doctor checks, global CLI install helper, and encrypted backup scheduling helper.

**Architecture:** Keep `VaultStore` as the authoritative SQLite core. Extend schema with an audit table and optional metadata columns. Add pure helper modules where needed, expose via Typer CLI, and update web API to record session/list/reveal events.

**Tech Stack:** Python 3.12, Typer, FastAPI, SQLite, pytest, cron-compatible shell commands.

---

## Tasks

1. Add tests for audit recording and audit CLI output.
2. Implement `audit_events` table, `record_audit`, `list_audit_events`, and event calls from CLI/web.
3. Add tests for expiry metadata and `doctor` report.
4. Implement `expires_at`, `rotation_url`, `set-metadata`, and `doctor`.
5. Add tests for a global install helper that creates an executable symlink without requiring root.
6. Implement `install-cli` command.
7. Add tests for backup schedule command generation.
8. Implement `backup-schedule-command` that emits a cron-safe encrypted backup command.
9. Update README, run full tests, compile, and commit.
