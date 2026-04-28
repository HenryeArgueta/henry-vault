# Secret Discovery Filters Implementation Plan

> **For Hermes:** Use test-driven-development skill to implement this plan task-by-task.

**Goal:** Make it easier to find the right secret without revealing values by adding safe metadata-only filters for name search and tags.

**Architecture:** Keep filtering in `VaultStore.list_secrets()` so CLI, web, and future callers can share one sanitized metadata path. The CLI `list` command exposes `--query` and repeatable `--tag` options, records only counts in audit metadata, and never prints values.

**Tech Stack:** Python 3.12, Typer, SQLite-backed store, pytest.

---

### Task 1: Store metadata filters

**Objective:** Let `VaultStore.list_secrets()` filter by case-insensitive name substring and require all requested tags.

**Files:**
- Modify: `tests/test_store.py`
- Modify: `src/henry_vault/store.py`

**Steps:**
1. Add a failing test that creates several tagged secrets and calls `list_secrets(query="api", tags=["prod"])`.
2. Verify it fails because `list_secrets()` does not accept the new arguments.
3. Add `query` and `tags` arguments to `list_secrets()`.
4. Use SQL `LOWER(name) LIKE ?` for the query and in-Python metadata filtering for tags.
5. Run targeted store tests.

### Task 2: CLI list filters

**Objective:** Expose the metadata filters through `hv list --query ... --tag ...` without leaking values.

**Files:**
- Modify: `tests/test_cli.py`
- Modify: `src/henry_vault/cli.py`

**Steps:**
1. Add a failing CLI test that lists only tagged matching secrets and asserts plaintext values are absent.
2. Verify it fails because `list` lacks `--query`/`--tag`.
3. Add the Typer options and pass them to `store.list_secrets()`.
4. Include sanitized query/tag/count metadata in the audit message.
5. Run targeted CLI tests.

### Task 3: Documentation and verification

**Objective:** Document the new safe discovery workflow and commit the upgrade.

**Files:**
- Modify: `README.md`

**Steps:**
1. Add examples for `hv list --query api --tag prod`.
2. Run `.venv/bin/pytest`, `python3 -m compileall -q src tests`, `.venv/bin/hv --help`, and `git status --short`.
3. Commit with `feat: add secret discovery filters`.
