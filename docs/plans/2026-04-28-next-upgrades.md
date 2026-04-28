# Henry Vault Next Upgrades Implementation Plan

> **For Hermes:** Use test-driven-development skill to implement this plan task-by-task.

**Goal:** Complete the remaining recommended Henry Vault hardening and usability upgrades without exposing secret values.

**Architecture:** Keep sensitive behavior in the shared store/core where possible, then expose through Typer CLI and FastAPI. Add tests first for each behavior, verify RED, implement minimally, then run focused and full test suites.

**Tech Stack:** Python 3.12, Typer, FastAPI, SQLite, cryptography/Fernet, pytest.

---

## Task 1: Profile-aware `hv run`

**Objective:** Refuse to run commands when a project/environment profile has missing required secrets, unless `--allow-missing` is provided.

**Files:**
- Modify: `tests/test_cli.py`
- Modify: `src/henry_vault/cli.py`

**Steps:**
1. Add a CLI test that creates a profile requiring `API_KEY` and `DATABASE_URL`, stores only `API_KEY`, then invokes `hv run --project demo --env prod -- python -c ...`.
2. Verify the test fails because `hv run` currently starts the command.
3. Implement missing-required-secret preflight in `run_command`.
4. Add `--allow-missing` to bypass the preflight.
5. Verify focused tests and full test suite.

## Task 2: CSRF protection for web unsafe requests

**Objective:** Require a CSRF token for cookie-authenticated unsafe web requests while preserving bearer-token API clients.

**Files:**
- Modify: `tests/test_web.py`
- Modify: `src/henry_vault/web.py`

**Steps:**
1. Add tests proving login returns a CSRF token and cookie-authenticated `POST /api/logout` fails without the token.
2. Add tests proving logout succeeds with `X-CSRF-Token` and bearer-token clients remain supported.
3. Implement per-session CSRF tokens and validation for unsafe cookie-authenticated routes.
4. Update web JavaScript to send the token header.
5. Verify focused web tests and full test suite.

## Task 3: Better Doctor/Audit web rendering

**Objective:** Render Doctor and Audit results as structured cards/tables rather than raw JSON in `<pre>` blocks.

**Files:**
- Modify: `tests/test_web.py`
- Modify: `src/henry_vault/web.py`

**Steps:**
1. Add HTML tests asserting the dashboard includes doctor/audit table/card containers and no raw `<pre id="doctor">` / `<pre id="audit">` blocks.
2. Implement JavaScript render helpers that build HTML tables/cards from sanitized API responses.
3. Verify no secret values are included in API responses or rendered test fixtures.

## Task 4: Encrypted file attachments

**Objective:** Store encrypted binary/text attachments such as service account JSON, certs, private keys, and recovery codes.

**Files:**
- Modify: `src/henry_vault/store.py`
- Modify: `src/henry_vault/cli.py`
- Modify: `tests/test_store.py`
- Modify: `tests/test_cli.py`
- Possibly modify: backup import/export modules and tests.

**Steps:**
1. Add store tests for saving attachment bytes encrypted-at-rest and retrieving exact bytes.
2. Add CLI tests for `attachment-add`, `attachment-list`, and `attachment-get` without leaking content in list/audit output.
3. Add schema migration for attachments.
4. Implement store and CLI commands.
5. Include attachments in encrypted backups or explicitly document them as not in backups until implemented.

## Task 5: Packaged install/release workflow

**Objective:** Make installation/update easier through pipx and/or GitHub releases.

**Files:**
- Modify: `README.md`
- Create/modify: `.github/workflows/release.yml` if GitHub Actions is desired.
- Possibly modify: `pyproject.toml`

**Steps:**
1. Add tests or verification commands for package build metadata.
2. Add pipx install/update docs.
3. Add release workflow if repo should publish artifacts from Git tags.
4. Verify `python -m build` or equivalent succeeds.
