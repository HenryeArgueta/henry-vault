# Web Hardening and Backup Safety Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Improve Henry Vault operational safety by making scheduled backup commands support separate vault and backup password files, and harden the local web UI session flow.

**Architecture:** Keep all sensitive business logic in shared modules. `install.py` owns command generation; `cli.py` exposes safer options. `web.py` keeps its in-memory session store but moves browser auth toward HttpOnly cookies while preserving bearer compatibility for API clients/tests.

**Tech Stack:** Python 3.12, Typer, FastAPI, pytest, stdlib `datetime`, `secrets`, shell quoting via `shlex`.

---

### Task 1: Safer scheduled backup command API

**Objective:** Replace the single password-file helper with separate vault unlock and backup encryption password files while preserving an explicit compatibility path.

**Files:**
- Modify: `tests/test_install.py`
- Modify: `tests/test_cli.py`
- Modify: `src/henry_vault/install.py`
- Modify: `src/henry_vault/cli.py`

**Step 1: Write failing tests**

Add unit test expectations that the generated command contains:
- `HENRY_VAULT_PASSWORD="$(cat <vault_password_file>)"`
- `--backup-password "$(cat <backup_password_file>)"`
- quoted paths with spaces
- no placeholder/broken fragments like `***` or unmatched `)`.

Add CLI test for:

```bash
hv backup-schedule-command --backup-path ... --vault-password-file ... --backup-password-file ... --hv-executable /tmp/hv
```

**Step 2: Run test to verify failure**

Run:

```bash
.venv/bin/pytest tests/test_install.py tests/test_cli.py::test_cli_backup_schedule_command -q
```

Expected: FAIL because the helper does not accept separate files yet.

**Step 3: Implement minimal code**

Update `backup_schedule_command()` signature to accept `vault_password_file` and `backup_password_file`. Generate a cron-safe command using `shlex.quote()` around paths.

Update CLI options:
- `--vault-password-file`
- `--backup-password-file`
- keep `--password-file` as a deprecated convenience alias that supplies both when the separate options are omitted.

**Step 4: Run tests to verify pass**

Run the targeted test command again.

---

### Task 2: Cookie-backed web sessions with logout

**Objective:** Let browsers store sessions in an HttpOnly cookie instead of JavaScript bearer-token memory, while preserving Authorization Bearer support for API clients.

**Files:**
- Modify: `tests/test_web.py`
- Modify: `src/henry_vault/web.py`

**Step 1: Write failing tests**

Add tests that:
- `/api/login` sets `hv_session` cookie with `HttpOnly` and `SameSite=Strict`.
- subsequent `/api/secrets` succeeds using only the cookie.
- `/api/logout` removes the session; subsequent cookie-only request fails with 401.
- bearer token still works for compatibility.

**Step 2: Run test to verify failure**

Run:

```bash
.venv/bin/pytest tests/test_web.py -q
```

Expected: FAIL because cookies/logout are not implemented yet.

**Step 3: Implement minimal code**

Update login route to receive `Response`, set `hv_session` cookie, and still return token for API compatibility. Add `Cookie` dependency to `store_for_session()` and fallback to bearer header. Add `/api/logout` endpoint to delete the server session and clear the cookie.

**Step 4: Run tests to verify pass**

Run web tests.

---

### Task 3: Basic web login rate limiting

**Objective:** Slow down local brute-force attempts against the master password.

**Files:**
- Modify: `tests/test_web.py`
- Modify: `src/henry_vault/web.py`

**Step 1: Write failing test**

Create app with `create_app(db_path, max_failed_logins=2, lockout_seconds=60)`. Make two wrong password attempts, then a correct attempt. Expected: 429 until lockout expires.

**Step 2: Run test to verify failure**

Run:

```bash
.venv/bin/pytest tests/test_web.py::test_web_login_rate_limits_failed_attempts -q
```

Expected: FAIL because rate limiting is absent.

**Step 3: Implement minimal code**

Track failed login count and lockout time in-memory by client host. On successful login, reset the failure state. Keep defaults conservative and local-friendly.

**Step 4: Run tests to verify pass**

Run web tests and full suite.

---

### Task 4: Documentation and verification

**Objective:** Document the safer backup command and hardened web session behavior.

**Files:**
- Modify: `README.md`

**Steps:**
1. Update backup scheduling docs to show separate password files.
2. Update web docs to mention HttpOnly local session cookie, logout, and lockout behavior.
3. Run:
   ```bash
   .venv/bin/pytest
   python3 -m compileall -q src tests
   .venv/bin/hv --help
   git status --short
   ```
4. Commit:
   ```bash
   git add .
   git commit -m "feat: harden web sessions and backup scheduling"
   ```
