# Rotation Workflow and Doctor Filters Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add a safe `hv rotate` workflow for updating an existing secret and add project/environment filtering to vault doctor checks.

**Architecture:** Keep secret update behavior in `VaultStore` by reusing `add_secret` and `set_secret_metadata`. The CLI command should never print the new value and should record sanitized audit metadata. `doctor_report()` should delegate filtering to `store.list_secrets(project=..., environment=...)`.

**Tech Stack:** Python 3.12, Typer, pytest, existing encrypted SQLite store.

---

### Task 1: Add CLI rotate tests

**Objective:** Verify rotating a secret changes its value, updates rotation metadata, and does not leak secret values in output or audit logs.

**Files:**
- Modify: `tests/test_cli.py`

**Step 1: Write failing test**

Create `test_cli_rotate_updates_value_metadata_and_audit_without_leaking_values`:
- Initialize vault with `HENRY_VAULT_PASSWORD`.
- Add `TOKEN` with old value in project `demo`, env `prod`.
- Run:
  ```bash
  hv rotate TOKEN new-value --project demo --env prod --expires-at 2027-12-31 --rotation-url https://example.com/rotate
  ```
- Assert command succeeds and output contains `Rotated TOKEN`.
- Assert output does not contain old or new value.
- Assert `hv get TOKEN --project demo --env prod` returns new value.
- Assert `hv list` does not reveal the new value.
- Assert `hv audit --limit 20` contains `secret.rotate`, `TOKEN`, but not old or new value.

**Step 2: Run test to verify failure**

```bash
.venv/bin/pytest tests/test_cli.py::test_cli_rotate_updates_value_metadata_and_audit_without_leaking_values -q
```

Expected: FAIL because `rotate` command does not exist.

**Step 3: Implement minimal CLI**

Add `@app.command("rotate")` in `src/henry_vault/cli.py`:
- Unlock vault.
- Verify existing secret exists.
- Accept optional positional `value`; prompt with `getpass.getpass` if omitted.
- Re-save secret with the new value, preserving tags and notes from old metadata.
- Set metadata if `--expires-at` or `--rotation-url` is provided.
- Record `secret.rotate` audit event with secret name/project/env only.
- Print sanitized confirmation.

**Step 4: Run test to verify pass**

Run targeted test, then full CLI tests.

---

### Task 2: Add doctor filter tests

**Objective:** Let `doctor` focus on a project and/or environment.

**Files:**
- Modify: `tests/test_doctor.py`
- Modify: `tests/test_cli.py`

**Step 1: Write failing tests**

Core test:
- Add `BAD` in `demo/prod` with missing metadata.
- Add `OTHER` in `other/prod` with missing metadata.
- Call `doctor_report(store, project="demo", environment="prod")`.
- Assert issues mention `BAD` and do not mention `OTHER`.

CLI test:
- Add missing-metadata secrets in two projects.
- Run `hv doctor --project demo --env prod`.
- Assert output includes only scoped secret.

**Step 2: Run test to verify failure**

```bash
.venv/bin/pytest tests/test_doctor.py::test_doctor_report_filters_by_project_and_environment tests/test_cli.py::test_cli_doctor_filters_project_and_env -q
```

Expected: FAIL because filters are unsupported.

**Step 3: Implement minimal code**

Update `doctor_report(store, ..., project=None, environment=None)` and call `store.list_secrets(project=project, environment=environment)`.

Update CLI `doctor` command with optional `--project` and `--env`, pass them into `doctor_report`, and include the scope in the OK message when helpful.

**Step 4: Run tests to verify pass**

Run targeted tests, then full suite.

---

### Task 3: Documentation and verification

**Objective:** Document the rotation workflow and scoped doctor checks.

**Files:**
- Modify: `README.md`

**Steps:**
1. Add `hv rotate` examples and security notes.
2. Add `hv doctor --project ... --env ...` examples.
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
   git commit -m "feat: add rotate workflow and scoped doctor"
   ```
