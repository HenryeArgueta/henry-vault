# API Services Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add grouped API service credential storage (web UI form + display section, CLI service-* commands) and rename the bare `add/get/list/delete` secret commands to `secret-add/secret-get/secret-list/secret-delete`.

**Architecture:** Services are stored as regular secrets with `project=<slugified-service-name>` and `tags=["service"]`. No schema changes. New store helpers expose service-level operations. The web API gains a `tags` query param on `/api/secrets`. The web UI adds an "Add API Service" form and an "API Services" grouped display section that filters service secrets out of the regular Secrets table.

**Tech Stack:** Python/FastAPI (backend), inline HTML/CSS/JS (web UI), Typer (CLI), SQLite via existing `VaultStore`

---

## Files

- **Modify:** `src/henry_vault/cli.py` — rename commands, add service commands
- **Modify:** `src/henry_vault/store.py` — add `list_service_names`, `delete_service`
- **Modify:** `src/henry_vault/web.py` — web API tag param, new UI sections and JS
- **Modify:** `tests/test_cli.py` — update renamed command invocations, add service tests
- **Modify:** `tests/test_web.py` — add service API and UI tests

---

## Task 1: Rename secret CLI commands

Rename `add` to `secret-add`, `get` to `secret-get`, `list` to `secret-list`, `delete` to `secret-delete` in `cli.py`. Update all usages in `test_cli.py`.

**Files:**
- Modify: `src/henry_vault/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Rename the four commands in `cli.py`**

Change `@app.command()` on `def add(` to `@app.command("secret-add")` and rename the function to `def secret_add(` (body unchanged).

Change `@app.command("get")` on `def get_secret(` to `@app.command("secret-get")`.

Change `@app.command("list")` on `def list_secrets(` to `@app.command("secret-list")` and rename the function to `def secret_list(` (also rename the local variable `tags` to `tags_str` in the body echo line to avoid shadowing the parameter named `tag`).

Change `@app.command("delete")` on `def delete_secret(` to `@app.command("secret-delete")` and rename the function to `def secret_delete(`.

- [ ] **Step 2: Update `test_cli.py` — replace all old command names**

In every `runner.invoke(app, [...])` call, replace the string `"add"` with `"secret-add"`, `"get"` with `"secret-get"`, `"list"` with `"secret-list"`, `"delete"` with `"secret-delete"`. Do NOT rename `"password-add"`, `"password-get"`, `"attachment-add"`, etc.

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/henry_vault/cli.py tests/test_cli.py
git commit -m "feat: rename secret CLI commands to secret-add/get/list/delete"
```

---

## Task 2: Add service store helpers

Add `list_service_names` and `delete_service` to `VaultStore`.

**Files:**
- Modify: `src/henry_vault/store.py`
- Modify: `tests/test_store.py` (or create if absent — check with `ls tests/test_store.py`)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_store.py` (add a new test function at the end):

```python
def test_store_service_helpers(tmp_path):
    from henry_vault.store import SecretInput, VaultStore

    db = tmp_path / "vault.db"
    store = VaultStore(db)
    store.init("pw")
    store.unlock("pw")

    store.add_secret(SecretInput(name="BOT_TOKEN", value="tok-123", project="discord", tags=["service"]))
    store.add_secret(SecretInput(name="APP_ID", value="app-456", project="discord", tags=["service"]))
    store.add_secret(SecretInput(name="API_KEY", value="key-789", project="github", tags=["service"]))
    store.add_secret(SecretInput(name="OTHER", value="plain", project="default"))

    assert sorted(store.list_service_names()) == ["discord", "github"]

    deleted = store.delete_service("discord")
    assert deleted == 2
    assert store.list_service_names() == ["github"]
    assert store.get_secret("OTHER", project="default") is not None
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run pytest tests/test_store.py::test_store_service_helpers -v
```

Expected: FAIL with `AttributeError: 'VaultStore' object has no attribute 'list_service_names'`

- [ ] **Step 3: Add methods to `store.py` after `delete_secret`**

```python
def list_service_names(self) -> list[str]:
    self._require_unlocked()
    items = self.list_secrets(tags=["service"])
    seen: set[str] = set()
    names: list[str] = []
    for item in items:
        if item.project not in seen:
            seen.add(item.project)
            names.append(item.project)
    return sorted(names)

def delete_service(self, service: str) -> int:
    self._require_unlocked()
    fields = self.list_secrets(project=service, tags=["service"])
    count = 0
    for field in fields:
        if self.delete_secret(field.name, project=field.project, environment=field.environment):
            count += 1
    return count
```

- [ ] **Step 4: Run to verify it passes**

```bash
uv run pytest tests/test_store.py::test_store_service_helpers -v
```

Expected: PASS

- [ ] **Step 5: Run full suite**

```bash
uv run pytest tests/ -q
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/henry_vault/store.py tests/test_store.py
git commit -m "feat: add list_service_names and delete_service to VaultStore"
```

---

## Task 3: Add service CLI commands

Add `service-add`, `service-get`, `service-list`, `service-delete` to `cli.py`.

**Files:**
- Modify: `src/henry_vault/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_cli.py`:

```python
def test_cli_service_add_get_list_and_delete(tmp_path, monkeypatch):
    db_path = tmp_path / "vault.db"
    monkeypatch.setenv("HENRY_VAULT_PASSWORD", "pw")
    assert runner.invoke(app, ["--db", str(db_path), "init"]).exit_code == 0

    result = runner.invoke(
        app,
        ["--db", str(db_path), "service-add", "Discord", "BOT_TOKEN", "APP_ID"],
        input="tok-abc\napp-123\n",
    )
    assert result.exit_code == 0
    assert "Saved Discord" in result.output
    assert "tok-abc" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "service-get", "discord"])
    assert result.exit_code == 0
    assert "BOT_TOKEN=tok-abc" in result.output
    assert "APP_ID=app-123" in result.output

    result = runner.invoke(app, ["--db", str(db_path), "service-list"])
    assert result.exit_code == 0
    assert "discord" in result.output
    assert "BOT_TOKEN" in result.output
    assert "tok-abc" not in result.output

    result = runner.invoke(app, ["--db", str(db_path), "service-delete", "discord"], input="y\n")
    assert result.exit_code == 0
    assert "Deleted 2 field" in result.output

    result = runner.invoke(app, ["--db", str(db_path), "service-list"])
    assert "No services found" in result.output
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run pytest tests/test_cli.py::test_cli_service_add_get_list_and_delete -v
```

Expected: FAIL with `No such command 'service-add'`

- [ ] **Step 3: Add `_slugify` helper near the top of `cli.py`**

After the imports, before `app = typer.Typer(...)`:

```python
import re as _re

def _slugify(name: str) -> str:
    return _re.sub(r'[^a-z0-9-]+', '', name.lower().replace(' ', '-')).strip('-')
```

- [ ] **Step 4: Add four service commands to `cli.py` after `secret-delete`**

```python
@app.command("service-add")
def service_add(
    ctx: typer.Context,
    service: str,
    fields: Annotated[list[str], typer.Argument(help="Field names to add (values prompted hidden)")],
    env: EnvOpt = "default",
) -> None:
    """Add or update a named group of credentials (API keys, tokens, etc.)."""
    slug = _slugify(service)
    if not slug:
        typer.echo("Invalid service name.", err=True)
        raise typer.Exit(1)
    store = _unlock(
        ctx.obj["db"],
        totp_code=ctx.obj.get("totp_code"),
        recovery_code=ctx.obj.get("recovery_code"),
    )
    for field in fields:
        value = getpass.getpass(f"Value for {field}: ")
        store.add_secret(SecretInput(name=field, value=value, project=slug, environment=env, tags=["service"]))
        store.record_audit("service.add", secret_name=field, project=slug, environment=env)
    typer.echo(f"Saved {service} ({len(fields)} field(s)) as project '{slug}'.")


@app.command("service-get")
def service_get(ctx: typer.Context, service: str, env: EnvOpt = "default") -> None:
    """Print all field values for a named service as FIELD=value lines."""
    slug = _slugify(service)
    store = _unlock(
        ctx.obj["db"],
        totp_code=ctx.obj.get("totp_code"),
        recovery_code=ctx.obj.get("recovery_code"),
    )
    fields = store.list_secrets(project=slug, tags=["service"])
    if not fields:
        typer.echo(f"No service found matching '{service}'.", err=True)
        raise typer.Exit(1)
    for item in fields:
        secret = store.get_secret(item.name, project=item.project, environment=item.environment)
        if secret:
            store.record_audit("service.get", secret_name=item.name, project=slug, environment=item.environment)
            typer.echo(f"{item.name}={secret.value}")


@app.command("service-list")
def service_list(ctx: typer.Context) -> None:
    """List all services and their field names without revealing values."""
    store = _unlock(
        ctx.obj["db"],
        totp_code=ctx.obj.get("totp_code"),
        recovery_code=ctx.obj.get("recovery_code"),
    )
    names = store.list_service_names()
    if not names:
        typer.echo("No services found.")
        return
    store.record_audit("service.list", message=f"count={len(names)}")
    for name in names:
        field_items = store.list_secrets(project=name, tags=["service"])
        field_names = ", ".join(f.name for f in field_items)
        typer.echo(f"{name}: [{field_names}]")


@app.command("service-delete")
def service_delete(ctx: typer.Context, service: str) -> None:
    """Delete all fields belonging to a named service."""
    slug = _slugify(service)
    store = _unlock(
        ctx.obj["db"],
        totp_code=ctx.obj.get("totp_code"),
        recovery_code=ctx.obj.get("recovery_code"),
    )
    if not typer.confirm(f"Delete all fields for service '{slug}'?"):
        raise typer.Exit(0)
    count = store.delete_service(slug)
    store.record_audit("service.delete", project=slug, message=f"fields={count}")
    typer.echo(f"Deleted {count} field(s) for service '{slug}'.")
```

- [ ] **Step 5: Run test to verify it passes**

```bash
uv run pytest tests/test_cli.py::test_cli_service_add_get_list_and_delete -v
```

Expected: PASS

- [ ] **Step 6: Run full suite**

```bash
uv run pytest tests/ -q
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/henry_vault/cli.py tests/test_cli.py
git commit -m "feat: add service-add/get/list/delete CLI commands"
```

---

## Task 4: Web UI — service form, display, and API tag filter

### 4a — Add `tags` query param to `/api/secrets`

**Files:**
- Modify: `src/henry_vault/web.py`
- Modify: `tests/test_web.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_web.py`:

```python
def test_web_secrets_api_filters_by_tag(tmp_path):
    db_path = tmp_path / "vault.db"
    store = VaultStore(db_path)
    store.init("pw")
    store.unlock("pw")
    store.add_secret(SecretInput(name="BOT_TOKEN", value="tok", project="discord", tags=["service"]))
    store.add_secret(SecretInput(name="PLAIN", value="plain", project="default", tags=[]))

    client = TestClient(create_app(db_path))
    login = client.post("/api/login", json={"password": "pw"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    service_only = client.get("/api/secrets?tags=service", headers=headers).json()
    assert any(s["name"] == "BOT_TOKEN" for s in service_only)
    assert all(s["name"] != "PLAIN" for s in service_only)
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run pytest tests/test_web.py::test_web_secrets_api_filters_by_tag -v
```

Expected: FAIL (PLAIN appears in results because tags param is ignored).

- [ ] **Step 3: Update the `/api/secrets` endpoint in `web.py`**

Find `def list_secrets(` under `@app.get("/api/secrets")` and replace it with:

```python
@app.get("/api/secrets")
def list_secrets(
    project: Optional[str] = None,
    environment: Optional[str] = None,
    query: Optional[str] = None,
    tags: Optional[str] = None,
    store: VaultStore = Depends(store_for_session),
) -> list[dict]:
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    items = store.list_secrets(project=project, environment=environment, query=query, tags=tag_list)
    store.record_audit("web.secret.list", project=project, environment=environment, message=f"count={len(items)}")
    return [item.__dict__ for item in items]
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_web.py::test_web_secrets_api_filters_by_tag -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/henry_vault/web.py tests/test_web.py
git commit -m "feat: add tags query param to /api/secrets endpoint"
```

### 4b — Add HTML sections

- [ ] **Step 1: Write the failing test**

Add to `tests/test_web.py`:

```python
def test_web_index_includes_service_sections(tmp_path):
    db_path = tmp_path / "vault.db"
    VaultStore(db_path).init("pw")
    client = TestClient(create_app(db_path))
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="add-service-form"' in response.text
    assert 'id="service-name"' in response.text
    assert 'id="service-fields"' in response.text
    assert 'data-action="add-service-field"' in response.text
    assert 'id="service-groups"' in response.text
    assert 'Add API Service' in response.text
    assert 'API Services' in response.text
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run pytest tests/test_web.py::test_web_index_includes_service_sections -v
```

Expected: FAIL

- [ ] **Step 3: Add CSS for service UI elements**

In `web.py`, find `.section-card { margin-top: 1rem; }` inside the `<style>` block and add after it:

```css
    .service-group { margin-bottom: 1.25rem; }
    .service-group:last-child { margin-bottom: 0; }
    .service-group-header { margin-bottom: .5rem; align-items: center; }
    .service-group-header strong { font-size: 1rem; flex: 1 1 auto; }
    .service-field-row { display: flex; gap: .5rem; align-items: center; margin-bottom: .4rem; }
    .service-field-row input { flex: 1 1 160px; }
    .service-field-row .remove-btn { flex: 0 0 auto; }
    #service-fields { margin: .5rem 0; }
```

- [ ] **Step 4: Add the two new card sections to `web.py`**

Find the Secrets card section (the one with `<summary>Secrets</summary>`). Insert both new cards immediately **before** it:

```html
  <div class="card section-card">
    <details open>
      <summary>Add API Service</summary>
      <div class="section-body stack">
        <p class="muted">Save a group of related credentials (tokens, keys, IDs) under one service name.</p>
        <form id="add-service-form" class="stack">
          <div class="row">
            <label>Service name <input id="service-name" required placeholder="Discord" /></label>
            <label>Environment <input id="service-environment" list="environment-options" placeholder="default" /></label>
          </div>
          <div id="service-fields">
            <div class="service-field-row">
              <input class="service-field-name" placeholder="Field name (e.g. BOT_TOKEN)" />
              <input class="service-field-value" type="password" placeholder="Value" />
              <button type="button" class="fixed secondary remove-btn" data-action="remove-service-field">&#8722;</button>
            </div>
          </div>
          <div class="row">
            <button type="button" class="fixed secondary" data-action="add-service-field">+ Add field</button>
            <button type="submit">Save service</button>
          </div>
        </form>
      </div>
    </details>
  </div>

  <div class="card section-card">
    <details open>
      <summary>API Services</summary>
      <div class="section-body">
        <div id="service-groups" class="muted">Unlock to load services.</div>
      </div>
    </details>
  </div>
```

- [ ] **Step 5: Run test to verify it passes**

```bash
uv run pytest tests/test_web.py::test_web_index_includes_service_sections -v
```

Expected: PASS

- [ ] **Step 6: Run full suite**

```bash
uv run pytest tests/ -q
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/henry_vault/web.py tests/test_web.py
git commit -m "feat: add Add API Service form and API Services display card to web UI"
```

### 4c — Add JS functions and wire up events

- [ ] **Step 1: Write the failing test**

Add to `tests/test_web.py`:

```python
def test_web_index_includes_service_js(tmp_path):
    db_path = tmp_path / "vault.db"
    VaultStore(db_path).init("pw")
    client = TestClient(create_app(db_path))
    response = client.get("/")
    assert response.status_code == 200
    assert 'function addServiceField' in response.text
    assert 'function loadServices' in response.text
    assert 'function renderServiceGroups' in response.text
    assert 'function deleteService' in response.text
    assert 'tags=service' in response.text
    assert 'add-service-form' in response.text
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run pytest tests/test_web.py::test_web_index_includes_service_js -v
```

Expected: FAIL

- [ ] **Step 3: Add JS functions before `handleActionClick` in `web.py`**

Note: all user-supplied data passed to innerHTML is wrapped in `escapeHtml()` — same pattern used throughout this file for `renderSecretRows`, `renderPasswordRows`, etc.

```javascript
    function _slugify(name) {
      return name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '').replace(/^-+|-+$/g, '');
    }

    function addServiceField() {
      const container = document.getElementById('service-fields');
      const div = document.createElement('div');
      div.className = 'service-field-row';
      div.innerHTML = '<input class="service-field-name" placeholder="Field name" />'
        + '<input class="service-field-value" type="password" placeholder="Value" />'
        + '<button type="button" class="fixed secondary remove-btn" data-action="remove-service-field">&#8722;</button>';
      container.appendChild(div);
    }

    function removeServiceField(button) {
      const row = button.closest('.service-field-row');
      const container = document.getElementById('service-fields');
      if (row && container.querySelectorAll('.service-field-row').length > 1) row.remove();
    }

    async function addService(event) {
      event.preventDefault();
      if (!unlocked) { setStatus('Unlock first', 'error'); return false; }
      const serviceName = document.getElementById('service-name').value.trim();
      const slug = _slugify(serviceName);
      if (!slug) { setStatus('Enter a valid service name.', 'error'); return false; }
      const environment = document.getElementById('service-environment').value.trim() || 'default';
      const rows = document.querySelectorAll('#service-fields .service-field-row');
      const fields = [];
      for (const row of rows) {
        const name = row.querySelector('.service-field-name').value.trim();
        const value = row.querySelector('.service-field-value').value;
        if (name) fields.push({name, value});
      }
      if (!fields.length) { setStatus('Add at least one field.', 'error'); return false; }
      let saved = 0;
      for (const field of fields) {
        const res = await fetch('/api/secrets', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', ...csrfHeaders()},
          body: JSON.stringify({name: field.name, value: field.value, project: slug, environment, tags: ['service'], notes: ''}),
        });
        if (res.ok) saved++;
      }
      document.getElementById('service-name').value = '';
      document.getElementById('service-environment').value = '';
      document.querySelectorAll('#service-fields .service-field-row').forEach((r, i) => {
        if (i > 0) r.remove();
        else {
          r.querySelector('.service-field-name').value = '';
          r.querySelector('.service-field-value').value = '';
        }
      });
      setStatus('Saved ' + saved + ' field(s) for ' + serviceName + '.', 'success');
      await loadServices();
      return false;
    }

    async function loadServices() {
      if (!unlocked) return;
      const res = await fetch('/api/secrets?tags=service');
      if (!res.ok) return;
      renderServiceGroups(await res.json());
    }

    function renderServiceGroups(items) {
      const container = document.getElementById('service-groups');
      if (!items || !items.length) {
        container.textContent = 'No API services saved yet.';
        return;
      }
      const grouped = {};
      for (const item of items) {
        if (!grouped[item.project]) grouped[item.project] = [];
        grouped[item.project].push(item);
      }
      let html = '';
      for (const [project, fields] of Object.entries(grouped)) {
        html += '<div class="service-group">'
          + '<div class="service-group-header row">'
          + '<strong>' + escapeHtml(project) + '</strong>'
          + '<span class="muted">' + fields.length + ' field(s)</span>'
          + '<button class="fixed danger" type="button" data-action="delete-service" data-service="' + escapeHtml(project) + '">Delete service</button>'
          + '</div><table><thead><tr><th>Field</th><th>Value</th><th>Copy</th></tr></thead><tbody>';
        for (const f of fields) {
          html += '<tr><td><code>' + escapeHtml(f.name) + '</code></td>'
            + '<td><span class="muted">········</span></td>'
            + '<td><button class="fixed secondary" type="button" data-action="copy-service-field"'
            + ' data-name="' + escapeHtml(f.name) + '" data-project="' + escapeHtml(f.project) + '"'
            + ' data-environment="' + escapeHtml(f.environment) + '">Copy</button></td></tr>';
        }
        html += '</tbody></table></div>';
      }
      container.innerHTML = html;
    }

    async function copyServiceField(name, project, environment) {
      const params = new URLSearchParams({name, project, environment});
      if (window.ClipboardItem && navigator.clipboard?.write) {
        try {
          await navigator.clipboard.write([new ClipboardItem({
            'text/plain': fetch('/api/secrets/reveal?' + params.toString())
              .then(r => { if (!r.ok) throw new Error('failed'); return r.json(); })
              .then(d => new Blob([d.value], {type: 'text/plain'})),
          })]);
          setStatus('Copied ' + name + '.', 'success');
          return;
        } catch (error) {
          console.warn('ClipboardItem failed', error);
        }
      }
      const res = await fetch('/api/secrets/reveal?' + params.toString());
      if (!res.ok) { setStatus('Could not copy ' + name + '.', 'error'); return; }
      const data = await res.json();
      const copied = await copyTextToClipboard(data.value);
      if (!copied) { setStatus('Could not copy ' + name + '. Your browser may block clipboard access.', 'error'); return; }
      setStatus('Copied ' + name + '.', 'success');
    }

    async function deleteService(service) {
      if (!confirm("Delete all fields for service '" + service + "'?")) return;
      const buttons = document.querySelectorAll('[data-action="copy-service-field"][data-project="' + service + '"]');
      let deleted = 0;
      for (const btn of buttons) {
        const params = new URLSearchParams({name: btn.dataset.name, project: btn.dataset.project, environment: btn.dataset.environment});
        const res = await fetch('/api/secrets?' + params.toString(), {method: 'DELETE', headers: csrfHeaders()});
        if (res.ok) deleted++;
      }
      setStatus('Deleted ' + deleted + ' field(s) for service \'' + service + '\'.', 'success');
      await loadServices();
    }
```

- [ ] **Step 4: Add new actions to `handleActionClick` and new listeners**

Inside `handleActionClick`, in the `if/else if` chain, add:

```javascript
      else if (action === 'add-service-field') addServiceField();
      else if (action === 'remove-service-field') removeServiceField(button);
      else if (action === 'copy-service-field') copyServiceField(name, button.dataset.project, button.dataset.environment);
      else if (action === 'delete-service') deleteService(button.dataset.service);
```

Add at the bottom with the other `addEventListener` calls:

```javascript
    document.getElementById('add-service-form')?.addEventListener('submit', addService);
```

Update `applyFilters` to also call `loadServices`:

```javascript
    async function applyFilters(event) {
      if (event) event.preventDefault();
      await loadSecrets();
      await loadAttachments();
      await loadPasswords();
      await loadServices();
      return false;
    }
```

Update `loadSecrets` to filter out service-tagged secrets from the Secrets table:

```javascript
    async function loadSecrets() {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const res = await fetch('/api/secrets?' + secretQueryParams().toString());
      if (!res.ok) { setStatus('Could not list secrets', 'error'); return; }
      const all = await res.json();
      renderSecretRows(all.filter(s => !(s.tags || []).includes('service')));
      setStatus('Secrets loaded.');
    }
```

- [ ] **Step 5: Run test to verify it passes**

```bash
uv run pytest tests/test_web.py::test_web_index_includes_service_js -v
```

Expected: PASS

- [ ] **Step 6: Run full suite**

```bash
uv run pytest tests/ -q
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/henry_vault/web.py tests/test_web.py
git commit -m "feat: add service JS, form wiring, and filter services from secrets table"
```
