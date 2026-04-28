from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .errors import VaultLocked, VaultNotInitialized
from .store import DEFAULT_DB_PATH, VaultStore


class AuthFilter(BaseModel):
    password: str
    project: Optional[str] = None
    environment: Optional[str] = None


class RevealRequest(BaseModel):
    password: str
    name: str
    project: str = "default"
    environment: str = "default"


HTML = """
<!doctype html>
<html>
<head>
  <title>Henry Vault</title>
  <style>
    body { background: #0f172a; color: #e2e8f0; font-family: system-ui, sans-serif; margin: 2rem; }
    input, button { padding: .6rem; border-radius: .5rem; border: 1px solid #334155; margin: .25rem; }
    input { background: #020617; color: #e2e8f0; }
    button { background: #2563eb; color: white; cursor: pointer; }
    table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
    th, td { border-bottom: 1px solid #334155; padding: .75rem; text-align: left; }
    .muted { color: #94a3b8; }
    .card { background: #111827; border: 1px solid #334155; border-radius: 1rem; padding: 1rem; }
    code { color: #86efac; }
  </style>
</head>
<body>
  <h1>Henry Vault</h1>
  <p class="muted">Local encrypted secrets dashboard. Metadata is listed without revealing values.</p>
  <div class="card">
    <input id="password" type="password" placeholder="Master password" />
    <input id="project" placeholder="Project filter" />
    <input id="environment" placeholder="Environment filter" />
    <button onclick="loadSecrets()">List secrets</button>
  </div>
  <table>
    <thead><tr><th>Project</th><th>Env</th><th>Name</th><th>Tags</th><th>Updated</th><th>Reveal</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <script>
    async function loadSecrets() {
      const body = {
        password: document.getElementById('password').value,
        project: document.getElementById('project').value || null,
        environment: document.getElementById('environment').value || null
      };
      const res = await fetch('/api/secrets', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)});
      if (!res.ok) { alert('Could not unlock/list vault'); return; }
      const data = await res.json();
      document.getElementById('rows').innerHTML = data.map(s => `
        <tr>
          <td>${s.project}</td><td>${s.environment}</td><td><code>${s.name}</code></td>
          <td>${(s.tags || []).join(', ')}</td><td>${s.updated_at}</td>
          <td><button onclick="reveal('${s.name}','${s.project}','${s.environment}')">Reveal</button></td>
        </tr>`).join('');
    }
    async function reveal(name, project, environment) {
      const body = {password: document.getElementById('password').value, name, project, environment};
      const res = await fetch('/api/secrets/reveal', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
      if (!res.ok) { alert('Reveal failed'); return; }
      const data = await res.json();
      await navigator.clipboard.writeText(data.value).catch(() => {});
      alert(`${name}: ${data.value}\n\nCopied to clipboard if browser allowed it.`);
    }
  </script>
</body>
</html>
"""


def create_app(db_path: str | Path = DEFAULT_DB_PATH) -> FastAPI:
    app = FastAPI(title="Henry Vault", version="0.1.0")

    def unlocked_store(password: str) -> VaultStore:
        store = VaultStore(db_path)
        try:
            store.unlock(password)
        except VaultLocked as exc:
            raise HTTPException(status_code=401, detail="Invalid master password") from exc
        except VaultNotInitialized as exc:
            raise HTTPException(status_code=404, detail="Vault is not initialized") from exc
        return store

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return HTML

    @app.get("/api/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/api/secrets")
    def list_secrets(request: AuthFilter) -> list[dict]:
        store = unlocked_store(request.password)
        return [item.__dict__ for item in store.list_secrets(project=request.project, environment=request.environment)]

    @app.post("/api/secrets/reveal")
    def reveal(request: RevealRequest) -> dict[str, str]:
        store = unlocked_store(request.password)
        secret = store.get_secret(request.name, project=request.project, environment=request.environment)
        if secret is None:
            raise HTTPException(status_code=404, detail="Secret not found")
        return {"name": secret.name, "value": secret.value}

    return app
