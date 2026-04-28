from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .errors import VaultLocked, VaultNotInitialized
from .store import DEFAULT_DB_PATH, VaultStore


class LoginRequest(BaseModel):
    password: str


@dataclass
class Session:
    password: str
    expires_at: datetime


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
  <p class="muted">Local encrypted secrets dashboard. Unlock once; this tab uses a short-lived local bearer session.</p>
  <div class="card">
    <input id="password" type="password" placeholder="Master password" />
    <button onclick="login()">Unlock</button>
    <input id="project" placeholder="Project filter" />
    <input id="environment" placeholder="Environment filter" />
    <button onclick="loadSecrets()">List secrets</button>
  </div>
  <table>
    <thead><tr><th>Project</th><th>Env</th><th>Name</th><th>Tags</th><th>Updated</th><th>Reveal</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <script>
    let token = null;
    async function login() {
      const res = await fetch('/api/login', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: document.getElementById('password').value})});
      if (!res.ok) { alert('Unlock failed'); return; }
      token = (await res.json()).token;
      document.getElementById('password').value = '';
      alert('Unlocked for this browser tab.');
    }
    function authHeaders() { return {'Authorization': 'Bearer ' + token}; }
    async function loadSecrets() {
      if (!token) { alert('Unlock first'); return; }
      const params = new URLSearchParams();
      const project = document.getElementById('project').value;
      const environment = document.getElementById('environment').value;
      if (project) params.set('project', project);
      if (environment) params.set('environment', environment);
      const res = await fetch('/api/secrets?' + params.toString(), {headers: authHeaders()});
      if (!res.ok) { alert('Could not list vault'); return; }
      const data = await res.json();
      document.getElementById('rows').innerHTML = data.map(s => `
        <tr>
          <td>${s.project}</td><td>${s.environment}</td><td><code>${s.name}</code></td>
          <td>${(s.tags || []).join(', ')}</td><td>${s.updated_at}</td>
          <td><button onclick="reveal('${s.name}','${s.project}','${s.environment}')">Copy</button></td>
        </tr>`).join('');
    }
    async function reveal(name, project, environment) {
      const params = new URLSearchParams({name, project, environment});
      const res = await fetch('/api/secrets/reveal?' + params.toString(), {headers: authHeaders()});
      if (!res.ok) { alert('Reveal failed'); return; }
      const data = await res.json();
      await navigator.clipboard.writeText(data.value).catch(() => {});
      alert(`${name} copied to clipboard if browser allowed it.`);
    }
  </script>
</body>
</html>
"""


def create_app(db_path: str | Path = DEFAULT_DB_PATH) -> FastAPI:
    app = FastAPI(title="Henry Vault", version="0.2.0")
    sessions: dict[str, Session] = {}

    def store_for_password(password: str) -> VaultStore:
        store = VaultStore(db_path)
        try:
            store.unlock(password)
        except VaultLocked as exc:
            raise HTTPException(status_code=401, detail="Invalid master password") from exc
        except VaultNotInitialized as exc:
            raise HTTPException(status_code=404, detail="Vault is not initialized") from exc
        return store

    def store_for_session(authorization: str = Header(default="")) -> VaultStore:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="Missing bearer token")
        session = sessions.get(token)
        if session is None or session.expires_at <= datetime.now(UTC):
            sessions.pop(token, None)
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        return store_for_password(session.password)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return HTML

    @app.get("/api/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/api/login")
    def login(request: LoginRequest) -> dict[str, str | int]:
        store_for_password(request.password)
        token = secrets.token_urlsafe(32)
        ttl_seconds = 15 * 60
        sessions[token] = Session(password=request.password, expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds))
        return {"token": token, "expires_in": ttl_seconds}

    @app.get("/api/secrets")
    def list_secrets(
        project: Optional[str] = None,
        environment: Optional[str] = None,
        store: VaultStore = Depends(store_for_session),
    ) -> list[dict]:
        return [item.__dict__ for item in store.list_secrets(project=project, environment=environment)]

    @app.get("/api/secrets/reveal")
    def reveal(
        name: str,
        project: str = "default",
        environment: str = "default",
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, str]:
        secret = store.get_secret(name, project=project, environment=environment)
        if secret is None:
            raise HTTPException(status_code=404, detail="Secret not found")
        return {"name": secret.name, "value": secret.value}

    return app
