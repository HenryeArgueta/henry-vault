from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .doctor import doctor_report
from .errors import VaultLocked, VaultNotInitialized
from .store import DEFAULT_DB_PATH, VaultStore


class LoginRequest(BaseModel):
    password: str


@dataclass
class Session:
    password: str
    expires_at: datetime


@dataclass
class FailedLoginState:
    count: int = 0
    locked_until: datetime | None = None


COOKIE_NAME = "hv_session"


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
  <p class="muted">Local encrypted secrets dashboard. Unlock once; this browser uses a short-lived HttpOnly local session cookie.</p>
  <div class="card">
    <input id="password" type="password" placeholder="Master password" />
    <button onclick="login()">Unlock</button>
    <input id="project" placeholder="Project filter" />
    <input id="environment" placeholder="Environment filter" />
    <button onclick="loadSecrets()">List secrets</button>
    <button onclick="loadDoctor()">Doctor</button>
    <button onclick="loadAudit()">Audit</button>
    <button onclick="logout()">Logout</button>
  </div>
  <div class="card" style="margin-top: 1rem;">
    <h2>Doctor</h2>
    <pre id="doctor"></pre>
    <h2>Audit</h2>
    <pre id="audit"></pre>
  </div>
  <table>
    <thead><tr><th>Project</th><th>Env</th><th>Name</th><th>Tags</th><th>Updated</th><th>Reveal</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <script>
    let unlocked = false;
    async function login() {
      const res = await fetch('/api/login', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: document.getElementById('password').value})});
      if (!res.ok) { alert(res.status === 429 ? 'Too many failed attempts; try again later.' : 'Unlock failed'); return; }
      await res.json();
      unlocked = true;
      document.getElementById('password').value = '';
      alert('Unlocked for this browser.');
    }
    function authHeaders() { return {}; }
    async function logout() {
      await fetch('/api/logout', {method: 'POST'});
      unlocked = false;
      document.getElementById('rows').innerHTML = '';
      alert('Logged out.');
    }
    async function loadSecrets() {
      if (!unlocked) { alert('Unlock first'); return; }
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
    async function loadDoctor() {
      if (!unlocked) { alert('Unlock first'); return; }
      const params = new URLSearchParams();
      const project = document.getElementById('project').value;
      const environment = document.getElementById('environment').value;
      if (project) params.set('project', project);
      if (environment) params.set('environment', environment);
      const res = await fetch('/api/doctor?' + params.toString(), {headers: authHeaders()});
      if (!res.ok) { alert('Doctor failed'); return; }
      document.getElementById('doctor').textContent = JSON.stringify(await res.json(), null, 2);
    }
    async function loadAudit() {
      if (!unlocked) { alert('Unlock first'); return; }
      const res = await fetch('/api/audit?limit=25', {headers: authHeaders()});
      if (!res.ok) { alert('Audit failed'); return; }
      document.getElementById('audit').textContent = JSON.stringify(await res.json(), null, 2);
    }
  </script>
</body>
</html>
"""


def create_app(
    db_path: str | Path = DEFAULT_DB_PATH,
    *,
    max_failed_logins: int = 5,
    lockout_seconds: int = 60,
) -> FastAPI:
    app = FastAPI(title="Henry Vault", version="0.2.0")
    sessions: dict[str, Session] = {}
    failed_logins: dict[str, FailedLoginState] = {}

    def store_for_password(password: str) -> VaultStore:
        store = VaultStore(db_path)
        try:
            store.unlock(password)
        except VaultLocked as exc:
            raise HTTPException(status_code=401, detail="Invalid master password") from exc
        except VaultNotInitialized as exc:
            raise HTTPException(status_code=404, detail="Vault is not initialized") from exc
        return store

    def client_key(request: Request) -> str:
        if request.client is None:
            return "unknown"
        return request.client.host

    def ensure_not_locked_out(key: str) -> None:
        state = failed_logins.get(key)
        now = datetime.now(UTC)
        if state and state.locked_until and state.locked_until > now:
            raise HTTPException(status_code=429, detail="Too many failed login attempts; try again later")
        if state and state.locked_until and state.locked_until <= now:
            failed_logins.pop(key, None)

    def record_failed_login(key: str) -> None:
        state = failed_logins.setdefault(key, FailedLoginState())
        state.count += 1
        if state.count >= max_failed_logins:
            state.locked_until = datetime.now(UTC) + timedelta(seconds=lockout_seconds)

    def store_for_session(
        authorization: str = Header(default=""),
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
    ) -> VaultStore:
        scheme, _, header_token = authorization.partition(" ")
        token = ""
        if scheme.lower() == "bearer" and header_token:
            token = header_token
        elif hv_session:
            token = hv_session
        if not token:
            raise HTTPException(status_code=401, detail="Missing session token")
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
    def login(request: Request, response: Response, login_request: LoginRequest) -> dict[str, str | int]:
        key = client_key(request)
        ensure_not_locked_out(key)
        try:
            store = store_for_password(login_request.password)
        except HTTPException:
            record_failed_login(key)
            raise
        failed_logins.pop(key, None)
        token = secrets.token_urlsafe(32)
        ttl_seconds = 15 * 60
        sessions[token] = Session(password=login_request.password, expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds))
        response.set_cookie(
            COOKIE_NAME,
            token,
            max_age=ttl_seconds,
            httponly=True,
            samesite="strict",
            secure=False,
        )
        store.record_audit("web.login", status="success")
        return {"token": token, "expires_in": ttl_seconds}

    @app.post("/api/logout")
    def logout(response: Response, hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME), authorization: str = Header(default="")) -> dict[str, bool]:
        scheme, _, header_token = authorization.partition(" ")
        token = header_token if scheme.lower() == "bearer" and header_token else hv_session
        if token:
            sessions.pop(token, None)
        response.delete_cookie(COOKIE_NAME)
        return {"ok": True}

    @app.get("/api/secrets")
    def list_secrets(
        project: Optional[str] = None,
        environment: Optional[str] = None,
        store: VaultStore = Depends(store_for_session),
    ) -> list[dict]:
        items = store.list_secrets(project=project, environment=environment)
        store.record_audit("web.secret.list", project=project, environment=environment, message=f"count={len(items)}")
        return [item.__dict__ for item in items]

    @app.get("/api/secrets/reveal")
    def reveal(
        name: str,
        project: str = "default",
        environment: str = "default",
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, str]:
        secret = store.get_secret(name, project=project, environment=environment)
        if secret is None:
            store.record_audit("web.secret.reveal", secret_name=name, project=project, environment=environment, status="not_found")
            raise HTTPException(status_code=404, detail="Secret not found")
        store.record_audit("web.secret.reveal", secret_name=name, project=project, environment=environment)
        return {"name": secret.name, "value": secret.value}

    @app.get("/api/doctor")
    def doctor(
        project: Optional[str] = None,
        environment: Optional[str] = None,
        expiring_days: int = Query(default=30, ge=0),
        store: VaultStore = Depends(store_for_session),
    ) -> dict:
        report = doctor_report(store, expiring_days=expiring_days, project=project, environment=environment)
        store.record_audit("web.doctor", project=project, environment=environment, status="success" if report.ok else "issues", message=f"count={len(report.issues)}")
        return {"ok": report.ok, "issues": [issue.__dict__ for issue in report.issues]}

    @app.get("/api/audit")
    def audit(limit: int = Query(default=50, ge=1, le=500), store: VaultStore = Depends(store_for_session)) -> list[dict]:
        events = store.list_audit_events(limit=limit)
        store.record_audit("web.audit.list", message=f"count={len(events)}")
        return [event.__dict__ for event in events]

    return app
