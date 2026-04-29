from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Cookie, Depends, File, FastAPI, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .doctor import doctor_report
from .errors import VaultLocked, VaultNotInitialized
from .store import AttachmentInput, DEFAULT_DB_PATH, PasswordInput, SecretInput, VaultStore


class AddSecretRequest(BaseModel):
    name: str
    value: str
    project: str = "default"
    environment: str = "default"
    tags: list[str] = []
    notes: str = ""


class AddPasswordRequest(BaseModel):
    name: str
    url: str
    username: str
    password: str
    note: str = ""


class LoginRequest(BaseModel):
    password: str


@dataclass
class Session:
    password: str
    expires_at: datetime
    csrf_token: str


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
    :root {
      color-scheme: dark;
    }
    body {
      --page-bg: #09090b;
      --panel-bg: rgba(24, 24, 27, 0.82);
      --text-color: #f4f1ea;
      --muted-color: #b4a79a;
      --border-color: rgba(213, 180, 118, 0.24);
      --input-bg: rgba(10, 10, 12, 0.9);
      --button-bg: linear-gradient(135deg, #d4af37 0%, #9c7a2f 52%, #6e5320 100%);
      --button-secondary-bg: rgba(48, 38, 28, 0.9);
      --danger-bg: linear-gradient(135deg, #c2410c 0%, #7c2d12 100%);
      --row-alt-bg: rgba(212, 175, 55, 0.06);
      --accent-glow: rgba(212, 175, 55, 0.18);
      background:
        radial-gradient(circle at top, rgba(212, 175, 55, 0.12), transparent 34%),
        radial-gradient(circle at bottom right, rgba(120, 53, 15, 0.18), transparent 24%),
        var(--page-bg);
      color: var(--text-color);
      font-family: "Inter", "Segoe UI", system-ui, sans-serif;
      margin: 2rem;
      max-width: 1200px;
    }
    body[data-theme="pearl-light"] {
      color-scheme: light;
      --page-bg: #f8f5ef;
      --panel-bg: rgba(255, 255, 255, 0.92);
      --text-color: #1f2937;
      --muted-color: #5b6472;
      --border-color: rgba(122, 92, 26, 0.18);
      --input-bg: #ffffff;
      --button-bg: linear-gradient(135deg, #d1a84a 0%, #b8892f 100%);
      --button-secondary-bg: #5b6472;
      --danger-bg: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
      --row-alt-bg: rgba(31, 41, 55, 0.04);
      --accent-glow: rgba(184, 137, 47, 0.12);
    }
    body[data-theme="royal-indigo"] {
      color-scheme: dark;
      --page-bg: #0a1026;
      --panel-bg: rgba(18, 24, 54, 0.88);
      --text-color: #f4f7ff;
      --muted-color: #bbc7ff;
      --border-color: rgba(122, 153, 255, 0.26);
      --input-bg: rgba(9, 14, 33, 0.96);
      --button-bg: linear-gradient(135deg, #7c8cff 0%, #4c63d2 100%);
      --button-secondary-bg: rgba(40, 50, 94, 0.92);
      --danger-bg: linear-gradient(135deg, #ef4444 0%, #8b1f3d 100%);
      --row-alt-bg: rgba(124, 140, 255, 0.08);
      --accent-glow: rgba(124, 140, 255, 0.18);
    }
    body[data-theme="emerald-velvet"] {
      color-scheme: dark;
      --page-bg: #07150f;
      --panel-bg: rgba(10, 35, 25, 0.9);
      --text-color: #effdf7;
      --muted-color: #a9d8bf;
      --border-color: rgba(110, 203, 163, 0.24);
      --input-bg: rgba(5, 20, 14, 0.96);
      --button-bg: linear-gradient(135deg, #49c98e 0%, #13795a 100%);
      --button-secondary-bg: rgba(24, 72, 55, 0.9);
      --danger-bg: linear-gradient(135deg, #f97316 0%, #8a3410 100%);
      --row-alt-bg: rgba(73, 201, 142, 0.08);
      --accent-glow: rgba(73, 201, 142, 0.18);
    }
    body[data-theme="rose-quartz"] {
      color-scheme: light;
      --page-bg: #fff5f8;
      --panel-bg: rgba(255, 255, 255, 0.94);
      --text-color: #2f2230;
      --muted-color: #77596f;
      --border-color: rgba(180, 104, 147, 0.18);
      --input-bg: #ffffff;
      --button-bg: linear-gradient(135deg, #e87ca1 0%, #b94f7c 100%);
      --button-secondary-bg: #7b6174;
      --danger-bg: linear-gradient(135deg, #db2777 0%, #a21caf 100%);
      --row-alt-bg: rgba(232, 124, 161, 0.08);
      --accent-glow: rgba(232, 124, 161, 0.14);
    }
    body[data-theme="sunset-amber"] {
      color-scheme: dark;
      --page-bg: #181006;
      --panel-bg: rgba(47, 25, 7, 0.9);
      --text-color: #fff4df;
      --muted-color: #e7c78a;
      --border-color: rgba(236, 179, 84, 0.22);
      --input-bg: rgba(22, 13, 3, 0.96);
      --button-bg: linear-gradient(135deg, #f9a825 0%, #c96a12 100%);
      --button-secondary-bg: rgba(84, 52, 16, 0.92);
      --danger-bg: linear-gradient(135deg, #f97316 0%, #9a3412 100%);
      --row-alt-bg: rgba(249, 168, 37, 0.08);
      --accent-glow: rgba(249, 168, 37, 0.18);
    }
    h1 {
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
      letter-spacing: .04em;
      margin-bottom: .25rem;
    }
    .theme-badge {
      display: inline-flex;
      align-items: center;
      gap: .35rem;
      margin-left: .6rem;
      padding: .25rem .55rem;
      border-radius: 999px;
      border: 1px solid var(--border-color);
      background: linear-gradient(135deg, rgba(212, 175, 55, 0.14), rgba(255, 255, 255, 0.04));
      box-shadow: 0 0 0 1px var(--accent-glow), 0 10px 22px rgba(0, 0, 0, 0.14) inset;
      color: var(--text-color);
      font-size: .8rem;
      text-transform: uppercase;
      letter-spacing: .12em;
    }
    input, button, textarea, select { padding: .6rem; border-radius: .5rem; border: 1px solid var(--border-color); margin: .25rem; }
    input, textarea { background: var(--input-bg); color: var(--text-color); }
    input::placeholder, textarea::placeholder { color: color-mix(in srgb, var(--muted-color) 82%, transparent); }
    button { background: var(--button-bg); color: #fff8e7; cursor: pointer; box-shadow: 0 10px 20px rgba(0, 0, 0, 0.12); }
    button:hover { filter: brightness(1.05); transform: translateY(-1px); }
    button:focus-visible, input:focus-visible, textarea:focus-visible, select:focus-visible {
      outline: 2px solid #e6c15a;
      outline-offset: 2px;
    }
    button.secondary { background: var(--button-secondary-bg); }
    button.danger { background: var(--danger-bg); }
    table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
    tbody tr:nth-child(even) { background: var(--row-alt-bg); }
    th, td { border-bottom: 1px solid var(--border-color); padding: .75rem; text-align: left; vertical-align: top; }
    .muted { color: var(--muted-color); }
    .status { margin-top: 1rem; min-height: 1.25rem; }
    .status.success { color: #86efac; }
    .status.error { color: #fca5a5; }
    .card {
      background: linear-gradient(180deg, rgba(255,255,255,.02), rgba(255,255,255,0)) , var(--panel-bg);
      border: 1px solid var(--border-color);
      border-radius: 1rem;
      padding: 1rem;
      margin-top: 1rem;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.18);
    }
    body[data-density="compact"] .card { padding: .75rem; }
    body[data-density="compact"] .topbar { padding-bottom: .5rem; }
    body[data-density="compact"] .shortcuts { margin-top: .35rem; }
    body[data-density="compact"] table { margin-top: .75rem; }
    body[data-density="compact"] th, body[data-density="compact"] td { padding: .5rem .6rem; }
    .topbar { position: sticky; top: 0; z-index: 500; padding-top: .25rem; padding-bottom: .75rem; background: linear-gradient(to bottom, var(--page-bg) 70%, transparent); backdrop-filter: blur(10px); }
    .shortcuts { margin-top: .5rem; font-size: .92rem; display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    kbd { padding: .15rem .45rem; border-radius: .35rem; border: 1px solid var(--border-color); background: var(--panel-bg); color: var(--text-color); font-size: .85em; }
    code { color: #f5d06f; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; }
    .stack { display: flex; flex-direction: column; }
    .stack label { display: flex; flex-direction: column; font-size: .9rem; gap: .25rem; }
    .row { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    .row > * { flex: 1 1 180px; }
    .row .fixed { flex: 0 0 auto; }
    .hidden { display: none; }
    details { margin-top: 1rem; }
    summary { cursor: pointer; font-weight: 600; }
    .section-body { margin-top: 1rem; }
    .toast {
      position: fixed;
      top: 1rem;
      right: 1rem;
      z-index: 1000;
      max-width: min(420px, calc(100vw - 2rem));
      padding: .8rem 1rem;
      border-radius: .75rem;
      background: rgba(15, 23, 42, .96);
      border: 1px solid var(--border-color);
      color: var(--text-color);
      box-shadow: 0 10px 30px rgba(15, 23, 42, .35);
      opacity: 0;
      transform: translateY(-8px);
      transition: opacity .18s ease, transform .18s ease;
      pointer-events: none;
    }
    .toast.visible { opacity: 1; transform: translateY(0); }
    .toast.success { border-color: #166534; }
    .toast.error { border-color: #7f1d1d; }
    @media (max-width: 820px) {
      body { margin: 1rem; }
      .row { flex-direction: column; align-items: stretch; }
      .row > * { width: 100%; }
      table { display: block; overflow-x: auto; white-space: nowrap; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div id="toast" class="toast" role="status" aria-live="polite"></div>
  <div id="topbar" class="topbar">
    <h1>Henry Vault <span id="theme-name" class="theme-badge">DarkLuxury</span></h1>
    <p class="muted">Local encrypted secrets dashboard. Unlock once; this browser uses a short-lived HttpOnly local session cookie.</p>
    <div class="card">
      <form id="login-form" class="row" onsubmit="return login(event)">
        <input id="password" class="fixed" type="password" placeholder="Master password" />
        <button class="fixed" type="submit">Unlock</button>
      </form>
      <form id="filter-form" class="row" onsubmit="return applyFilters(event)">
        <input id="project" list="project-options" placeholder="Project filter" />
        <input id="environment" list="environment-options" placeholder="Environment filter" />
        <input id="secret-search" placeholder="Secret search" />
        <input id="attachment-search" placeholder="Attachment search" />
        <input id="password-search" placeholder="Password search" />
        <button class="fixed" type="submit">Apply filters</button>
        <button class="fixed secondary" type="button" onclick="clearFilters()">Clear filters</button>
        <button class="fixed secondary" type="button" onclick="loadDoctor()">Doctor</button>
        <button class="fixed secondary" type="button" onclick="loadAudit()">Audit</button>
        <button id="theme-toggle" class="fixed secondary" type="button" onclick="toggleTheme()">Toggle theme</button>
        <select id="theme-select" class="fixed secondary" onchange="setTheme(this.value)"></select>
        <button id="density-toggle" class="fixed secondary" type="button" onclick="toggleDensity()">Compact mode</button>
        <button class="fixed secondary" type="button" onclick="logout()">Logout</button>
      </form>
      <div class="shortcuts muted">
        <span>Shortcuts:</span>
        <span><kbd>/</kbd> focus search</span>
        <span><kbd>g</kbd> <kbd>d</kbd> doctor</span>
        <span><kbd>g</kbd> <kbd>a</kbd> audit</span>
        <span><kbd>t</kbd> theme</span>
        <span><kbd>c</kbd> clear filters</span>
      </div>
      <datalist id="project-options"></datalist>
      <datalist id="environment-options"></datalist>
    </div>
  </div>

  <div class="card">
    <h2>Add data</h2>
    <div class="grid">
      <form id="add-secret-form" class="stack" onsubmit="return addSecret(event)">
        <h3>Add secret</h3>
        <label>Name <input id="secret-name" required placeholder="API_KEY" /></label>
        <label>Value <textarea id="secret-value" required rows="3" placeholder="secret value"></textarea></label>
        <label>Tags <input id="secret-tags" placeholder="ai,prod" /></label>
        <label>Notes <input id="secret-notes" placeholder="optional note" /></label>
        <label>Project <input id="secret-project" list="project-options" placeholder="default" /></label>
        <label>Environment <input id="secret-environment" list="environment-options" placeholder="default" /></label>
        <div class="row">
          <button id="secret-submit-button" type="submit">Add secret</button>
          <button id="clear-edit-button" class="secondary hidden" type="button" onclick="cancelSecretEdit()">Clear edit mode</button>
        </div>
      </form>
      <form id="add-attachment-form" class="stack" onsubmit="return addAttachment(event)">
        <h3>Add attachment</h3>
        <label>Name <input id="attachment-name" required placeholder="SERVICE_ACCOUNT_JSON" /></label>
        <label>File <input id="attachment-file" type="file" required /></label>
        <label>Content type <input id="attachment-content-type" placeholder="application/json" /></label>
        <label>Notes <input id="attachment-notes" placeholder="optional note" /></label>
        <label>Project <input id="attachment-project" list="project-options" placeholder="default" /></label>
        <label>Environment <input id="attachment-environment" list="environment-options" placeholder="default" /></label>
        <button type="submit">Add attachment</button>
      </form>
    </div>
    <div id="action-status" class="status muted">No action yet.</div>
  </div>

  <div class="card" style="margin-top: 1rem;">
    <details open>
      <summary>Doctor</summary>
      <div class="section-body">
        <div id="doctor-summary" class="muted">Run Doctor to check vault hygiene.</div>
        <table>
          <thead><tr><th>Severity</th><th>Code</th><th>Scope</th><th>Secret</th><th>Message</th></tr></thead>
          <tbody id="doctor-issues"></tbody>
        </table>
      </div>
    </details>
    <details open>
      <summary>Audit</summary>
      <div class="section-body">
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Status</th><th>Scope</th><th>Secret</th><th>Message</th></tr></thead>
          <tbody id="audit-events"></tbody>
        </table>
      </div>
    </details>
  </div>

  <div class="card" style="margin-top: 1rem;">
    <details open>
      <summary>Secrets</summary>
      <div class="section-body">
        <table>
          <thead><tr><th>Project</th><th>Env</th><th>Name</th><th>Tags</th><th>Updated</th><th>Reveal</th><th>Edit</th><th>Manage</th></tr></thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
    </details>
  </div>

  <div class="card" style="margin-top: 1rem;">
    <details open>
      <summary>Attachments</summary>
      <div class="section-body">
        <table>
          <thead><tr><th>Project</th><th>Env</th><th>Name</th><th>Filename</th><th>Content type</th><th>Updated</th><th>Size</th><th>Download</th><th>Manage</th></tr></thead>
          <tbody id="attachment-rows"></tbody>
        </table>
      </div>
    </details>
  </div>

  <div class="card" style="margin-top: 1rem;">
    <details open id="passwords">
      <summary>Passwords</summary>
      <div class="section-body stack">
        <div class="row">
          <button id="password-list" class="fixed secondary" type="button" onclick="loadPasswords()">Refresh passwords</button>
        </div>
        <form id="add-password-form" class="stack" onsubmit="return addPassword(event)">
          <h3>Add password</h3>
          <label>Name <input id="password-name" required placeholder="GitHub" /></label>
          <label>URL <input id="password-url" required placeholder="https://github.com" /></label>
          <label>Username <input id="password-username" required placeholder="henry" /></label>
          <label>Password <input id="password-value" type="password" required placeholder="password" /></label>
          <label>Note <input id="password-note" placeholder="optional note" /></label>
          <button type="submit">Add password</button>
        </form>
        <table>
          <thead><tr><th>Name</th><th>URL</th><th>Username</th><th>Note</th><th>Updated</th><th>Copy</th><th>Manage</th></tr></thead>
          <tbody id="password-rows"></tbody>
        </table>
      </div>
    </details>
  </div>

  <script>
    let unlocked = false;
    let csrfToken = '';
    let editingSecret = null;
    let toastTimeout = null;
    let shortcutPrefix = '';
    let shortcutTimeout = null;
    const knownProjects = new Set();
    const knownEnvironments = new Set();
    const THEMES = [
      {value: 'dark-luxury', label: 'DarkLuxury'},
      {value: 'pearl-light', label: 'Pearl Light'},
      {value: 'royal-indigo', label: 'Royal Indigo'},
      {value: 'emerald-velvet', label: 'Emerald Velvet'},
      {value: 'rose-quartz', label: 'Rose Quartz'},
      {value: 'sunset-amber', label: 'Sunset Amber'},
    ];

    function csrfHeaders() {
      return csrfToken ? {'X-CSRF-Token': csrfToken} : {};
    }

    function themeLabel(theme) {
      return (THEMES.find(item => item.value === theme) || THEMES[0]).label;
    }

    function applyTheme(theme) {
      const resolved = THEMES.some(item => item.value === theme) ? theme : 'dark-luxury';
      document.body.dataset.theme = resolved;
      localStorage.setItem('hv-theme', resolved);
      const select = document.getElementById('theme-select');
      if (select) select.value = resolved;
      document.getElementById('theme-toggle').textContent = 'Toggle theme';
      document.getElementById('theme-name').textContent = themeLabel(resolved);
    }

    function setTheme(theme) {
      applyTheme(theme);
      setStatus(`Theme switched to ${themeLabel(document.body.dataset.theme)}.`);
    }

    function toggleTheme() {
      const currentIndex = Math.max(0, THEMES.findIndex(item => item.value === document.body.dataset.theme));
      const nextTheme = THEMES[(currentIndex + 1) % THEMES.length].value;
      applyTheme(nextTheme);
      setStatus(`Theme switched to ${themeLabel(nextTheme)}.`);
    }

    function applyDensity(density) {
      const resolved = density === 'compact' ? 'compact' : 'comfortable';
      document.body.dataset.density = resolved;
      localStorage.setItem('hv-density', resolved);
      document.getElementById('density-toggle').textContent = resolved === 'compact' ? 'Comfortable mode' : 'Compact mode';
    }

    function toggleDensity() {
      const current = document.body.dataset.density === 'compact' ? 'compact' : 'comfortable';
      applyDensity(current === 'compact' ? 'comfortable' : 'compact');
      setStatus(`Density switched to ${document.body.dataset.density}.`);
    }

    const storedTheme = localStorage.getItem('hv-theme');
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
      themeSelect.innerHTML = THEMES.map(item => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.label)}</option>`).join('');
    }
    applyTheme(storedTheme === 'light' ? 'pearl-light' : storedTheme || 'dark-luxury');
    const storedDensity = localStorage.getItem('hv-density');
    applyDensity(storedDensity === 'compact' ? 'compact' : 'comfortable');

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
    }

    function showToast(message, kind = '') {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.className = kind ? `toast ${kind} visible` : 'toast visible';
      clearTimeout(toastTimeout);
      toastTimeout = setTimeout(() => {
        toast.classList.remove('visible');
      }, 2600);
    }

    function setStatus(message, kind = '') {
      const status = document.getElementById('action-status');
      status.textContent = message;
      status.className = kind ? `status ${kind}` : 'status muted';
      showToast(message, kind);
    }

    function addKnownValues(items) {
      for (const item of items || []) {
        if (item.project) knownProjects.add(item.project);
        if (item.environment) knownEnvironments.add(item.environment);
      }
      document.getElementById('project-options').innerHTML = Array.from(knownProjects).sort().map(value => `<option value="${escapeHtml(value)}"></option>`).join('');
      document.getElementById('environment-options').innerHTML = Array.from(knownEnvironments).sort().map(value => `<option value="${escapeHtml(value)}"></option>`).join('');
    }

    function refreshSecretSubmitLabel() {
      const button = document.getElementById('secret-submit-button');
      const clearButton = document.getElementById('clear-edit-button');
      button.textContent = editingSecret ? 'Save secret' : 'Add secret';
      clearButton.classList.toggle('hidden', !editingSecret);
    }

    function clearSecretForm() {
      document.getElementById('secret-name').value = '';
      document.getElementById('secret-value').value = '';
      document.getElementById('secret-tags').value = '';
      document.getElementById('secret-notes').value = '';
      document.getElementById('secret-project').value = 'default';
      document.getElementById('secret-environment').value = 'default';
      editingSecret = null;
      refreshSecretSubmitLabel();
    }

    function cancelSecretEdit() {
      clearSecretForm();
      setStatus('Edit mode cleared.');
    }

    async function applyFilters(event) {
      if (event) event.preventDefault();
      await loadSecrets();
      await loadAttachments();
      await loadPasswords();
      return false;
    }

    async function clearFilters() {
      document.getElementById('project').value = '';
      document.getElementById('environment').value = '';
      document.getElementById('secret-search').value = '';
      document.getElementById('attachment-search').value = '';
      document.getElementById('password-search').value = '';
      await applyFilters();
      setStatus('Filters cleared.', 'success');
    }

    function focusSecretSearch() {
      const input = document.getElementById('secret-search');
      input.focus();
      input.select();
    }

    function runShortcut(action) {
      if (action === 'doctor') {
        loadDoctor();
      } else if (action === 'audit') {
        loadAudit();
      } else if (action === 'theme') {
        toggleTheme();
      } else if (action === 'clear') {
        clearFilters();
      }
    }

    function handleKeyboardShortcuts(event) {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }
      const target = event.target;
      const tag = target && target.tagName ? target.tagName.toLowerCase() : '';
      if (tag === 'input' || tag === 'textarea' || tag === 'select' || target.isContentEditable) {
        if (event.key === 'Escape') {
          target.blur();
        }
        return;
      }
      const key = event.key.toLowerCase();
      if (key === '/') {
        event.preventDefault();
        focusSecretSearch();
        setStatus('Focused secret search.');
        return;
      }
      if (shortcutTimeout) clearTimeout(shortcutTimeout);
      if (shortcutPrefix === 'g') {
        shortcutPrefix = '';
        if (key === 'd') {
          runShortcut('doctor');
        } else if (key === 'a') {
          runShortcut('audit');
        }
        return;
      }
      if (key === 'g') {
        shortcutPrefix = 'g';
        shortcutTimeout = setTimeout(() => { shortcutPrefix = ''; }, 1000);
        return;
      }
      if (key === 't') {
        runShortcut('theme');
      } else if (key === 'c') {
        runShortcut('clear');
      }
    }

    document.addEventListener('keydown', handleKeyboardShortcuts);

    async function login(event) {
      if (event) event.preventDefault();
      const res = await fetch('/api/login', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: document.getElementById('password').value})});
      if (!res.ok) {
        setStatus(res.status === 429 ? 'Too many failed attempts; try again later.' : 'Unlock failed', 'error');
        return false;
      }
      const data = await res.json();
      csrfToken = data.csrf_token || '';
      unlocked = true;
      document.getElementById('password').value = '';
      setStatus('Unlocked for this browser.', 'success');
      await applyFilters();
      return false;
    }

    async function logout() {
      await fetch('/api/logout', {method: 'POST', headers: csrfHeaders()});
      csrfToken = '';
      unlocked = false;
      editingSecret = null;
      refreshSecretSubmitLabel();
      document.getElementById('rows').innerHTML = '';
      document.getElementById('attachment-rows').innerHTML = '';
      document.getElementById('password-rows').innerHTML = '';
      setStatus('Logged out.');
    }

    function secretQueryParams() {
      const params = new URLSearchParams();
      const project = document.getElementById('project').value;
      const environment = document.getElementById('environment').value;
      const query = document.getElementById('secret-search').value.trim();
      if (project) params.set('project', project);
      if (environment) params.set('environment', environment);
      if (query) params.set('query', query);
      return params;
    }

    function attachmentQueryParams() {
      const params = new URLSearchParams();
      const project = document.getElementById('project').value;
      const environment = document.getElementById('environment').value;
      const query = document.getElementById('attachment-search').value.trim();
      if (project) params.set('project', project);
      if (environment) params.set('environment', environment);
      if (query) params.set('query', query);
      return params;
    }

    function passwordQueryParams() {
      const params = new URLSearchParams();
      const query = document.getElementById('password-search').value.trim();
      if (query) params.set('query', query);
      return params;
    }

    function renderSecretRows(items) {
      addKnownValues(items);
      document.getElementById('rows').innerHTML = (items || []).map(s => `
        <tr>
          <td>${escapeHtml(s.project)}</td><td>${escapeHtml(s.environment)}</td><td><code>${escapeHtml(s.name)}</code></td>
          <td>${escapeHtml((s.tags || []).join(', '))}</td><td>${escapeHtml(s.updated_at)}</td>
          <td><button class="fixed secondary" onclick="reveal('${escapeHtml(s.name)}','${escapeHtml(s.project)}','${escapeHtml(s.environment)}')">Copy</button></td>
          <td><button class="fixed secondary" onclick="beginSecretEdit('${escapeHtml(s.name)}','${escapeHtml(s.project)}','${escapeHtml(s.environment)}')">Edit</button></td>
          <td><button class="fixed danger" onclick="deleteSecret('${escapeHtml(s.name)}','${escapeHtml(s.project)}','${escapeHtml(s.environment)}')">Delete</button></td>
        </tr>`).join('');
    }

    function renderAttachmentRows(items) {
      addKnownValues(items);
      document.getElementById('attachment-rows').innerHTML = (items || []).map(a => `
        <tr>
          <td>${escapeHtml(a.project)}</td><td>${escapeHtml(a.environment)}</td><td><code>${escapeHtml(a.name)}</code></td>
          <td>${escapeHtml(a.filename)}</td><td>${escapeHtml(a.content_type)}</td><td>${escapeHtml(a.updated_at)}</td><td>${escapeHtml(a.size)}</td>
          <td><button class="fixed secondary" onclick="downloadAttachment('${escapeHtml(a.name)}','${escapeHtml(a.project)}','${escapeHtml(a.environment)}','${escapeHtml(a.filename)}')">Download</button></td>
          <td><button class="fixed danger" onclick="deleteAttachment('${escapeHtml(a.name)}','${escapeHtml(a.project)}','${escapeHtml(a.environment)}')">Delete</button></td>
        </tr>`).join('');
    }

    function renderPasswordRows(items) {
      document.getElementById('password-rows').innerHTML = (items || []).map(p => `
        <tr>
          <td><code>${escapeHtml(p.name)}</code></td><td>${escapeHtml(p.url)}</td><td>${escapeHtml(p.username)}</td>
          <td>${escapeHtml(p.note)}</td><td>${escapeHtml(p.updated_at)}</td>
          <td><button class="fixed secondary" onclick="copyPassword('${escapeHtml(p.name)}','${escapeHtml(p.url)}','${escapeHtml(p.username)}')">Copy</button></td>
          <td><button class="fixed danger" onclick="deletePassword('${escapeHtml(p.name)}','${escapeHtml(p.url)}','${escapeHtml(p.username)}')">Delete</button></td>
        </tr>`).join('');
    }

    async function loadSecrets() {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const res = await fetch('/api/secrets?' + secretQueryParams().toString());
      if (!res.ok) { setStatus('Could not list secrets', 'error'); return; }
      renderSecretRows(await res.json());
      setStatus('Secrets loaded.');
    }

    async function loadAttachments() {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const res = await fetch('/api/attachments?' + attachmentQueryParams().toString());
      if (!res.ok) { setStatus('Could not list attachments', 'error'); return; }
      renderAttachmentRows(await res.json());
      setStatus('Attachments loaded.');
    }

    async function loadPasswords() {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const res = await fetch('/api/passwords?' + passwordQueryParams().toString());
      if (!res.ok) { setStatus('Could not list passwords', 'error'); return; }
      renderPasswordRows(await res.json());
      setStatus('Passwords loaded.');
    }

    async function beginSecretEdit(name, project, environment) {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const params = new URLSearchParams({name, project, environment});
      const res = await fetch('/api/secrets/reveal?' + params.toString());
      if (!res.ok) { setStatus('Load secret for edit failed', 'error'); return; }
      const data = await res.json();
      document.getElementById('secret-name').value = data.name;
      document.getElementById('secret-value').value = data.value;
      document.getElementById('secret-project').value = project || 'default';
      document.getElementById('secret-environment').value = environment || 'default';
      editingSecret = {name, project, environment};
      refreshSecretSubmitLabel();
      setStatus(`Editing secret ${name}.`, 'success');
    }

    async function addSecret(event) {
      event.preventDefault();
      if (!unlocked) { setStatus('Unlock first', 'error'); return false; }
      const payload = {
        name: document.getElementById('secret-name').value,
        value: document.getElementById('secret-value').value,
        project: document.getElementById('secret-project').value || 'default',
        environment: document.getElementById('secret-environment').value || 'default',
        tags: document.getElementById('secret-tags').value.split(',').map(s => s.trim()).filter(Boolean),
        notes: document.getElementById('secret-notes').value,
      };
      const res = await fetch('/api/secrets', {method: 'POST', headers: {'Content-Type':'application/json', ...csrfHeaders()}, body: JSON.stringify(payload)});
      if (!res.ok) { setStatus('Add secret failed', 'error'); return false; }
      clearSecretForm();
      setStatus(`Saved secret ${payload.name}.`, 'success');
      await loadSecrets();
      return false;
    }

    async function addAttachment(event) {
      event.preventDefault();
      if (!unlocked) { setStatus('Unlock first', 'error'); return false; }
      const fileInput = document.getElementById('attachment-file');
      const file = fileInput.files && fileInput.files[0];
      if (!file) { setStatus('Choose a file', 'error'); return false; }
      const formData = new FormData();
      formData.append('name', document.getElementById('attachment-name').value);
      formData.append('project', document.getElementById('attachment-project').value || 'default');
      formData.append('environment', document.getElementById('attachment-environment').value || 'default');
      formData.append('content_type', document.getElementById('attachment-content-type').value || file.type || 'application/octet-stream');
      formData.append('notes', document.getElementById('attachment-notes').value);
      formData.append('file', file);
      const res = await fetch('/api/attachments', {method: 'POST', headers: csrfHeaders(), body: formData});
      if (!res.ok) { setStatus('Add attachment failed', 'error'); return false; }
      fileInput.value = '';
      setStatus(`Added attachment ${document.getElementById('attachment-name').value}.`, 'success');
      await loadAttachments();
      return false;
    }

    async function addPassword(event) {
      event.preventDefault();
      if (!unlocked) { setStatus('Unlock first', 'error'); return false; }
      const payload = {
        name: document.getElementById('password-name').value,
        url: document.getElementById('password-url').value,
        username: document.getElementById('password-username').value,
        password: document.getElementById('password-value').value,
        note: document.getElementById('password-note').value,
      };
      const res = await fetch('/api/passwords', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', ...csrfHeaders()},
        body: JSON.stringify(payload),
      });
      if (!res.ok) { setStatus('Add password failed', 'error'); return false; }
      document.getElementById('password-value').value = '';
      setStatus(`Saved password ${payload.name}.`, 'success');
      await loadPasswords();
      return false;
    }

    async function copyPassword(name, url, username) {
      const params = new URLSearchParams({name, url, username});
      const res = await fetch('/api/passwords/reveal?' + params.toString());
      if (!res.ok) { setStatus('Copy password failed', 'error'); return; }
      const data = await res.json();
      await navigator.clipboard.writeText(data.password).catch(() => {});
      setStatus(`Copied password for ${name}.`, 'success');
    }

    async function deletePassword(name, url, username) {
      if (!confirm(`Delete password ${name}?`)) return;
      const params = new URLSearchParams({name, url, username});
      const res = await fetch('/api/passwords?' + params.toString(), {method: 'DELETE', headers: csrfHeaders()});
      if (!res.ok) { setStatus('Delete password failed', 'error'); return; }
      setStatus(`Deleted password ${name}.`, 'success');
      await loadPasswords();
    }

    async function reveal(name, project, environment) {
      const params = new URLSearchParams({name, project, environment});
      const res = await fetch('/api/secrets/reveal?' + params.toString());
      if (!res.ok) { setStatus('Reveal failed', 'error'); return; }
      const data = await res.json();
      await navigator.clipboard.writeText(data.value).catch(() => {});
      setStatus(`${name} copied to clipboard if browser allowed it.`, 'success');
    }

    async function deleteSecret(name, project, environment) {
      if (!confirm(`Delete ${name}?`)) return;
      const params = new URLSearchParams({name, project, environment});
      const res = await fetch('/api/secrets?' + params.toString(), {method: 'DELETE', headers: csrfHeaders()});
      if (!res.ok) { setStatus('Delete failed', 'error'); return; }
      setStatus(`Deleted secret ${name}.`, 'success');
      await loadSecrets();
    }

    async function downloadAttachment(name, project, environment, filename) {
      const params = new URLSearchParams({name, project, environment});
      const res = await fetch('/api/attachments/download?' + params.toString());
      if (!res.ok) { setStatus('Download failed', 'error'); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename || name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setStatus(`Downloaded ${filename || name}.`, 'success');
    }

    async function deleteAttachment(name, project, environment) {
      if (!confirm(`Delete attachment ${name}?`)) return;
      const params = new URLSearchParams({name, project, environment});
      const res = await fetch('/api/attachments?' + params.toString(), {method: 'DELETE', headers: csrfHeaders()});
      if (!res.ok) { setStatus('Delete attachment failed', 'error'); return; }
      setStatus(`Deleted attachment ${name}.`, 'success');
      await loadAttachments();
    }

    async function loadDoctor() {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const res = await fetch('/api/doctor?' + secretQueryParams().toString());
      if (!res.ok) { setStatus('Doctor failed', 'error'); return; }
      const data = await res.json();
      document.getElementById('doctor-summary').textContent = data.ok ? 'Vault doctor: OK' : `${data.issues.length} issue(s) found`;
      document.getElementById('doctor-issues').innerHTML = (data.issues || []).map(issue => `
        <tr>
          <td>${escapeHtml(issue.severity)}</td><td><code>${escapeHtml(issue.code)}</code></td>
          <td>${escapeHtml(issue.project)}/${escapeHtml(issue.environment)}</td><td><code>${escapeHtml(issue.secret_name)}</code></td>
          <td>${escapeHtml(issue.message)}</td>
        </tr>`).join('');
      setStatus(data.ok ? 'Vault doctor reports no issues.' : 'Vault doctor found issues.', data.ok ? 'success' : 'error');
    }

    async function loadAudit() {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const res = await fetch('/api/audit?limit=25');
      if (!res.ok) { setStatus('Audit failed', 'error'); return; }
      const data = await res.json();
      document.getElementById('audit-events').innerHTML = (data || []).map(event => `
        <tr>
          <td>${escapeHtml(event.created_at)}</td><td><code>${escapeHtml(event.action)}</code></td><td>${escapeHtml(event.status)}</td>
          <td>${escapeHtml(event.project || '-')}/${escapeHtml(event.environment || '-')}</td><td><code>${escapeHtml(event.secret_name || '-')}</code></td>
          <td>${escapeHtml(event.message)}</td>
        </tr>`).join('');
      setStatus('Audit loaded.');
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

    def csrf_guard(hv_session: str | None, authorization: str, x_csrf_token: str) -> None:
        scheme, _, header_token = authorization.partition(" ")
        bearer_token = header_token if scheme.lower() == "bearer" and header_token else ""
        if hv_session and not bearer_token:
            session = sessions.get(hv_session)
            if session is None or not secrets.compare_digest(session.csrf_token, x_csrf_token):
                raise HTTPException(status_code=403, detail="Invalid CSRF token")

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
        csrf_token = secrets.token_urlsafe(32)
        ttl_seconds = 15 * 60
        sessions[token] = Session(password=login_request.password, expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds), csrf_token=csrf_token)
        response.set_cookie(
            COOKIE_NAME,
            token,
            max_age=ttl_seconds,
            httponly=True,
            samesite="strict",
            secure=False,
        )
        store.record_audit("web.login", status="success")
        return {"token": token, "csrf_token": csrf_token, "expires_in": ttl_seconds}

    @app.post("/api/logout")
    def logout(
        response: Response,
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
        authorization: str = Header(default=""),
        x_csrf_token: str = Header(default=""),
    ) -> dict[str, bool]:
        scheme, _, header_token = authorization.partition(" ")
        bearer_token = header_token if scheme.lower() == "bearer" and header_token else ""
        token = bearer_token or hv_session
        if hv_session and not bearer_token:
            session = sessions.get(hv_session)
            if session is None or not secrets.compare_digest(session.csrf_token, x_csrf_token):
                raise HTTPException(status_code=403, detail="Invalid CSRF token")
        if token:
            sessions.pop(token, None)
        response.delete_cookie(COOKIE_NAME)
        return {"ok": True}

    @app.get("/api/secrets")
    def list_secrets(
        project: Optional[str] = None,
        environment: Optional[str] = None,
        query: Optional[str] = None,
        store: VaultStore = Depends(store_for_session),
    ) -> list[dict]:
        items = store.list_secrets(project=project, environment=environment, query=query)
        store.record_audit("web.secret.list", project=project, environment=environment, message=f"count={len(items)}")
        return [item.__dict__ for item in items]

    @app.post("/api/secrets")
    def add_secret(
        payload: AddSecretRequest,
        authorization: str = Header(default=""),
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
        x_csrf_token: str = Header(default=""),
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, bool]:
        csrf_guard(hv_session, authorization, x_csrf_token)
        store.add_secret(
            SecretInput(
                name=payload.name,
                value=payload.value,
                project=payload.project,
                environment=payload.environment,
                tags=payload.tags,
                notes=payload.notes,
            )
        )
        store.record_audit("web.secret.add", secret_name=payload.name, project=payload.project, environment=payload.environment, message=f"tags={len(payload.tags)}")
        return {"ok": True}

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

    @app.get("/api/passwords")
    def list_passwords(
        query: Optional[str] = None,
        store: VaultStore = Depends(store_for_session),
    ) -> list[dict]:
        items = store.list_passwords(query=query)
        store.record_audit("web.password.list", message=f"count={len(items)}")
        return [item.__dict__ for item in items]

    @app.post("/api/passwords")
    def add_password(
        payload: AddPasswordRequest,
        authorization: str = Header(default=""),
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
        x_csrf_token: str = Header(default=""),
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, bool]:
        csrf_guard(hv_session, authorization, x_csrf_token)
        store.add_password(
            PasswordInput(
                name=payload.name,
                url=payload.url,
                username=payload.username,
                password=payload.password,
                note=payload.note,
            )
        )
        store.record_audit("web.password.add", secret_name=payload.name, message=payload.url)
        return {"ok": True}

    @app.get("/api/passwords/reveal")
    def reveal_password(
        name: str,
        url: str,
        username: str,
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, str]:
        item = store.get_password(name, url=url, username=username)
        if item is None:
            store.record_audit("web.password.reveal", secret_name=name, message=url, status="not_found")
            raise HTTPException(status_code=404, detail="Password not found")
        store.record_audit("web.password.reveal", secret_name=name, message=url)
        return {"name": item.name, "url": item.url, "username": item.username, "password": item.password, "note": item.note}

    @app.delete("/api/passwords")
    def delete_password(
        name: str,
        url: str,
        username: str,
        authorization: str = Header(default=""),
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
        x_csrf_token: str = Header(default=""),
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, bool]:
        csrf_guard(hv_session, authorization, x_csrf_token)
        deleted = store.delete_password(name, url=url, username=username)
        store.record_audit("web.password.delete", secret_name=name, message=url, status="success" if deleted else "not_found")
        if not deleted:
            raise HTTPException(status_code=404, detail="Password not found")
        return {"ok": True}

    @app.get("/api/attachments")
    def list_attachments(
        project: Optional[str] = None,
        environment: Optional[str] = None,
        query: Optional[str] = None,
        store: VaultStore = Depends(store_for_session),
    ) -> list[dict]:
        items = store.list_attachments(project=project, environment=environment, query=query)
        store.record_audit("web.attachment.list", project=project, environment=environment, message=f"count={len(items)}")
        return [item.__dict__ for item in items]

    @app.post("/api/attachments")
    def add_attachment(
        name: str = Form(...),
        project: str = Form(default="default"),
        environment: str = Form(default="default"),
        content_type: str = Form(default="application/octet-stream"),
        notes: str = Form(default=""),
        file: UploadFile = File(...),
        authorization: str = Header(default=""),
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
        x_csrf_token: str = Header(default=""),
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, bool]:
        csrf_guard(hv_session, authorization, x_csrf_token)
        content = file.file.read()
        store.add_attachment(
            AttachmentInput(
                name=name,
                filename=file.filename or name,
                content=content,
                project=project,
                environment=environment,
                content_type=content_type or file.content_type or "application/octet-stream",
                notes=notes,
            )
        )
        store.record_audit("web.attachment.add", secret_name=name, project=project, environment=environment, message=f"filename={file.filename or name}")
        return {"ok": True}

    @app.delete("/api/attachments")
    def delete_attachment(
        name: str,
        project: str = "default",
        environment: str = "default",
        authorization: str = Header(default=""),
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
        x_csrf_token: str = Header(default=""),
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, bool]:
        csrf_guard(hv_session, authorization, x_csrf_token)
        deleted = store.delete_attachment(name, project=project, environment=environment)
        store.record_audit("web.attachment.delete", secret_name=name, project=project, environment=environment, status="success" if deleted else "not_found")
        if not deleted:
            raise HTTPException(status_code=404, detail="Attachment not found")
        return {"ok": True}

    @app.delete("/api/secrets")
    def delete_secret(
        name: str,
        project: str = "default",
        environment: str = "default",
        authorization: str = Header(default=""),
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
        x_csrf_token: str = Header(default=""),
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, bool]:
        csrf_guard(hv_session, authorization, x_csrf_token)
        deleted = store.delete_secret(name, project=project, environment=environment)
        store.record_audit("web.secret.delete", secret_name=name, project=project, environment=environment, status="success" if deleted else "not_found")
        if not deleted:
            raise HTTPException(status_code=404, detail="Secret not found")
        return {"ok": True}

    @app.get("/api/attachments/download")
    def download_attachment(
        name: str,
        project: str = "default",
        environment: str = "default",
        store: VaultStore = Depends(store_for_session),
    ) -> Response:
        attachment = store.get_attachment(name, project=project, environment=environment)
        if attachment is None:
            store.record_audit("web.attachment.download", secret_name=name, project=project, environment=environment, status="not_found")
            raise HTTPException(status_code=404, detail="Attachment not found")
        store.record_audit("web.attachment.download", secret_name=name, project=project, environment=environment, message=f"filename={attachment.filename}")
        headers = {"Content-Disposition": f'attachment; filename="{attachment.filename}"'}
        return Response(content=attachment.content, media_type=attachment.content_type, headers=headers)

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
