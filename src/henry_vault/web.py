from __future__ import annotations

import base64
import hashlib
import io
import re
import secrets
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional

import qrcode
from fastapi import Cookie, Depends, File, FastAPI, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from qrcode.image.svg import SvgPathImage

from .doctor import doctor_report
from .errors import VaultAlreadyExists, VaultLocked, VaultNotInitialized
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
    password: str | None = None
    totp_code: str | None = None
    recovery_code: str | None = None


class VaultInitRequest(BaseModel):
    password: str
    enable_two_factor: bool = True
    recovery_code_count: int = Field(default=8, ge=1, le=20)


@dataclass
class Session:
    vault_key: bytes
    expires_at: datetime
    csrf_token: str


@dataclass
class FailedLoginState:
    count: int = 0
    locked_until: datetime | None = None


COOKIE_NAME = "hv_session"


def _build_qr_svg(otpauth_uri: str | None) -> str | None:
    if not otpauth_uri:
        return None
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=2)
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    svg = image.to_string()
    if isinstance(svg, bytes):
        return svg.decode()
    return str(svg)


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
      margin: 2rem auto;
      width: min(1200px, calc(100vw - 4rem));
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
      margin: 0;
      line-height: 1.05;
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
    .hero-title {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: center;
      gap: .65rem;
    }
    .hero-subtitle {
      max-width: 68ch;
      margin: .5rem auto 0;
      line-height: 1.55;
      text-align: center;
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
    .topbar .card {
      padding: 1.25rem 1.35rem;
      margin-top: .9rem;
    }
    .topbar .card h2,
    .topbar .card h3 {
      margin-top: 0;
      margin-bottom: .45rem;
    }
    .topbar .card .row {
      gap: .75rem .9rem;
    }
    .topbar .card .row > * {
      flex: 1 1 210px;
    }
    .topbar .shortcuts {
      justify-content: center;
      padding-top: .85rem;
      margin-top: 1.1rem;
      border-top: 1px solid var(--border-color);
    }
    .topbar .shortcuts span:first-child {
      font-weight: 600;
      color: var(--text-color);
    }
    .topbar .shortcuts span:not(:first-child) {
      opacity: .9;
    }
    .topbar .top-group + .top-group {
      margin-top: 1.15rem;
      padding-top: 1.15rem;
      border-top: 1px solid var(--border-color);
    }
    .section-label {
      margin-bottom: .45rem;
      font-size: .76rem;
      letter-spacing: .14em;
      text-transform: uppercase;
      color: var(--muted-color);
    }
    .topbar .split-row {
      width: 100%;
    }
    .topbar .split-row:first-of-type > * {
      flex: 1 1 180px;
    }
    .topbar .split-row:last-of-type > * {
      flex: 0 0 auto;
    }
    #setup-form {
      gap: .85rem;
    }
    #login-form {
      align-items: stretch;
    }
    #filter-form {
      align-items: stretch;
      margin-top: .25rem;
    }
    #filter-form button,
    #filter-form select {
      min-width: 120px;
    }
    #passwords .row {
      align-items: stretch;
    }
    #passwords .subgroup + .subgroup {
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border-color);
    }
    #passwords .credentials-tools .row {
      align-items: stretch;
    }
    #passwords table {
      table-layout: fixed;
    }
    #passwords th,
    #passwords td {
      vertical-align: middle;
    }
    #passwords th:nth-child(1),
    #passwords td:nth-child(1) {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    #passwords th:nth-child(2),
    #passwords td:nth-child(2),
    #passwords th:nth-child(4),
    #passwords td:nth-child(4) {
      overflow-wrap: anywhere;
    }
    #passwords th:nth-child(6),
    #passwords td:nth-child(6),
    #passwords th:nth-child(7),
    #passwords td:nth-child(7) {
      width: 7.5rem;
      white-space: nowrap;
      text-align: center;
    }
    #passwords td:nth-child(6) button,
    #passwords td:nth-child(7) button {
      width: 100%;
    }
    #credentials-import-form {
      flex: 1 1 260px;
    }
    #add-password-form {
      max-width: 720px;
      margin: 0 auto;
    }
    .qr-shell {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 240px;
      padding: 1rem;
      border-radius: 1rem;
      background: #fff;
      border: 1px solid rgba(17, 24, 39, 0.08);
    }
    .qr-shell svg {
      width: min(100%, 240px);
      height: auto;
      display: block;
    }
    .recovery-codes {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      padding-left: 1.4rem;
      margin: 0;
    }
    .recovery-codes li {
      margin: .35rem 0;
      letter-spacing: .06em;
    }
    .setup-result strong {
      letter-spacing: .04em;
    }
    .stack code {
      word-break: break-all;
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
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.15rem; }
    .stack { display: flex; flex-direction: column; }
    .stack label { display: flex; flex-direction: column; font-size: .9rem; gap: .3rem; }
    .stack h2, .stack h3 { margin-bottom: .2rem; }
    .row { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    .row > * { flex: 1 1 180px; }
    .row .fixed { flex: 0 0 auto; }
    .hidden { display: none; }
    .clipboard-helper {
      position: fixed;
      top: -9999px;
      left: -9999px;
      opacity: 0;
      pointer-events: none;
    }
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
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0)), var(--panel-bg);
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
    .section-card { margin-top: 1rem; }
    .service-group { margin-bottom: 1.25rem; }
    .service-group:last-child { margin-bottom: 0; }
    .service-group-header { margin-bottom: .5rem; align-items: center; }
    .service-group-header strong { font-size: 1rem; flex: 1 1 auto; }
    .service-field-row { display: flex; gap: .5rem; align-items: center; margin-bottom: .4rem; }
    .service-field-row input { flex: 1 1 160px; }
    .service-field-row .remove-btn { flex: 0 0 auto; }
    #service-fields { margin: .5rem 0; }
    @media (max-width: 820px) {
      body { margin: 1rem auto; width: calc(100vw - 2rem); }
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
    <h1 class="hero-title">Henry Vault <span id="theme-name" class="theme-badge">DarkLuxury</span></h1>
    <p class="muted hero-subtitle">Local encrypted secrets dashboard. Unlock once; this browser uses a short-lived HttpOnly local session cookie.</p>
    <div class="card hidden" id="setup-card">
      <h2>Create a new vault</h2>
      <p class="muted">After creating the vault, scan the QR code in your authenticator app. Recovery codes are shown once.</p>
      <form id="setup-form" class="stack">
        <div class="row">
          <label>Master password <input id="setup-password" class="fixed" type="password" placeholder="New master password" required /></label>
          <label>Confirm password <input id="setup-confirm" class="fixed" type="password" placeholder="Confirm master password" required /></label>
        </div>
        <div class="row">
          <label class="fixed"><input id="setup-enable-2fa" type="checkbox" checked /> Enable authenticator app + recovery codes</label>
          <label>Recovery codes
            <select id="setup-recovery-count" class="fixed">
              <option value="6">6</option>
              <option value="8" selected>8</option>
              <option value="10">10</option>
              <option value="12">12</option>
            </select>
          </label>
          <button class="fixed" type="submit">Create vault</button>
        </div>
      </form>
    </div>
    <div class="card hidden" id="setup-result">
      <h2>Save these recovery codes now</h2>
      <p class="muted">This screen appears only once. Recovery codes are shown once. Store the QR code and recovery codes in a safe place before continuing.</p>
      <div class="grid">
        <div class="stack">
          <h3>Authenticator QR</h3>
          <div id="setup-qr" class="qr-shell" aria-label="Authenticator provisioning QR code"></div>
          <p class="muted">Provisioning URI: <code id="setup-uri"></code></p>
        </div>
        <div class="stack">
          <h3>Recovery codes</h3>
          <ol id="setup-recovery-codes" class="recovery-codes"></ol>
        </div>
      </div>
      <div class="row">
        <button class="fixed secondary" type="button" data-action="dismiss-setup-result">I saved these codes</button>
      </div>
    </div>
    <div class="card hidden" id="login-card">
      <div class="top-group">
        <div class="section-label">Unlock</div>
        <form id="login-form" class="row">
          <input id="password" class="fixed" type="password" autocomplete="current-password" placeholder="Master password" />
          <input id="totp-code" class="fixed" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="Authenticator code (optional)" />
          <input id="recovery-code" class="fixed" type="text" autocomplete="off" placeholder="Recovery code (optional)" />
          <button class="fixed" type="submit">Unlock</button>
        </form>
      </div>
      <div class="top-group">
        <div class="section-label">Search and actions</div>
        <form id="filter-form" class="stack">
          <div class="row split-row">
            <input id="project" list="project-options" placeholder="Project filter" />
            <input id="environment" list="environment-options" placeholder="Environment filter" />
            <input id="secret-search" placeholder="Secret search" />
            <input id="attachment-search" placeholder="Attachment search" />
            <input id="password-search" placeholder="Password search" />
          </div>
          <div class="row split-row">
            <button class="fixed" type="submit">Apply filters</button>
            <button class="fixed secondary" type="button" data-action="clear-filters">Clear filters</button>
            <button class="fixed secondary" type="button" data-action="doctor">Doctor</button>
            <button class="fixed secondary" type="button" data-action="audit">Audit</button>
            <button id="theme-toggle" class="fixed secondary" type="button" data-action="toggle-theme">Toggle theme</button>
            <select id="theme-select" class="fixed secondary"></select>
            <button id="density-toggle" class="fixed secondary" type="button" data-action="toggle-density">Compact mode</button>
            <button class="fixed secondary" type="button" data-action="logout">Logout</button>
          </div>
        </form>
      </div>
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
      <form id="add-secret-form" class="stack">
        <h3>Add secret</h3>
        <label>Name <input id="secret-name" required placeholder="API_KEY" /></label>
        <label>Value <textarea id="secret-value" required rows="3" placeholder="secret value"></textarea></label>
        <label>Tags <input id="secret-tags" placeholder="ai,prod" /></label>
        <label>Notes <input id="secret-notes" placeholder="optional note" /></label>
        <label>Project <input id="secret-project" list="project-options" placeholder="default" /></label>
        <label>Environment <input id="secret-environment" list="environment-options" placeholder="default" /></label>
        <div class="row">
          <button id="secret-submit-button" type="submit">Add secret</button>
          <button id="clear-edit-button" class="secondary hidden" type="button" data-action="cancel-secret-edit">Clear edit mode</button>
        </div>
      </form>
      <form id="add-attachment-form" class="stack">
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

  <div class="card section-card">
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

  <div class="card section-card">
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

  <div class="card section-card">
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

    <div class="card section-card">
      <details open id="passwords">
        <summary>Passwords</summary>
        <div class="section-body stack">
          <div class="subgroup credentials-tools">
            <div class="section-label">Credentials tools</div>
            <div class="row">
              <button id="password-list" class="fixed secondary" type="button" data-action="refresh-passwords">Refresh passwords</button>
              <button id="credentials-export" class="fixed secondary" type="button" data-action="export-credentials">Export credentials CSV</button>
              <form id="credentials-import-form" class="row">
                <input id="credentials-import-file" class="fixed" type="file" accept=".csv,text/csv" required />
                <button class="fixed secondary" type="submit">Import credentials CSV</button>
              </form>
            </div>
          </div>
          <div class="subgroup">
            <div class="section-label">New password</div>
            <form id="add-password-form" class="stack">
              <label>Name <input id="password-name" required placeholder="GitHub" /></label>
              <label>URL <input id="password-url" required placeholder="https://github.com" /></label>
              <label>Username <input id="password-username" required placeholder="henry" /></label>
              <label>Password <input id="password-value" type="password" required placeholder="password" /></label>
              <label>Note <input id="password-note" placeholder="optional note" /></label>
              <button type="submit">Add password</button>
            </form>
          </div>
          <div class="subgroup">
            <div class="section-label">Saved passwords</div>
            <table>
              <thead><tr><th>Name</th><th>URL</th><th>Username</th><th>Note</th><th>Updated</th><th>Copy</th><th>Manage</th></tr></thead>
              <tbody id="password-rows"></tbody>
            </table>
          </div>
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

    function renderSetupResult(setup) {
      const result = document.getElementById('setup-result');
      const qr = document.getElementById('setup-qr');
      const uri = document.getElementById('setup-uri');
      const codes = document.getElementById('setup-recovery-codes');
      if (!result || !qr || !uri || !codes) return;
      if (!setup?.otpauth_uri && !(setup?.recovery_codes || []).length) {
        result.classList.add('hidden');
        return;
      }
      uri.textContent = setup.otpauth_uri;
      qr.innerHTML = setup.qr_svg;
      codes.innerHTML = setup.recovery_codes.map(code => `<li><code>${escapeHtml(code)}</code></li>`).join('');
      result.classList.remove('hidden');
    }

    function dismissSetupResult() {
      const result = document.getElementById('setup-result');
      if (result) result.classList.add('hidden');
      setStatus('Vault setup complete. Keep your recovery codes safe.', 'success');
    }

    async function refreshLandingState() {
      const setupCard = document.getElementById('setup-card');
      const loginCard = document.getElementById('login-card');
      try {
        const res = await fetch('/api/status');
        if (!res.ok) throw new Error('status unavailable');
        const data = await res.json();
        if (data.initialized) {
          setupCard?.classList.add('hidden');
          loginCard?.classList.remove('hidden');
          setStatus('Vault is ready. Unlock with the master password. If 2FA is enabled, include your authenticator code or a recovery code.', 'success');
        } else {
          setupCard?.classList.remove('hidden');
          loginCard?.classList.add('hidden');
          setStatus('Create a new vault to get started.');
        }
      } catch (error) {
        setupCard?.classList.remove('hidden');
        loginCard?.classList.add('hidden');
      }
    }

    async function initVault(event) {
      if (event) event.preventDefault();
      const password = document.getElementById('setup-password').value;
      const confirm = document.getElementById('setup-confirm').value;
      if (!password || !confirm) {
        setStatus('Enter and confirm the new master password.', 'error');
        return false;
      }
      if (password !== confirm) {
        setStatus('Passwords do not match.', 'error');
        return false;
      }
      const payload = {
        password,
        enable_two_factor: document.getElementById('setup-enable-2fa').checked,
        recovery_code_count: Number(document.getElementById('setup-recovery-count').value || 8),
      };
      const res = await fetch('/api/init', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload)});
      if (!res.ok) {
        setStatus(res.status === 409 ? 'Vault is already initialized.' : 'Vault setup failed.', 'error');
        return false;
      }
      const data = await res.json();
      csrfToken = data.csrf_token || '';
      unlocked = true;
      document.getElementById('setup-password').value = '';
      document.getElementById('setup-confirm').value = '';
      renderSetupResult(data.setup);
      document.getElementById('setup-card')?.classList.add('hidden');
      document.getElementById('login-card')?.classList.remove('hidden');
      setStatus(data.setup ? 'Vault initialized. Save the recovery codes shown below.' : 'Vault initialized. You are logged in.', 'success');
      await applyFilters();
      return false;
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
      await loadServices();
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
    document.addEventListener('DOMContentLoaded', refreshLandingState);

    async function login(event) {
      if (event) event.preventDefault();
      const res = await fetch('/api/login', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: document.getElementById('password').value, totp_code: document.getElementById('totp-code').value, recovery_code: document.getElementById('recovery-code').value})});
      if (!res.ok) {
        setStatus(res.status === 429 ? 'Too many failed attempts; try again later.' : 'Unlock failed', 'error');
        return false;
      }
      const data = await res.json();
      csrfToken = data.csrf_token || '';
      unlocked = true;
      document.getElementById('password').value = '';
      document.getElementById('totp-code').value = '';
      document.getElementById('recovery-code').value = '';
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
          <td><button class="fixed secondary" data-action="reveal-secret" data-name="${escapeHtml(s.name)}" data-project="${escapeHtml(s.project)}" data-environment="${escapeHtml(s.environment)}">Copy</button></td>
          <td><button class="fixed secondary" data-action="edit-secret" data-name="${escapeHtml(s.name)}" data-project="${escapeHtml(s.project)}" data-environment="${escapeHtml(s.environment)}">Edit</button></td>
          <td><button class="fixed danger" data-action="delete-secret" data-name="${escapeHtml(s.name)}" data-project="${escapeHtml(s.project)}" data-environment="${escapeHtml(s.environment)}">Delete</button></td>
        </tr>`).join('');
    }

    function renderAttachmentRows(items) {
      addKnownValues(items);
      document.getElementById('attachment-rows').innerHTML = (items || []).map(a => `
        <tr>
          <td>${escapeHtml(a.project)}</td><td>${escapeHtml(a.environment)}</td><td><code>${escapeHtml(a.name)}</code></td>
          <td>${escapeHtml(a.filename)}</td><td>${escapeHtml(a.content_type)}</td><td>${escapeHtml(a.updated_at)}</td><td>${escapeHtml(a.size)}</td>
          <td><button class="fixed secondary" data-action="download-attachment" data-name="${escapeHtml(a.name)}" data-project="${escapeHtml(a.project)}" data-environment="${escapeHtml(a.environment)}" data-filename="${escapeHtml(a.filename)}">Download</button></td>
          <td><button class="fixed danger" data-action="delete-attachment" data-name="${escapeHtml(a.name)}" data-project="${escapeHtml(a.project)}" data-environment="${escapeHtml(a.environment)}">Delete</button></td>
        </tr>`).join('');
    }

    function renderPasswordRows(items) {
      document.getElementById('password-rows').innerHTML = (items || []).map(p => `
        <tr>
          <td><code>${escapeHtml(p.name)}</code></td><td>${escapeHtml(p.url)}</td><td>${escapeHtml(p.username)}</td>
          <td>${escapeHtml(p.note)}</td><td>${escapeHtml(p.updated_at)}</td>
          <td><button class="fixed secondary" type="button" data-action="copy-password" data-name="${escapeHtml(p.name)}" data-url="${escapeHtml(p.url)}" data-username="${escapeHtml(p.username)}">Copy</button></td>
          <td><button class="fixed danger" type="button" data-action="delete-password" data-name="${escapeHtml(p.name)}" data-url="${escapeHtml(p.url)}" data-username="${escapeHtml(p.username)}">Delete</button></td>
        </tr>`).join('');
    }

    async function loadSecrets() {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const res = await fetch('/api/secrets?' + secretQueryParams().toString());
      if (!res.ok) { setStatus('Could not list secrets', 'error'); return; }
      const all = await res.json();
      renderSecretRows(all.filter(s => !(s.tags || []).includes('service')));
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

    async function exportCredentials() {
      if (!unlocked) { setStatus('Unlock first', 'error'); return; }
      const res = await fetch('/api/credentials/export');
      if (!res.ok) { setStatus('Export credentials failed', 'error'); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'henry-vault-credentials.csv';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setStatus('Exported credentials CSV.', 'success');
    }

    async function importCredentials(event) {
      if (event) event.preventDefault();
      if (!unlocked) { setStatus('Unlock first', 'error'); return false; }
      const fileInput = document.getElementById('credentials-import-file');
      const file = fileInput.files && fileInput.files[0];
      if (!file) { setStatus('Choose a CSV file', 'error'); return false; }
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('/api/credentials/import', {method: 'POST', headers: csrfHeaders(), body: formData});
      if (!res.ok) { setStatus('Import credentials failed', 'error'); return false; }
      const data = await res.json();
      fileInput.value = '';
      setStatus(`Imported ${data.secrets} secrets and ${data.passwords} passwords.`, 'success');
      await Promise.all([loadSecrets(), loadPasswords(), loadAttachments()]);
      return false;
    }

    async function copyTextToClipboard(text) {
      if (navigator.clipboard && window.isSecureContext) {
        try {
          await navigator.clipboard.writeText(text);
          return true;
        } catch (error) {
          console.warn('navigator.clipboard.writeText failed', error);
        }
      }
      const textarea = document.createElement('textarea');
      textarea.className = 'clipboard-helper';
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.setAttribute('aria-hidden', 'true');
      textarea.style.top = '0';
      textarea.style.left = '0';
      textarea.style.width = '1px';
      textarea.style.height = '1px';
      textarea.style.margin = '0';
      textarea.style.padding = '0';
      textarea.style.border = '0';
      document.body.appendChild(textarea);
      textarea.focus({preventScroll: true});
      textarea.select();
      textarea.setSelectionRange(0, textarea.value.length);
      let copied = false;
      try {
        copied = document.execCommand('copy');
      } catch (error) {
        console.warn('document.execCommand("copy") failed', error);
      }
      document.body.removeChild(textarea);
      return copied;
    }

    async function copyPassword(name, url, username) {
      const params = new URLSearchParams({name, url, username});
      if (window.ClipboardItem && navigator.clipboard?.write) {
        try {
          await navigator.clipboard.write([new ClipboardItem({
            'text/plain': fetch('/api/passwords/reveal?' + params.toString())
              .then(r => { if (!r.ok) throw new Error('fetch failed'); return r.json(); })
              .then(d => new Blob([d.password], {type: 'text/plain'})),
          })]);
          setStatus(`Copied password for ${name}.`, 'success');
          return;
        } catch (error) {
          console.warn('ClipboardItem write failed', error);
        }
      }
      const res = await fetch('/api/passwords/reveal?' + params.toString());
      if (!res.ok) { setStatus('Copy password failed', 'error'); return; }
      const data = await res.json();
      const copied = await copyTextToClipboard(data.password);
      if (!copied) {
        setStatus(`Could not copy password for ${name}. Your browser may block clipboard access.`, 'error');
        return;
      }
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
      if (window.ClipboardItem && navigator.clipboard?.write) {
        try {
          await navigator.clipboard.write([new ClipboardItem({
            'text/plain': fetch('/api/secrets/reveal?' + params.toString())
              .then(r => { if (!r.ok) throw new Error('fetch failed'); return r.json(); })
              .then(d => new Blob([d.value], {type: 'text/plain'})),
          })]);
          setStatus(`${name} copied to clipboard.`, 'success');
          return;
        } catch (error) {
          console.warn('ClipboardItem write failed', error);
        }
      }
      const res = await fetch('/api/secrets/reveal?' + params.toString());
      if (!res.ok) { setStatus('Reveal failed', 'error'); return; }
      const data = await res.json();
      const copied = await copyTextToClipboard(data.value);
      if (!copied) {
        setStatus(`Could not copy ${name}. Your browser may block clipboard access.`, 'error');
        return;
      }
      setStatus(`${name} copied to clipboard.`, 'success');
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
    function _slugify(name) {
      return name.toLowerCase().replace(/[ \t\r\n]+/g, '-').replace(/[^a-z0-9-]/g, '').replace(/^-+|-+$/g, '');
    }

    function addServiceField() {
      const container = document.getElementById('service-fields');
      const div = document.createElement('div');
      div.className = 'service-field-row';
      div.innerHTML = '<input class="service-field-name" placeholder="Field name" />\'
        + '<input class="service-field-value" type="password" placeholder="Value" />\'
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
        html += '<div class="service-group">\'
          + '<div class="service-group-header row">\'
          + '<strong>' + escapeHtml(project) + '</strong>\'
          + '<span class="muted">' + fields.length + ' field(s)</span>\'
          + '<button class="fixed danger" type="button" data-action="delete-service" data-service="' + escapeHtml(project) + '">Delete service</button>\'
          + '</div><table><thead><tr><th>Field</th><th>Value</th><th>Copy</th></tr></thead><tbody>';
        for (const f of fields) {
          html += '<tr><td><code>' + escapeHtml(f.name) + '</code></td>\'
            + '<td><span class="muted">········</span></td>\'
            + '<td><button class="fixed secondary" type="button" data-action="copy-service-field"\'
            + ' data-name="' + escapeHtml(f.name) + '" data-project="' + escapeHtml(f.project) + '"\'
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

    function handleActionClick(event) {
      const button = event.target.closest('[data-action]');
      if (!button) return;
      const {action, name, project, environment, filename, url, username} = button.dataset;
      if (action === 'dismiss-setup-result') dismissSetupResult();
      else if (action === 'clear-filters') clearFilters();
      else if (action === 'doctor') loadDoctor();
      else if (action === 'audit') loadAudit();
      else if (action === 'toggle-theme') toggleTheme();
      else if (action === 'toggle-density') toggleDensity();
      else if (action === 'logout') logout();
      else if (action === 'cancel-secret-edit') cancelSecretEdit();
      else if (action === 'refresh-passwords') loadPasswords();
      else if (action === 'export-credentials') exportCredentials();
      else if (action === 'reveal-secret') reveal(name, project, environment);
      else if (action === 'edit-secret') beginSecretEdit(name, project, environment);
      else if (action === 'delete-secret') deleteSecret(name, project, environment);
      else if (action === 'download-attachment') downloadAttachment(name, project, environment, filename);
      else if (action === 'delete-attachment') deleteAttachment(name, project, environment);
      else if (action === 'copy-password') copyPassword(name, url, username);
      else if (action === 'delete-password') deletePassword(name, url, username);
      else if (action === 'add-service-field') addServiceField();
      else if (action === 'remove-service-field') removeServiceField(button);
      else if (action === 'copy-service-field') copyServiceField(button.dataset.name, button.dataset.project, button.dataset.environment);
      else if (action === 'delete-service') deleteService(button.dataset.service);
    }

    document.getElementById('setup-form')?.addEventListener('submit', initVault);
    document.getElementById('login-form')?.addEventListener('submit', login);
    document.getElementById('filter-form')?.addEventListener('submit', applyFilters);
    document.getElementById('add-secret-form')?.addEventListener('submit', addSecret);
    document.getElementById('add-attachment-form')?.addEventListener('submit', addAttachment);
    document.getElementById('credentials-import-form')?.addEventListener('submit', importCredentials);
    document.getElementById('add-password-form')?.addEventListener('submit', addPassword);
    document.getElementById('add-service-form')?.addEventListener('submit', addService);
    document.getElementById('theme-select')?.addEventListener('change', event => setTheme(event.target.value));
    document.addEventListener('click', handleActionClick);
  </script>
</body>
</html>
"""


def _csp_hash(tag: str) -> str:
    match = re.search(rf"<{tag}>(.*?)</{tag}>", HTML, flags=re.DOTALL)
    if match is None:
        raise RuntimeError(f"Missing inline {tag} block")
    digest = hashlib.sha256(match.group(1).encode()).digest()
    return "'sha256-" + base64.b64encode(digest).decode() + "'"


STYLE_CSP_HASH = _csp_hash("style")
SCRIPT_CSP_HASH = _csp_hash("script")


def _security_csp() -> str:
    return (
        "default-src 'self'; "
        f"script-src 'self' {SCRIPT_CSP_HASH}; "
        f"style-src 'self' {STYLE_CSP_HASH}; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )


def create_app(
    db_path: str | Path = DEFAULT_DB_PATH,
    *,
    max_failed_logins: int = 5,
    lockout_seconds: int = 60,
) -> FastAPI:
    app = FastAPI(title="Henry Vault", version="0.3.0")
    sessions: dict[str, Session] = {}
    failed_logins: dict[str, FailedLoginState] = {}

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", _security_csp())
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    def store_for_password(password: str | None, totp_code: str | None = None, recovery_code: str | None = None) -> VaultStore:
        store = VaultStore(db_path)
        try:
            store.unlock(password, totp_code=totp_code, recovery_code=recovery_code)
        except VaultLocked as exc:
            raise HTTPException(status_code=401, detail="Invalid unlock credentials") from exc
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
        store = VaultStore(db_path)
        try:
            store.unlock_with_vault_key(session.vault_key)
        except VaultLocked as exc:
            raise HTTPException(status_code=401, detail="Invalid or expired session") from exc
        return store

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

    @app.get("/api/status")
    def status() -> dict[str, bool]:
        store = VaultStore(db_path)
        return {"initialized": store.is_initialized()}

    @app.get("/api/session/status")
    def session_status(store: VaultStore = Depends(store_for_session)) -> dict[str, bool]:
        return {"authenticated": True, "two_factor_enabled": store.has_two_factor_enabled()}

    @app.post("/api/init")
    def init_vault(request: Request, response: Response, init_request: VaultInitRequest) -> dict[str, object]:
        key = client_key(request)
        ensure_not_locked_out(key)
        store = VaultStore(db_path)
        if store.is_initialized():
            raise HTTPException(status_code=409, detail="Vault is already initialized")
        try:
            setup = store.init(
                init_request.password,
                enable_two_factor=init_request.enable_two_factor,
                recovery_code_count=init_request.recovery_code_count,
            )
        except VaultAlreadyExists as exc:
            record_failed_login(key)
            raise HTTPException(status_code=409, detail="Vault is already initialized") from exc
        failed_logins.pop(key, None)
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        ttl_seconds = 15 * 60
        sessions[token] = Session(
            vault_key=store.current_vault_key(),
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            csrf_token=csrf_token,
        )
        response.set_cookie(
            COOKIE_NAME,
            token,
            max_age=ttl_seconds,
            httponly=True,
            samesite="strict",
            secure=False,
        )
        store.record_audit("web.init", status="success")
        setup_payload = None
        if setup.otpauth_uri or setup.recovery_codes:
            setup_payload = {
                "otpauth_uri": setup.otpauth_uri,
                "qr_svg": _build_qr_svg(setup.otpauth_uri),
                "recovery_codes": setup.recovery_codes,
            }
        return {"token": token, "csrf_token": csrf_token, "expires_in": ttl_seconds, "setup": setup_payload}

    @app.post("/api/login")
    def login(request: Request, response: Response, login_request: LoginRequest) -> dict[str, str | int]:
        key = client_key(request)
        ensure_not_locked_out(key)
        try:
            store = store_for_password(
                login_request.password,
                totp_code=login_request.totp_code,
                recovery_code=login_request.recovery_code,
            )
        except HTTPException as exc:
            record_failed_login(key)
            if exc.status_code == 401:
                try:
                    VaultStore(db_path).record_audit("web.login", status="failed", message="invalid unlock credentials")
                except VaultNotInitialized:
                    pass
            raise
        failed_logins.pop(key, None)
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        ttl_seconds = 15 * 60
        sessions[token] = Session(
            vault_key=store.current_vault_key(),
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            csrf_token=csrf_token,
        )
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
        tags: Optional[str] = None,
        store: VaultStore = Depends(store_for_session),
    ) -> list[dict]:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
        items = store.list_secrets(project=project, environment=environment, query=query, tags=tag_list)
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

    @app.get("/api/credentials/export")
    def export_credentials(store: VaultStore = Depends(store_for_session)) -> Response:
        with tempfile.NamedTemporaryFile("wb", suffix=".csv", delete=False) as tmp:
            temp_path = Path(tmp.name)
        try:
            summary = store.export_credentials(temp_path)
            content = temp_path.read_bytes()
        finally:
            temp_path.unlink(missing_ok=True)
        store.record_audit("web.credentials.export", message=f"secrets={summary.secrets} passwords={summary.passwords}")
        headers = {"Content-Disposition": 'attachment; filename="henry-vault-credentials.csv"'}
        return Response(content=content, media_type="text/csv; charset=utf-8", headers=headers)

    @app.post("/api/credentials/import")
    def import_credentials(
        file: UploadFile = File(...),
        authorization: str = Header(default=""),
        hv_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
        x_csrf_token: str = Header(default=""),
        store: VaultStore = Depends(store_for_session),
    ) -> dict[str, int | bool]:
        csrf_guard(hv_session, authorization, x_csrf_token)
        original_name = Path(file.filename or "credentials.csv")
        if original_name.suffix.lower() != ".csv":
            raise HTTPException(status_code=400, detail="Only .csv credential files are supported")
        with tempfile.NamedTemporaryFile("wb", suffix=".csv", delete=False) as tmp:
            temp_path = Path(tmp.name)
            tmp.write(file.file.read())
        try:
            summary = store.import_credentials(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)
        store.record_audit("web.credentials.import", message=f"secrets={summary.secrets} passwords={summary.passwords}")
        return {"ok": True, "secrets": summary.secrets, "passwords": summary.passwords}

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
