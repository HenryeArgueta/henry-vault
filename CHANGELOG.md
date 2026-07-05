# Changelog

All notable changes to Henry Vault will be documented in this file.

## [0.4.0] - 2026-07-05

### Added
- GitHub sign-in on the web lock screen using the OAuth device flow: click the button, enter the short code at github.com/login/device, and the vault unlocks. The master password and recovery codes always keep working offline.
- CLI enrollment lifecycle: `hv github-link --client-id <ID>`, `hv github-status`, `hv github-unlink`.
- Key model: enrollment wraps the vault key with a random device secret (`~/.henry-vault/github-device.secret`, chmod 0600) — the same trust model as recovery codes. Only the enrolled GitHub user ID (immutable, not the rename-able login) can unlock. No scopes are requested and the GitHub token is never stored.
- New audit events: `github.link`, `github.unlink`, `web.login.github`.
- `/api/status` now reports whether GitHub unlock is available; new endpoints `/api/auth/github/start` and `/api/auth/github/poll`.

### Security
- Failed GitHub unlock attempts (wrong account) count toward the existing login rate limiter and are audited.
- Server-side polling respects GitHub's device-flow interval regardless of browser polling frequency.

## [0.3.1] - 2026-07-05

### Added
- `add`, `get`, `list`, and `delete` CLI aliases for `secret-add`, `secret-get`, `secret-list`, and `secret-delete`, matching the README quickstart.
- Focused lock screen: the dashboard stays hidden until the vault is unlocked, and the unlock form is the only thing shown when locked.
- Session chip showing unlock state and time remaining, with a Lock button; the UI returns to the lock screen when the session expires or any API call returns 401.
- "Generate strong password" and Show/Hide buttons on the new-password form (20 characters, cryptographically random).
- `/favicon.ico` endpoint so browsers stop logging 404s.

### Fixed
- Mobile layout: form fields no longer render hundreds of pixels tall (desktop `flex-basis` leaked into the stacked column layout).
- Toast notifications moved to the bottom-right so they no longer cover the header.

### Changed
- Updated/Time columns render as friendly local times ("37m ago", "Jul 5, 2026") with the full timestamp on hover instead of raw UTC ISO strings.

## [0.3.0] - 2026-04-30

### Added
- First-run and existing-vault authenticator-app 2FA support using standard TOTP provisioning URIs.
- One-time emergency recovery codes that can unlock the vault by themselves when needed.
- CLI lifecycle commands for existing vaults:
  - `hv two-factor-enable`
  - `hv recovery-codes-regenerate`
  - `hv totp-rotate`
  - `hv two-factor-disable`
- Web onboarding QR-code rendering for authenticator setup using the Python `qrcode` package.
- API service grouping in the CLI and web UI for saving, listing, copying, and deleting related credential fields under one service name.
- README security model covering encrypted data, metadata, unlock semantics, recovery-code behavior, and no-reset guidance.
- Security headers for the local FastAPI web UI/API, including a nonce-based CSP that avoids `unsafe-inline`.

### Changed
- Web/API login failures now return a generic `Invalid unlock credentials` message while recording sanitized failed-login audit events.
- Dashboard layout has clearer unlock, search/action, credentials-tool, new-password, and saved-password groups.
- Existing vaults now render the unlock form in the initial HTML response instead of depending on JavaScript to reveal it.
- The web UI reports password list counts and empty/error states so imported password visibility is easier to diagnose.
- README examples use safer public-facing placeholders and a corrected bearer-token flow.

### Security
- Web UI script execution now uses per-response CSP nonces, avoiding browser normalization issues that could block all dashboard JavaScript.
- Recovery-code generation is bounded to 1-20 codes to avoid accidental expensive setup requests.
- Recovery-code consumption is one-time and conditionally marked used before unlocking the session.
- Regenerating recovery codes invalidates old unused codes.
- Disabling 2FA invalidates recovery codes.

## [0.2.1] - Credential CSV export/import

### Added
- Export/import all secrets and passwords in a single CSV file for easier migration and sharing.
- Added matching browser controls in the Passwords section for CSV export and upload.

## [0.2.0] - Web UI polish release

### Added
- Browser-based secret management from the web UI:
  - add secrets
  - edit secrets
  - delete secrets
  - search and filter secrets
- Attachment management from the web UI:
  - upload attachments
  - download attachments
  - delete attachments
- Theme toggle with saved preference
- Compact density mode with saved preference
- Keyboard shortcuts for common actions
- Toast notifications for action feedback
- Collapsible sections for a cleaner dashboard
- Sticky top bar for navigation and controls

### Improved
- Better responsive layout on smaller screens
- Improved hover and focus-visible styles
- Clearer manage actions in tables and forms
- Better inline status messaging and search UX

### Security
- Secret values remain hidden in listings and tables
- Browser actions remain CSRF-protected
- Web UI is intended for local access, ideally via SSH tunnel

### Verified
- Full test suite passed
- Build passed
- Changes committed and pushed to `origin/master`
- Commit: `d87bb8a` (`feat: polish vault web ui`)
