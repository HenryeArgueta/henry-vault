# Changelog

All notable changes to Henry Vault will be documented in this file.

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
