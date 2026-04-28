# Web Doctor and Audit views

## Goal

Add browser/API access to Henry Vault operational hygiene and audit history without exposing secret values.

## Implemented

- Added `/api/doctor` endpoint.
  - Requires an authenticated browser session or bearer token.
  - Accepts `project`, `environment`, and `expiring_days` query parameters.
  - Returns `{ok, issues}` using the existing `doctor_report` logic.
  - Records sanitized `web.doctor` audit events.
- Added `/api/audit` endpoint.
  - Requires an authenticated browser session or bearer token.
  - Accepts `limit` query parameter.
  - Returns sanitized audit event dictionaries.
  - Records `web.audit.list` audit events.
- Updated the web dashboard HTML.
  - Added Doctor and Audit buttons.
  - Added output panels for JSON doctor/audit results.

## Security notes

- Doctor/audit endpoints return metadata only, not secret values.
- Existing web auth/session checks protect both endpoints.
- Audit listing remains sanitized because stored audit events do not contain secret values.

## Verification

- Added failing tests first for the doctor endpoint, audit endpoint, and dashboard controls.
- Verified targeted tests failed before implementation.
- Implemented minimal web/API changes.
- Verified targeted tests passed.
- Full test suite passed.
