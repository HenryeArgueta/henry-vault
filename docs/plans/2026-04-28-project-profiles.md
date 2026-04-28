# Project profiles and required-secret manifests

## Goal

Add project/environment profiles so Henry Vault can remember which secret names are required before deploying a service.

## Implemented

- Added `project_profiles` SQLite table.
- Added `ProjectProfile` store model.
- Added store methods:
  - `set_project_profile(project, environment, required_secrets, notes='')`
  - `list_project_profiles(project=None, environment=None)`
  - `delete_project_profile(project, environment)`
- Added CLI commands:
  - `hv profile-set --project NAME --env ENV --required SECRET ...`
  - `hv profile-list [--project NAME] [--env ENV]`
  - `hv profile-delete --project NAME --env ENV`
- Added `doctor` integration that reports `missing_required_secret` issues for profile requirements not present in the vault.
- Added sanitized audit events for profile set/list/delete.
- Updated README with examples.

## Verification

- Added TDD tests for store/doctor behavior and CLI behavior.
- Verified targeted tests fail before implementation.
- Verified targeted tests pass after implementation.
- Full test suite passes.
