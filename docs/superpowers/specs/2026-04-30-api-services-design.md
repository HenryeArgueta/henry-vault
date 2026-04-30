# API Services Feature Design

**Date:** 2026-04-30  
**Status:** Approved

## Overview

Add the ability to store groups of related credentials (API keys, tokens, IDs) under a single named service — e.g., all Discord credentials together. Fields are stored individually in the existing secrets table, masked by default in the UI, and accessible via new CLI commands.

## Storage

No schema changes. Each field in a service is stored as a regular secret with:

- `project` = slugified service name (e.g., `discord` for "Discord")
- `tags` = `["service"]` to distinguish from regular one-off secrets
- `name` = the field name (e.g., `BOT_TOKEN`, `CLIENT_SECRET`)
- `environment` = user-specified or `default`

This means encryption, audit logging, backup, export/import, and doctor checks all work for free.

Slugification rule: lowercase, spaces → hyphens, strip non-alphanumeric except hyphens.

## CLI Changes

### Rename bare secret commands

Match the existing `password-*` and `attachment-*` naming convention:

| Old command | New command |
|-------------|-------------|
| `hv add` | `hv secret-add` |
| `hv get` | `hv secret-get` |
| `hv list` | `hv secret-list` |
| `hv delete` | `hv secret-delete` |

Old names are removed (not aliased). Other commands (`set-metadata`, `rotate`, `scan`, `profile-*`, `export-env`, `import-env`, etc.) are unchanged.

### New service commands

**`hv service-add <service-name> <field1> [field2 ...]`**  
Prompts for each field value with hidden input. Saves each as a secret under the slugified service name project with tag `service`. Re-running upserts existing fields.

Example: `hv service-add Discord BOT_TOKEN APP_ID CLIENT_SECRET PUBLIC_KEY`

**`hv service-get <service-name>`**  
Prints all fields for the service. Each line: `FIELD_NAME=<value>`. Always uses this format regardless of field count, so output is consistent for scripting.

Example: `hv service-get discord` → prints all Discord fields

**`hv service-list`**  
Lists all services (distinct project values tagged `service`) with their field names. Does not reveal values.

**`hv service-delete <service-name>`**  
Deletes all fields belonging to a service after confirmation prompt.

## Web UI Changes

### Add API Service form (new card section)

A dedicated collapsible card below the "Add data" card. Contains:

- **Service name** text input (required) — slugified automatically for storage, displayed as-entered
- **Project** input (optional, defaults to slugified service name)
- **Environment** input (optional, defaults to `default`)
- Dynamic **field rows**: each row has a field name input + masked value input + remove (−) button
- **"+ Add field"** button appends a new blank row (minimum one row required)
- **"Save service"** submit button — POSTs each field as a separate secret via existing `/api/secrets` endpoint

### API Services section (new display section)

A collapsible card below the "Add data" card and above the Secrets section. Contains:

- One collapsible group per service (grouped by project where tag includes `service`)
- Group header: service name + field count + Delete service button
- Each field row: field name visible, value masked (`••••••••`) + Copy button
- Copy button fetches value via `/api/secrets/reveal` and copies to clipboard (same ClipboardItem pattern as passwords)
- Delete service button removes all fields for that service after browser confirm dialog
- Section is hidden when no services exist

### Secrets table

Regular secrets (those without the `service` tag) continue to display in the existing Secrets table unchanged. Services do not appear there.

## Error Handling

- Duplicate field name within the same service on add: upsert (overwrite), consistent with existing secret and password behavior
- Empty field name: client-side validation, form does not submit
- Service not found on CLI get/delete: exit code 1 with message to stderr
- Partial save failure mid-service (network drop): fields saved so far persist; user can re-run to fill in missing ones (upsert is safe)

## Testing

- Unit tests for `service-add`, `service-get`, `service-list`, `service-delete` CLI commands
- Unit tests for renamed `secret-*` commands
- Web API tests: service fields correctly tagged, filtered out of regular secret list, revealed correctly
- Web UI: manual verification — add service, verify masked display, copy button, delete
