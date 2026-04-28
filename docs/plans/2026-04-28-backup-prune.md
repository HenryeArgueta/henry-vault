# Backup retention pruning

## Goal

Add a safe way to remove old Henry Vault backup bundles so scheduled backups do not grow forever.

## Implemented

- Added `prune_backups(backup_dir, keep_days, now=None, dry_run=True)`.
- Added result models:
  - `PrunedBackup`
  - `BackupPruneResult`
- Added CLI command:
  - `hv backup-prune BACKUP_DIR --keep-days 30`
  - `hv backup-prune BACKUP_DIR --keep-days 30 --delete`
- Dry-run is the default. Files are deleted only when `--delete` is passed.
- Safety behavior:
  - only scans top-level `*.hv.json` files in the chosen backup directory
  - only considers files whose JSON format is `henry-vault-backup-v1`
  - ignores invalid JSON, non-backup files, directories, and recent backups

## Verification

- Added failing tests first for prune behavior and CLI behavior.
- Verified targeted tests failed before implementation.
- Implemented minimal backup pruning logic.
- Verified targeted tests passed.
- Full test suite passed.
