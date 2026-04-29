# Changelog

All notable changes to Henry Vault will be documented in this file.

## [0.2.1] - Credential CSV export/import

### Added
- Export/import all secrets and passwords in a single CSV file for easier migration and sharing.

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
