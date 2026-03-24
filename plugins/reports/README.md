# Reports

This plugin provides API endpoints returning CSV reports on session and browser usage.
This is an instant image, no history in it.

## APIs

- **Requires PostgreSQL session storage:**
  - `/reports/apps`: CSV list of software connected using OpenID-Connect "offline\_access" _(mostly phone apps)_
  - `/reports/browsers`: CSV list of browsers connected
- **Requires LDAP user backend + PostgreSQL session storage:**
  - `/reports/lastcnx`: CSV list of users with their last connection time

## Installation

```
sudo lemonldap-ng-store install reports --activate
```

## Configuration

Protect `/reports/*` endpoints in your Manager virtual host rules to restrict
access to administrators.

## Files

- `lib/Lemonldap/NG/Portal/Plugins/Reports.pm` — Plugin module
- `plugin.json` — Plugin metadata
