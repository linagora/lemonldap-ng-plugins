# Reports

This plugin provides API endpoints returning CSV reports on session and browser usage.
This is an instant image, no history in it.

## APIs

- **Requires PostgreSQL session storage:**
  - `/reports/apps`: CSV list of software connected using OpenID-Connect "offline*access" *(mostly phone apps)\_
  - `/reports/browsers`: CSV list of browsers connected
- **Requires LDAP user backend + PostgreSQL session storage:**
  - `/reports/lastcnx`: CSV list of users with their last connection time

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```
sudo lemonldap-ng-store install reports --activate
```

Manually: copy `lib/` into your Perl `@INC` path and add `::Plugins::Reports` to `customPlugins` in the LLNG configuration.

## Configuration

Protect `/reports/*` endpoints in your Manager virtual host rules to restrict
access to administrators.

## Files

- `lib/Lemonldap/NG/Portal/Plugins/Reports.pm` — Plugin module
- `plugin.json` — Plugin metadata
