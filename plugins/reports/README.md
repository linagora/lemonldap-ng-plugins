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

The `/reports/*` endpoints are served by the portal, so Manager or handler
virtual host rules do not apply to them. Access is controlled by the
`reportsRule` option (_General Parameters_ > _Plugins_ > _Reports_ in the
Manager), a rule evaluated against the session of the authenticated user:

```
reportsRule = $groups =~ /\badmins\b/
```

When `reportsRule` is unset, empty or `0`, every request gets `403
Forbidden`. A rule that does not compile makes the portal fail to start, as
for any plugin whose initialization fails.

## CSV format

Every field is quoted with `"`, and embedded double quotes are doubled. A
value starting with `=`, `+`, `-`, `@`, a tab or a CR is prefixed with an
apostrophe, so a spreadsheet does not evaluate it as a formula. The body is
encoded as UTF-8 and `Content-Type` is `text/csv; charset=utf-8`.

## Files

- `lib/Lemonldap/NG/Portal/Plugins/Reports.pm` — Plugin module
- `manager-overrides/reports.json` — Manager declaration of `reportsRule`
- `plugin.json` — Plugin metadata
