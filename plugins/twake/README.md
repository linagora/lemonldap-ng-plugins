# Twake - Integration Plugin

This plugin provides Twake integration for LemonLDAP::NG.

## Components

- **`TwakeWellknown`** — Serves `/.well-known/twake-configuration` with
  configurable JSON content
- **`TwakeAppAccounts`** — LDAP-based applicative account management:
  create, delete, and list accounts with auto-generated passwords

## Requirements

- LemonLDAP::NG >= 2.0.0
- LDAP backend configured for applicative accounts
- `String::Random` Perl module

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install twake
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add
`::Plugins::TwakeWellknown, ::Plugins::TwakeAppAccounts` to `customPlugins`, and run
`llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Plugins** > **Twake**:

| Parameter             | Description                                                  |
| --------------------- | ------------------------------------------------------------ |
| `twakeWellKnown`      | Key/value pairs served at `/.well-known/twake-configuration` |
| `twakeAppAccounts`    | Enable applicative account management                        |
| `twakeAppLdapBranch`  | LDAP branch where accounts are stored                        |
| `twakeAppEntryFields` | User attributes to copy to accounts (comma-separated)        |
| `twakeAdminTokens`    | Admin tokens for API access (comma/semicolon separated)      |
