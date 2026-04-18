# External Menu

Redirects authenticated users to an external URL instead of showing the
LemonLDAP::NG portal menu.

> **Note:** This plugin is for LLNG < 2.23.0. Starting with LLNG 2.23.0,
> this feature is included in the core.

## Features

- Redirects after authentication and on authenticated visits to the portal
- Supports session variable substitution in the URL (`$uid`, `$mail`,
  `${variable}`)
- Does not override existing `urldc` (e.g. from service provider redirects)

## Installation

With `lemonldap-ng-store`:

```bash
sudo lemonldap-ng-store install external-menu
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add
`::Plugins::ExternalMenu` to `customPlugins`, and run
`llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Portal** > **Customization** >
**Redirection** > **Portal Redirection**:

| Parameter      | Default   | Description                                         |
| -------------- | --------- | --------------------------------------------------- |
| `externalMenu` | _(empty)_ | URL to redirect to (supports `$uid`, `$mail`, etc.) |

## Example

Set `externalMenu` to `https://apps.example.com/dashboard?user=$uid` to
redirect all authenticated users to the external dashboard with their
username in the URL.
