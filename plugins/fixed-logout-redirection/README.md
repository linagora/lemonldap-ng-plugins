# Fixed Logout Redirection

Forces a redirect to a configured URL after logout, instead of displaying
the default portal logout page.

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install fixed-logout-redirection
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add
`::Plugins::FixedRedirectOnLogout` to `customPlugins`, and run
`llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Portal** > **Customization** > **Forms**:

| Parameter                | Description                     |
| ------------------------ | ------------------------------- |
| `fixedLogoutRedirection` | URL to redirect to after logout |

The target domain is automatically added to `trustedDomains`.
