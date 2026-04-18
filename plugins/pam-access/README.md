# PAM Access - Token Generation and Authorization

This plugin provides PAM integration for LemonLDAP::NG, allowing users to
generate temporary access tokens for SSH and other PAM-enabled services.

## Features

- **Portal interface** (`/pam`): users generate short-lived one-time tokens
- **Token verification** (`/pam/verify`): server-to-server endpoint for PAM modules
- **Authorization** (`/pam/authorize`): server-to-server endpoint for SSH/sudo rules
- **Server groups**: per-group authorization rules for SSH and sudo
- **Heartbeat monitoring**: track PAM server health
- **Offline mode**: cache authorization decisions for disconnected servers
- **OIDC Device Authorization Grant**: secure server authentication

## Requirements

- LemonLDAP::NG >= 2.23.0
- OIDC issuer must be enabled
- An OIDC RP configured for PAM access (default name: `pam-access`)

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install pam-access
```

Manually: copy `lib/` into your Perl `@INC` path, copy `portal-templates/`
and `portal-static/` into the portal directories, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add `::Plugins::PamAccess` to
`customPlugins`, and run `llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Plugins** > **PAM Access**.

## See Also

- [PAM Access documentation](https://lemonldap-ng.org/documentation/latest/pamaccess)
