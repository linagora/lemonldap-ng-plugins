# OIDC Scope Applications

Adds an `applications` scope to LemonLDAP::NG's OIDC provider that exposes
the user's portal application menu in the userinfo response.

## Features

- **`applications` scope**: when requested by an RP, the userinfo response
  includes an `applications` claim containing the JSON-encoded portal
  application list for the authenticated user
- **Per-RP control**: enable via `oidcRPMetaDataOptionsAllowScopeApplications`
- **Hooks**: uses `oidcResolveScope` and `oidcGenerateUserInfoResponse`

## Requirements

- LemonLDAP::NG >= 2.23.0
- OIDC issuer must be enabled

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install oidc-scope-applications
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add
`::Plugins::OIDCScopeApplications` to `customPlugins`, and run
`llng-build-manager-files`.

## Configuration

For each OIDC RP, enable in the Manager:

| Parameter                                     | Default | Description              |
| --------------------------------------------- | ------- | ------------------------ |
| `oidcRPMetaDataOptionsAllowScopeApplications` | `0`     | Allow applications scope |

The RP then requests `scope=openid applications` in the authorization request.

## Response Example

The `applications` claim in the userinfo response contains a JSON array of
application categories, each with its list of applications (same structure
as the portal menu).
