# OIDC Device Authorization - RFC 8628

This plugin implements [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
for LemonLDAP::NG.

## Features

- **Device code endpoint** (`/oauth2/device`): issues device and user codes
- **User verification page** (`/oauth2/device/verify`): portal page for users
  to enter the device code and approve/deny
- **Device code grant type** on the token endpoint
  (`urn:ietf:params:oauth:grant-type:device_code`)
- **PKCE support** for additional security
- **Configurable** expiration, polling interval, and user code length

## Requirements

- LemonLDAP::NG >= 2.23.0
- OIDC issuer must be enabled

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install oidc-device-authorization --activate
```

Manually: copy `lib/` and `portal-templates/` into the appropriate directories,
copy `manager-overrides/` into `/etc/lemonldap-ng/manager-overrides.d/`,
add `::Plugins::OIDCDeviceAuthorization` to `customPlugins`, and run
`llng-build-manager-files`.

## Configuration

### OIDC Service Settings

In the Manager under **OpenID Connect Service** > **Device Authorization**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcServiceDeviceAuthorizationExpiration` | `600` | Device code TTL (seconds) |
| `oidcServiceDeviceAuthorizationPollingInterval` | `5` | Min polling interval (seconds) |
| `oidcServiceDeviceAuthorizationUserCodeLength` | `8` | User code length |

### Per-RP Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcRPMetaDataOptionsAllowDeviceAuthorization` | `0` | Enable for this RP |

## See Also

- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
