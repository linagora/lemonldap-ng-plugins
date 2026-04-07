# OIDC Device Organization - Organization Device Ownership

Extension to the [oidc-device-authorization](../oidc-device-authorization)
plugin that adds organization-level device ownership for RFC 8628 Device
Authorization Grant.

## Overview

By default, tokens issued via Device Authorization Grant are tied to the user
who approved the device enrollment. With organization ownership, the token
identifies the **client application** (the enrolled device) instead.

This is useful for:

- Server enrollment (bastions, CI/CD runners)
- Kiosks and shared devices
- IoT devices
- Any device that should remain authorized even if the approving admin leaves

## Requirements

- LemonLDAP::NG >= 2.23.0
- **oidc-device-authorization** plugin must be installed and active

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install oidc-device-organization --activate
```

## Configuration

For each OIDC RP:

| Parameter                              | Default          | Description                                   |
| -------------------------------------- | ---------------- | --------------------------------------------- |
| `oidcRPMetaDataOptionsDeviceOwnership` | _(empty = user)_ | `organization` to enable org device ownership |

When set to `organization`:

- The admin approves the device enrollment
- The resulting token's subject (`sub`) is the `client_id` instead of the admin
- The token survives the admin leaving the organization
- Refresh tokens follow RP offline session expiration settings

## See Also

- [oidc-device-authorization plugin](../oidc-device-authorization) (required)
- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
