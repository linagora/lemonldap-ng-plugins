# OIDC CIBA - Client-Initiated Backchannel Authentication

This plugin implements [OpenID Connect CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
for LemonLDAP::NG.

## Features

- **Backchannel authentication endpoint** (`/oauth2/bc-authorize`): accepts
  authentication requests from RPs with `login_hint`, `id_token_hint`, or
  `login_hint_token`
- **Poll and Ping delivery modes**: clients can poll the token endpoint or
  receive a ping notification when authentication completes
- **External authentication channel**: delegates user authentication to an
  external service via configurable webhook
- **CIBA callback endpoint** (`/oauth2/ciba-callback`): receives approval/denial
  from the external authentication channel
- **CIBA grant type** on the token endpoint
  (`urn:openid:params:grant-type:ciba`)
- **Direct approval** when the user is already authenticated
- **OIDC Discovery**: advertises CIBA support via the `oidcGenerateMetadata` hook

## Requirements

- LemonLDAP::NG >= 2.23.0

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install oidc-ciba --activate
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::OIDCCIBA` to
`customPlugins`, and run `llng-build-manager-files`.

## Configuration

### OIDC Service Settings

In the Manager, under **OpenID Connect Service** > **CIBA**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcServiceMetaDataCibaURI` | `bc-authorize` | CIBA endpoint path |
| `oidcServiceMetaDataCibaCallbackURI` | `ciba-callback` | Callback endpoint path |
| `oidcServiceCibaExpiration` | `120` | Default auth_req_id TTL (seconds) |
| `oidcServiceCibaMaxExpiration` | `300` | Maximum auth_req_id TTL (seconds) |
| `oidcServiceCibaInterval` | `5` | Minimum polling interval (seconds) |
| `oidcServiceCibaAuthenticationChannelUrl` | | External auth channel URL |
| `oidcServiceCibaAuthenticationChannelSecret` | | Secret for outgoing auth channel requests |
| `oidcServiceCibaCallbackSecret` | | Secret expected from auth channel callbacks |

### Per-RP Settings

For each OIDC RP:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcRPMetaDataOptionsAllowCIBA` | `0` | Enable CIBA for this RP |
| `oidcRPMetaDataOptionsCIBAMode` | `poll` | Delivery mode: `poll` or `ping` |
| `oidcRPMetaDataOptionsCIBANotificationEndpoint` | | Client notification URL (ping mode) |

## How It Works

1. **RP sends POST to `/oauth2/bc-authorize`** with client auth + user hint
2. **LLNG notifies** the external authentication channel (webhook)
3. **External channel** authenticates the user and calls back `/oauth2/ciba-callback`
4. **RP polls** `/oauth2/token` with `grant_type=urn:openid:params:grant-type:ciba`
   (or receives a ping notification)
5. **LLNG issues tokens** when the user has approved

## See Also

- [OIDC CIBA specification](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
