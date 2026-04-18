# OIDC JARM - JWT Secured Authorization Response Mode (RFC 9207)

This plugin implements [JARM](https://openid.net/specs/oauth-v2-jarm.html)
for LemonLDAP::NG, both as OIDC Provider and OIDC Client.

## Components

- **`OIDCJarm.pm`** — Provider-side: signs (and optionally encrypts) authorization
  responses as JWTs when a Relying Party has JARM enabled. Also advertises
  JARM support in the OIDC discovery document via the `oidcGenerateMetadata` hook.
- **`OIDCJarmClient.pm`** — Client-side: requests JARM response modes from
  remote OPs and verifies received JWT authorization responses
- **`manager-overrides/jarm.json`** — Manager extension adding JARM configuration
  to both OIDC RP and OP metadata

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```
sudo lemonldap-ng-store install oidc-jarm
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/` into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::OIDCJarm, ::Plugins::OIDCJarmClient` to `customPlugins`, and run `llng-build-manager-files`.

## Configuration

### As OIDC Provider (IDP)

For each OIDC RP that should use JARM, set in the Manager:

- **JARM** (`oidcRPMetaDataOptionsJarm`): `Allowed` or `Required`
- **JARM signing algorithm**: default `RS256`
- **JARM encryption** (optional): key management and content encryption algorithms

### As OIDC Client (SP)

For each remote OP, set:

- **Response mode** (`oidcOPMetaDataOptionsResponseMode`): one of `query.jwt`,
  `fragment.jwt`, `form_post.jwt`, or `jwt`

## OIDC Discovery

The plugin automatically advertises JARM support in the OIDC discovery
document (`.well-known/openid-configuration`) via the `oidcGenerateMetadata`
hook. No core patch is needed. The following metadata fields are added:

- `response_modes_supported`: `query.jwt`, `fragment.jwt`, `form_post.jwt`, `jwt`
- `authorization_signing_alg_values_supported`
- `authorization_encryption_alg_values_supported`
- `authorization_encryption_enc_values_supported`

## Files

- `lib/Lemonldap/NG/Portal/Plugins/OIDCJarm.pm` — Provider-side JARM plugin
- `lib/Lemonldap/NG/Portal/Plugins/OIDCJarmClient.pm` — Client-side JARM plugin
- `manager-overrides/jarm.json` — Manager extension (attributes, ctrees, translations)
- `plugin.json` — Plugin metadata
