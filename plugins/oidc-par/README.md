# OIDC PAR - Pushed Authorization Requests (RFC 9126)

This plugin implements [RFC 9126 - OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)
for LemonLDAP::NG, both as OIDC Provider and OIDC Client.

## Components

- **`OIDCPushedAuthRequest.pm`** — Provider-side: accepts pushed authorization
  request parameters from RPs, stores them in a session, and returns a
  `request_uri`. Also resolves `request_uri` on the authorization endpoint and
  advertises the PAR endpoint in OIDC discovery via the `oidcGenerateMetadata` hook.
- **`OIDCPushedAuthRequestClient.pm`** — Client-side: pushes authorization
  parameters to a remote OP's PAR endpoint before redirecting the user,
  replacing all query parameters with `client_id` and `request_uri`.
- **`manager-overrides/par.json`** — Manager extension adding PAR configuration
  to OIDC service, RP metadata, and OP metadata.

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install oidc-par --activate
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-plugins.d/`, add
`::Plugins::OIDCPushedAuthRequest, ::Plugins::OIDCPushedAuthRequestClient`
to `customPlugins`, and run `llng-build-manager-files`.

## Configuration

### As OIDC Provider (IDP)

In the Manager, under **OpenID Connect Service**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcServiceMetaDataPushedAuthURI` | `par` | PAR endpoint path |
| `oidcServicePushedAuthExpiration` | `60` | PAR request_uri TTL in seconds |

For each OIDC RP:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcRPMetaDataOptionsPAR` | disabled | PAR mode: `disabled`, `allowed`, or `required` |

When set to `required`, the RP **must** use PAR — direct authorization
requests without a `request_uri` are rejected.

### As OIDC Client (SP)

For each remote OP:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcOPMetaDataOptionsUsePAR` | Disabled | `Disabled`, `Allowed` (use if OP advertises it), or `Required` |

The client automatically reads `pushed_authorization_request_endpoint` from
the OP's discovery document.

## How It Works

1. **RP sends POST to `/oauth2/par`** with all authorization parameters +
   client authentication
2. **LLNG validates** the request, stores parameters in a short-lived session,
   and returns `{ "request_uri": "urn:ietf:params:oauth:request_uri:<id>", "expires_in": 60 }`
3. **RP redirects** user to `/oauth2/authorize?client_id=...&request_uri=urn:...`
4. **LLNG resolves** the `request_uri`, loads stored parameters, deletes the
   session (single-use), and proceeds with normal authorization flow

## Security Benefits

- Authorization parameters are never exposed in browser URL bars or referrer headers
- Enables confidential client authentication at the authorization step
- Single-use request URIs prevent replay attacks
- Short TTL limits the window for stolen request URIs

## See Also

- [RFC 9126 - OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)
- [RFC 9126 in OIDC Security Best Practices](https://openid.net/specs/openid-connect-core-1_0.html)
