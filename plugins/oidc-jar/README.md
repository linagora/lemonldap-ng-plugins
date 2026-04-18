# OIDC JAR — JWT-Secured Authorization Request (RFC 9101)

This plugin completes LemonLDAP::NG's built-in support of the OIDC Core
`request` and `request_uri` parameters with the full
[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101) JAR profile.

## Features

- **Encrypted request objects (JWE)**: decrypts JWE-wrapped request objects
  using the OP service encryption key before the core verifies the signature.
- **Hardened `request_uri` fetch**: configurable timeout, `Content-Type` check
  (`application/jwt`, `application/oauth-authz-req+jwt`) and response size
  limit.
- **`Require Signed Request Object`**: per-RP option that rejects plain
  authorization requests with the RFC 9101 `request_not_supported` error.
- **RFC 9101 error codes**: emits `invalid_request_object`,
  `invalid_request_uri` and `request_not_supported` back to the RP when
  a usable `redirect_uri` is available.
- **Claim validation**: `iss`, `aud`, `exp`, `nbf`, `iat` (with per-RP
  `oidcRPMetaDataOptionsJarMaxAge`) and `jti` anti-replay cache backed by the
  OIDC session store. Configurable clock skew via `oidcJarClockSkew`.
- **Discovery metadata**: advertises
  `request_object_signing_alg_values_supported`,
  `request_object_encryption_alg_values_supported`,
  `request_object_encryption_enc_values_supported` and
  `require_signed_request_object`.

## Requirements

- LemonLDAP::NG >= 2.23.0

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install oidc-jar
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::OIDCJar` to
`customPlugins`, and run `llng-build-manager-files`.

## Configuration

### OIDC service (global, under **OpenID Connect Service > Security**)

| Key                         | Default | Purpose                                                                                |
| --------------------------- | ------- | -------------------------------------------------------------------------------------- |
| `oidcJarRequestUriTimeout`  | `10`    | HTTP timeout (seconds) when fetching a `request_uri`.                                  |
| `oidcJarRequestUriMaxSize`  | `65536` | Max size in bytes of the body returned from a `request_uri`.                           |
| `oidcJarClockSkew`          | `30`    | Clock skew tolerance (seconds) for `exp`, `nbf`, `iat` checks.                         |
| `oidcJarJtiTtl`             | `600`   | Fallback TTL (seconds) of the jti replay cache when no `exp` claim is provided.        |

### Relying Party

Under the RP's **Options > Security**:

- `oidcRPMetaDataOptionsRequireSignedRequestObject` — refuse plain requests.
- `oidcRPMetaDataOptionsJarMaxAge` — reject request objects older than N
  seconds based on their `iat` claim (`0` disables the check).

Under the RP's **Options > Algorithms**:

- `oidcRPMetaDataOptionsJarSigAlg` — expected JWS `alg`.
- `oidcRPMetaDataOptionsJarEncAlg` — expected JWE `alg` (key management).
- `oidcRPMetaDataOptionsJarEncEnc` — expected JWE `enc` (content encryption).

## Status

Beta. Core LLNG already parses OIDC Core request objects; this plugin adds
the RFC 9101 hardening (encryption, URI fetch safety, claim validation,
error codes, discovery).

## License

GPL-2.0+, following LemonLDAP::NG.
