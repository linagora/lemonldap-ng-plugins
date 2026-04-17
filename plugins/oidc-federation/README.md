# OIDC Federation - OpenID Connect Federation (Server Side)

> **Beta** — This plugin is under active development. Use with caution.

This plugin implements [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html)
for LemonLDAP::NG as an OIDC Provider.

## Components

- **`Plugins/OpenIDFederation.pm`** — Main plugin: registers federation
  endpoints, hooks into OIDC metadata generation and RP resolution, handles
  federation-aware dynamic registration.
- **`Lib/OpenIDFederation.pm`** — Mouse role providing trust chain resolution,
  entity statement signing/verification, metadata policy enforcement, and
  federation JWK building.
- **`manager-overrides/federation.json`** — Manager extension adding federation
  configuration to OIDC service settings and RP metadata.

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```bash
sudo lemonldap-ng-store install oidc-federation --activate
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::OpenIDFederation`
to `customPlugins`, and run `llng-build-manager-files`.

## Configuration

In the Manager, under **OpenID Connect Service > Federation**:

| Parameter                      | Default            | Description                                            |
| ------------------------------ | ------------------ | ------------------------------------------------------ |
| `oidcFederationEnabled`        | `0`                | Enable OpenID Federation support                       |
| `oidcFederationEntityId`       | _(issuer URL)_     | Federation entity identifier (defaults to OIDC issuer) |
| `oidcFederationAuthorityHints` | _(empty)_          | Space-separated list of superior entity IDs            |
| `oidcFederationSigningKey`     | `default-oidc-sig` | Key ID used for signing entity statements              |
| `oidcFederationSigningAlg`     | `RS256`            | Signing algorithm (RS256/384/512, ES256/384/512)       |
| `oidcFederationTrustAnchors`   | `{}`               | Trust anchors mapping entity IDs to their JWKS         |

For each OIDC RP _(dynamically filled)_:

| Parameter                                 | Default   | Description                      |
| ----------------------------------------- | --------- | -------------------------------- |
| `oidcRPMetaDataOptionsFederationEntityId` | _(empty)_ | Federation entity ID for this RP |

## Endpoints

| Endpoint                                   | Method | Description                            |
| ------------------------------------------ | ------ | -------------------------------------- |
| `/.well-known/openid-federation`           | GET    | Entity Configuration (self-signed JWT) |
| `/oauth2/federation_fetch?sub=<entity_id>` | GET    | Subordinate Statement about a known RP |
| `/oauth2/federation_list`                  | GET    | List of subordinate entity IDs         |

## How It Works

### Entity Configuration

The `/.well-known/openid-federation` endpoint serves the provider's Entity
Configuration as a self-signed JWT (`application/entity-statement+jwt`),
containing:

- OIDC Provider metadata
- Federation entity metadata (fetch/list endpoints)
- Authority hints (pointers to superior entities)
- JWKS for signature verification

### Trust Chain Resolution

When an unknown client presents an entity ID (URL) as `client_id`, the plugin:

1. Fetches the client's Entity Configuration
2. Walks up `authority_hints` to find a path to a configured trust anchor
3. Fetches Subordinate Statements at each level
4. Applies metadata policies from each level
5. Builds a virtual RP configuration from the resolved metadata

Resolved RPs are cached for 1 hour.

### Federation-Aware Registration

RPs can include a `trust_chain` in dynamic registration requests. If a valid
trust chain to a configured trust anchor is found, registration is approved
(even if standard dynamic registration is disabled).

## See Also

- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
- [LemonLDAP::NG Documentation](https://lemonldap-ng.org)
