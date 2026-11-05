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

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install oidc-federation
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
| `oidcFederationFetchTimeout`   | `5`                | Timeout in seconds for one federation HTTP fetch        |
| `oidcFederationResolutionTimeout` | `15`           | Maximum wall-clock time for one trust chain resolution (`0` uses the default) |
| `oidcFederationAllowPrivateHosts` | `0`             | Allow loopback/private/link-local hosts; uses the standard LWP agent (proxy support, per-read timeout). Lab use only |
| `oidcFederationCacheTTL`       | `60`               | Trust chain cache TTL, negative results included (`0` disables) |

> By default federation fetches use `LWPx::ParanoidAgent`: loopback, private
> and link-local destinations are refused, but it has **no proxy support** and
> only follows IPv4 `A`/`CNAME` records. Set `oidcFederationAllowPrivateHosts`
> only in a lab: it restores the standard LWP agent (proxies included) but
> removes the address filtering, and its timeout is per read.

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

Every statement must link `iss` and `sub`, carry a non-expired `exp`, and
each Entity Configuration is verified with the keys its superior vouched
for; a leaf without usable `jwks` is refused. Trust anchors are verified with
the `jwks` from `oidcFederationTrustAnchors`, never with the keys they
publish themselves.

Metadata policies are type-checked: `one_of`, `subset_of`, `superset_of` and
`add` operands must be arrays, a `one_of` mismatch or a missing `essential`
claim refuses the chain, and `superset_of` is a check rather than an
addition. `redirect_uris`, `response_types` and `grant_types` must be arrays
of non-empty strings before a virtual RP is built.

Entity identifiers, authority hints and fetch URLs must be `https` URLs
without query or fragment, and the `sub` parameter is encoded with
`URI->query_form`. A resolution is limited to 20 fetches, 5 authority hints
per level and a wall-clock deadline (`oidcFederationResolutionTimeout`, 15 s
by default); each response is capped at 512 KiB and each fetch times out
after `oidcFederationFetchTimeout` (5 s by default). Destinations are
filtered by `LWPx::ParanoidAgent` unless `oidcFederationAllowPrivateHosts` is
set.

Resolved chains are cached for `oidcFederationCacheTTL` seconds (60 by
default), negative results included, without outliving the chain `exp`; `0`
disables the cache.

### Federation-Aware Registration

Federated clients register through the standard dynamic registration endpoint
with `token_endpoint_auth_method=private_key_jwt` and a `trust_chain` member.
The chain must resolve to a configured trust anchor, and
`oidcServiceAllowDynamicRegistration` must be `2` (the value that also allows
public clients). The registered client takes its `client_id` (the entity ID),
redirect URIs and other options from the policy-applied chain metadata only;
the request body is not used for them, and `redirect_uris` is required in the
chain. No client secret is issued: the client authenticates with the keys in
its Entity Configuration. The chain values also replace the request metadata
used for core validation and the 201 response.

A valid chain returns `PE_OK` and an invalid one `PE_ERROR`; the plugin never
falls back to ordinary dynamic registration. Only the fixed entry created by
federated registration is reused: an existing federated entry is merged,
keeping admin tweaks such as its access rule, but any other RP that uses the
entity ID as `ClientID` or `FederationEntityId` is a conflict and is never
overwritten. The saved options use `oidcRPMetaDataOptionsAuthMethod` and a
JSON `oidcRPMetaDataOptionsJwks`.

The core requires a `jwks_uri` in the registration request for
`private_key_jwt`. When the chain metadata provides one it replaces the
request value; otherwise the request must carry one (it is not used to build
the RP options). The response is a plain RFC 7591 JSON document, not the
`application/entity-statement+jwt` response of OpenID Federation §12.2; this
is a known limitation of dynamic registration.

## See Also

- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
- [LemonLDAP::NG Documentation](https://lemonldap-ng.org)
