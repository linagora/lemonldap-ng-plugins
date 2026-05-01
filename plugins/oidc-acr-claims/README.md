# OIDC ACR Claims — `acr` + `auth_time` on JWT access tokens

This plugin emits the `acr` (Authentication Context Class Reference) and `auth_time` claims on JWT-formatted access tokens, mirroring what LemonLDAP::NG core already does for ID tokens. It's the AS-side ingredient required by:

- **[RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge](https://www.rfc-editor.org/rfc/rfc9470)** — primary use case;
- **FAPI 2.0** generic conformance;
- audit / logging on the Resource Server side;
- any custom RS-side policy that needs to know how the user authenticated.

LemonLDAP::NG already:

- honors `acr_values` and `max_age` on `/oauth2/authorize`;
- forces re-authentication when a stricter `acr` is requested;
- emits `acr` + `auth_time` on the **ID token**.

What was missing is the same pair on the **access token**, since the RS validates the access token, not the ID token. That gap is what this plugin closes — purely through existing hooks, no LLNG core change.

## RFC 9470 in one paragraph

When the RS considers the user's auth context insufficient for the operation, it returns:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
    error_description="A higher LoA or a more recent authentication is required",
    acr_values="urn:llng:loa:elevated",
    max_age=120
```

The client re-authorizes with the requested `acr_values` / `max_age`, the OP forces step-up auth, the new access token carries the higher `acr`, the API call succeeds.

This plugin only delivers the **claims** that make this loop possible. The 401 emission lives on the RS / handler side, not here.

## Installation

With `lemonldap-ng-store` (LLNG ≥ 2.23.0):

```bash
sudo lemonldap-ng-store install oidc-acr-claims
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/` into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::OIDCAcrClaims` to *Custom plugins*, and run `llng-build-manager-files`.

## Configuration

Per-RP, in **Manager → *OIDC Relying Parties* → `<rp>` → *Options* → *Security*** :

| Parameter                          | Default | Description                                                                                    |
| ---------------------------------- | ------- | ---------------------------------------------------------------------------------------------- |
| `oidcRPMetaDataOptionsAcrClaims`   | `0`     | Emit `acr` + `auth_time` in the JWT access token issued for this RP. Triggers plugin autoload. |

The `acr` value is derived from the user's `authenticationLevel` exactly the same way the ID token is built:

1. If the deployment defines `oidcServiceMetaDataAuthnContext` mapping (e.g., `urn:llng:loa:basic → 1`, `urn:llng:loa:elevated → 3`), the matching name is used.
2. Otherwise it falls back to `loa-<level>` (e.g., `loa-2`).

If several names map to the same level (almost always a config mistake), the **alphabetically first name wins**, deterministically across runs and processes. The plugin also logs a loud `userLogger->error` at config-load time pointing at the offending level and the names involved, so operators see the issue before clients do.

`auth_time` is the seconds-epoch of the user's last authentication (`_lastAuthnUTime`), the same value LLNG already exposes on the ID token.

## Refresh token behavior

The values surfaced on the access token reflect the **original** authentication, not the refresh time — exactly what RFC 9470 §3.3 requires. The plugin captures `authenticationLevel` and `_lastAuthnUTime` on the refresh session at issuance (`oidcGenerateRefreshToken`) and restores them at /oauth2/token (`oidcGotTokenRequest`). Refresh-token rotation preserves the values across rotations.

## Hook map

| Hook                       | Role                                                                                                                |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `oidcGenerateRefreshToken` | Stash `authenticationLevel` + `_lastAuthnUTime` on the refresh session at issuance and on each rotation             |
| `oidcGotTokenRequest`      | At /token, restore those values from the refresh session (refresh grant) or from the user session via `user_session_id` (auth_code grant) |
| `oidcGenerateAccessToken`  | Inject `acr` + `auth_time` into the JWT payload                                                                     |

## What still needs to be done elsewhere

- **RS-side challenge emission**: a Resource Server protected by an LLNG handler that wants to honor RFC 9470 needs to detect insufficient `acr` / stale `auth_time` and emit the `WWW-Authenticate: Bearer error="insufficient_user_authentication"` response. That's a separate concern — not handled here.
- **`acr_values_supported` discovery field**: nice-to-have. Could be added later via `oidcGenerateMetadata`.

## See also

- [RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge](https://www.rfc-editor.org/rfc/rfc9470)
- [`oidc-rar`](../oidc-rar/) — Rich Authorization Requests (RFC 9396)
- [`oidc-resource-indicators`](../oidc-resource-indicators/) — Resource Indicators (RFC 8707)
