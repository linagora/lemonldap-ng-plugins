# OIDC Step-Up — AS-side `acr` / `auth_time` claims (RFC 9470)

This plugin implements the **Authorization Server side** of [RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge](https://www.rfc-editor.org/rfc/rfc9470). It adds the `acr` and `auth_time` claims to JWT-formatted access tokens so a Resource Server can decide whether the user's authentication context is sufficient for the requested operation, and otherwise emit:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
    error_description="A higher LoA or a more recent authentication is required",
    acr_values="urn:llng:loa:elevated",
    max_age=120
```

The client then re-authorizes with the requested `acr_values` / `max_age`, retries, and the API succeeds. **Only the AS-side claim emission is in scope here** — the RS-side challenge logic lives in handler-side or API-side code.

## Why this is needed

Out of the box LemonLDAP::NG already:

- honors `acr_values` and `max_age` on `/oauth2/authorize`;
- forces re-authentication when a stricter `acr` is requested;
- emits `acr` + `auth_time` in the **ID token**.

What is missing for RFC 9470 is `acr` + `auth_time` on the **access token**, since the RS validates the access token, not the ID token. That gap is what this plugin closes — purely through existing hooks, no LLNG core change.

## Installation

With `lemonldap-ng-store` (LLNG ≥ 2.23.0):

```bash
sudo lemonldap-ng-store install oidc-step-up
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/` into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::OIDCStepUp` to *Custom plugins*, and run `llng-build-manager-files`.

## Configuration

Per-RP, in **Manager → *OIDC Relying Parties* → `<rp>` → *Options* → *Security*** :

| Parameter                            | Default | Description                                                                                  |
| ------------------------------------ | ------- | -------------------------------------------------------------------------------------------- |
| `oidcRPMetaDataOptionsStepUpClaims`  | `0`     | Emit `acr` + `auth_time` in the JWT access token issued for this RP. Triggers plugin autoload. |

The `acr` value is derived from the user's `authenticationLevel` exactly the same way the ID token is built:

1. If the deployment defines `oidcServiceMetaDataAuthnContext` mapping (e.g., `urn:llng:loa:basic → 1`, `urn:llng:loa:elevated → 3`), the matching name is used.
2. Otherwise it falls back to `loa-<level>` (e.g., `loa-2`).

If several names map to the same level (almost always a config mistake), the **alphabetically first name wins**, deterministically across runs and processes. The plugin also logs a loud `userLogger->error` at config-load time pointing at the offending level and the names involved, so operators see the issue before clients do.

`auth_time` is the seconds-epoch of the user's last authentication (`_lastAuthnUTime`), the same value LLNG already exposes on the ID token.

## Refresh token behavior

The values stored on the access token reflect the **original** authentication, not the refresh time — exactly what RFC 9470 §3.3 requires. The plugin captures `authenticationLevel` and `_lastAuthnUTime` on the refresh session at issuance (`oidcGenerateRefreshToken`) and restores them at /oauth2/token (`oidcGotTokenRequest`). Tested.

## Hook map

| Hook                       | Role                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------- |
| `oidcGenerateRefreshToken` | Stash `authenticationLevel` + `_lastAuthnUTime` on the refresh session at issuance    |
| `oidcGotTokenRequest`      | At /token, restore those values from the refresh session (refresh grant) or from the user session via `user_session_id` (auth_code grant) |
| `oidcGenerateAccessToken`  | Inject `acr` + `auth_time` into the JWT payload                                       |

## What still needs to be done elsewhere

- **RS-side challenge emission**: a Resource Server protected by an LLNG handler that wants to honor RFC 9470 needs to detect insufficient `acr` / stale `auth_time` and emit the `WWW-Authenticate: Bearer error="insufficient_user_authentication"` response. That's a separate concern — not handled here.
- **`acr_values_supported` discovery field**: nice-to-have. Could be added later via `oidcGenerateMetadata`.

## See also

- [RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge](https://www.rfc-editor.org/rfc/rfc9470)
- [`oidc-rar`](../oidc-rar/) — Rich Authorization Requests (RFC 9396)
- [`oidc-resource-indicators`](../oidc-resource-indicators/) — Resource Indicators (RFC 8707)
