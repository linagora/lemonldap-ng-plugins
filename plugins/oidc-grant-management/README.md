# OIDC Grant Management — FAPI Grant Management API

This plugin implements the **OpenID Foundation [FAPI Grant Management for OAuth 2.0](https://openid.net/specs/fapi-grant-management.html)** specification on the LemonLDAP::NG OIDC Provider side.

It introduces *grants* as durable first-class records, distinct from tokens: a grant captures the cumulative set of scopes (and `authorization_details` if `oidc-rar` is also active) authorized for a `(client, user)` couple, persists across token rotations, and can be queried or revoked through a RESTful API independently of any individual token's lifecycle.

## Why grants?

Plain OAuth 2.0 has access tokens (short-lived) and refresh tokens (medium-lived) but **nothing durable that materializes the user's authorization**. Apps that need to:

- track "what did this user authorize this client to do, and when?";
- let the user revoke an entire authorization in one operation, not token by token;
- ask the user to *renew* an authorization (PSD2 §50: 90-day refresh) without restarting from scratch;
- *add* permissions to an existing authorization (e.g., the user adds a second bank account to a fintech app);

…all need a notion of grant. This plugin adds it.

## What it does

Three things, with a **`grant_id`** that ties them together:

### 1. `grant_management_action` parameter on `/oauth2/authorize`

| Action      | Effect                                                                                                                                  |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `create`    | (default if RP mode allows) Mint a fresh grant. The new `grant_id` is returned in the token response.                                   |
| `update`    | Load the grant pointed at by the `grant_id` request parameter and **add** the requested scopes/details. Same `grant_id` is returned.    |
| `replace`   | Load the grant and **replace** its scope set with the newly requested one. Same `grant_id` is returned.                                 |

### 2. `grant_id` field

Surfaces in three places:

- **Token response JSON** (always, when an action was provided);
- **JWT access token claim** (`grant_id`);
- **Introspection response**.

### 3. RESTful endpoint

```
GET    /oauth2/grants/{grant_id}    →  200 JSON describing the grant
DELETE /oauth2/grants/{grant_id}    →  204 No Content; grant revoked
```

Authenticated as the OAuth client that owns the grant (`Authorization: Basic` or any of the standard token-endpoint client auth methods). A client cannot read or revoke a grant that doesn't belong to it (returns 403).

## Installation

With `lemonldap-ng-store` (LLNG ≥ 2.24.0):

```bash
sudo lemonldap-ng-store install oidc-grant-management
```

Manually: copy `lib/` and `manager-overrides/`, add `::Plugins::OIDCGrantManagement` to *Custom plugins*, run `llng-build-manager-files`.

## Configuration

In **Manager → *OpenID Connect Service*** :

| Parameter                                | Default     | Description                                                                                  |
| ---------------------------------------- | ----------- | -------------------------------------------------------------------------------------------- |
| `oidcServiceMetaDataGrantManagementURI`  | `grants`    | Endpoint path component. Final URL is `/<oidc-path>/<this>/{grant_id}`.                     |
| `oidcServiceGrantExpiration`             | `7776000`   | Grant TTL in seconds. Default 90 days, aligned with PSD2.                                    |

In **Manager → *OIDC Relying Parties* → `<rp>` → *Options* → *Security*** :

| Parameter                              | Values                          | Description                                                                                            |
| -------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `oidcRPMetaDataOptionsGrantManagement` | `""` / `allowed` / `required`   | Disabled / accept `grant_management_action` if the client sends it / reject authorize without action. |

## Discovery

When at least one RP has Grant Management enabled, the plugin advertises:

```json
{
  "grant_management_endpoint": "https://op.example.com/oauth2/grants",
  "grant_management_actions_supported": ["create", "replace", "update"]
}
```

## Limitations (v1)

- **Token cascade revocation is best-effort.** `DELETE /oauth2/grants/{id}` removes the grant session, but already-issued access tokens stay valid until they expire. Operators wanting hard cascade can shorten access-token TTLs or pair this plugin with a custom userinfo/introspection hook that re-checks the grant. A hooked re-check feature can land in v2.
- **`merge` action not supported.** RFC says it's optional and the semantics are ambiguous.
- **No native consent-screen integration.** When an `update` or `replace` action arrives with `BypassConsent=0`, the user sees the standard consent UI, not a delta-aware one. Operators wanting a delta UI need a custom template.
- **Grant ownership tied to the RP confKey.** A client renamed in the manager loses access to grants held under its old name. Don't rename RPs in flight.

## Hook map

| Hook                                | Role                                                                                                                  |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `oidcGotRequest`                    | Parse `grant_management_action` + `grant_id`, validate against the per-RP mode, stash on `$req->data`                 |
| `oidcGenerateCode`                  | Materialize the grant (mint or update/replace) so its id is known before any AT is built; persist on the code session |
| `oidcGotTokenRequest`               | At /token, restore grant context from the code or refresh session                                                     |
| `oidcGenerateRefreshToken`          | Carry the grant context onto refresh sessions (survives rotation)                                                     |
| `oidcGenerateAccessToken`           | Add `grant_id` claim to JWT AT and patch the AT session for introspection                                             |
| `oidcGenerateTokenResponse`         | Echo `grant_id` in the JSON token response                                                                            |
| `oidcGenerateIntrospectionResponse` | Surface `grant_id` in introspection                                                                                   |
| `oidcGenerateMetadata`              | Advertise `grant_management_endpoint` + `_actions_supported`                                                          |

The RESTful endpoint is registered in `init()` via `addUnauthRoute` with the `:grant_id` path-capture syntax.

## Combining with `oidc-rar`

If `oidc-rar` is also loaded, the grant carries `authorization_details` alongside the scope set: GET on the grant returns the cumulative `authorization_details`, and `update`/`replace` extends/replaces them the same way they do for scopes.

## See also

- [FAPI Grant Management for OAuth 2.0](https://openid.net/specs/fapi-grant-management.html)
- [`oidc-rar`](../oidc-rar/) — Rich Authorization Requests (RFC 9396)
- [`oidc-resource-indicators`](../oidc-resource-indicators/) — Resource Indicators (RFC 8707)
- [`oidc-acr-claims`](../oidc-acr-claims/) — `acr` + `auth_time` on JWT access tokens
