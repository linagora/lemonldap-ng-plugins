# OIDC Grant Management — FAPI Grant Management API

This plugin implements the **OpenID Foundation [FAPI Grant Management for OAuth 2.0](https://openid.net/specs/fapi-grant-management.html)** specification on the LemonLDAP::NG OIDC Provider side.

It introduces _grants_ as durable first-class records, distinct from tokens: a grant captures the cumulative set of scopes (and `authorization_details` if `oidc-rar` is also active) authorized for a `(client, user)` couple, persists across token rotations, and can be queried or revoked through a RESTful API independently of any individual token's lifecycle.

## Why grants?

Plain OAuth 2.0 has two kinds of artifacts: access tokens (minutes) and refresh tokens (hours to weeks). Neither _materializes the underlying authorization_. There is no standard way to ask the AS "what did this user authorize this client to do, and when?", or to "remove this app's access" in one go: token revocation works token by token, and a refresh token chain that's been rotated is gone — but the _intent_ it represented is invisible to everyone.

A **grant** is the missing first-class record. One grant per `(client, user)` (per consent), durable, queryable, modifiable, revocable. Tokens become tags on the grant, not the authorization itself.

### Concrete scenarios

#### 1. Open banking (the canonical use case)

PSD2 RTS Article 10(b) caps "Account Information Service" consent durations to 90 days — every 90 days the user must reaffirm. Without grant management, the fintech app drives the user back through a full authorize flow with all the consent UI: scope selection, account picker, etc. With grant management it sends:

```
GET /oauth2/authorize?
    grant_management_action=update&
    grant_id=<the-existing-id>&
    scope=accounts+balances&
    ...
```

The OP loads the existing grant, asks the user only "extend until next quarter?", and the fintech keeps working with the same `grant_id`. No data loss on the fintech side (account selections stay tied to the same grant), no UX trauma for the user.

#### 2. Add an account / scope to an active authorization

A user authorized a fintech to read their checking account. A month later they buy a stock and want the fintech to read their broker account too. Without grant management: full re-authorize. With:

```
GET /oauth2/authorize?
    grant_management_action=update&
    grant_id=<existing>&
    authorization_details=[{"type":"account_information","accounts":["broker-789"]}]
```

The OP shows a delta consent ("add broker-789?"), the grant grows. Same id everywhere.

#### 3. "Disconnect this app" in user-facing dashboards

`Settings → Connected Apps → Acme Bank → Disconnect`. With plain OAuth, the operator either runs N revocation calls (one per outstanding refresh token) or relies on cookie-based session bookkeeping. With grant management the dashboard issues a single `DELETE /oauth2/grants/<id>` and is done — and the AS can then proactively iterate tokens to invalidate them on the next request (best-effort in v1; see Limitations).

#### 4. "Show me what these apps have access to"

Same dashboard. To render the "Acme Bank can read: account-1, account-2, balances since 2026-01-15" panel, the operator hits `GET /oauth2/grants/<id>` and gets a structured JSON. No need to invent a separate management API.

#### 5. Multiple grants for the same RP

Some setups want one grant per device or per use case. PSD2 explicitly allows it: the same fintech holds one `grant_id` for "balances" (90-day TTL) and another for "payments" (one-shot or short-lived), revocable independently. This plugin supports it: each `grant_management_action=create` mints a fresh grant. The client tracks them by id.

#### 6. Compliance and audit

A grant carries `created_at`, `last_used_at`, the cumulative scope set, the cumulative `authorization_details`. That's exactly the audit trail PSD3, DORA, and most banking regulators want. The plugin doesn't ship a dashboard, but the data is there for one.

### Why refresh tokens aren't enough

| Need                                      | Refresh token                                                       | Grant                                                            |
| ----------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------- |
| "What scopes did this user authorize?"    | Stored implicitly, not queryable                                    | First-class field                                                |
| Revoke an authorization                   | Revoke the RT — but ATs issued from it stay valid until expiration  | Same caveat for v1 (see Limitations), but the intent is captured |
| Survive RT rotation                       | RT id changes on every rotation; the "authorization" loses identity | `grant_id` is stable                                             |
| Two devices, same auth                    | Two unrelated RT chains; no shared identity                         | Optional: same `grant_id` across both, or two grants             |
| Add/remove permissions mid-life           | Not possible — must re-authorize from scratch                       | `update` / `replace`                                             |
| Inspect from the user's account dashboard | No standard endpoint                                                | `GET /oauth2/grants/{id}`                                        |

### Where this matters today

- **PSD2 / open banking** — RTS Article 10 essentially forces grant-management thinking; the FAPI WG wrote this spec largely with PSD2 in mind.
- **Open insurance, open energy, open data** — all importing the PSD2 model.
- **PSD3** (2026 draft) — raises the consent expiry to 180 days and explicitly references grant management as the renewal mechanism.
- **Healthcare / HEART** — similar consent-driven flows with stricter audit requirements.
- **Enterprise B2B** — multi-tenant SaaS where a client app holds different grants per customer tenant; admins want a "kill switch" per tenant without breaking the others.

## What it does

Three things, with a **`grant_id`** that ties them together:

### 1. `grant_management_action` parameter on `/oauth2/authorize`

| Action    | Effect                                                                                                                               |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `create`  | Mint a fresh grant. The new `grant_id` is returned in the token response. (Action is opt-in: an authorize call without `grant_management_action` does NOT create a grant — the FAPI draft has gone back and forth on whether `create` is implicit; this plugin requires it explicitly.) |
| `update`  | Load the grant pointed at by the `grant_id` request parameter and **add** the requested scopes/details. Same `grant_id` is returned. |
| `replace` | Load the grant and **replace** its scope set with the newly requested one. Same `grant_id` is returned.                              |

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

Manually: copy `lib/` and `manager-overrides/`, add `::Plugins::OIDCGrantManagement` to _Custom plugins_, run `llng-build-manager-files`.

## Configuration

In **Manager → _OpenID Connect Service_** :

| Parameter                               | Default   | Description                                                             |
| --------------------------------------- | --------- | ----------------------------------------------------------------------- |
| `oidcServiceMetaDataGrantManagementURI` | `grants`  | Endpoint path component. Final URL is `/<oidc-path>/<this>/{grant_id}`. |
| `oidcServiceGrantExpiration`            | `7776000` | Grant TTL in seconds. Default 90 days, aligned with PSD2.               |

In **Manager → _OIDC Relying Parties_ → `<rp>` → _Options_ → _Security_** :

| Parameter                              | Values                        | Description                                                                                           |
| -------------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| `oidcRPMetaDataOptionsGrantManagement` | `""` / `allowed` / `required` | Disabled / accept `grant_management_action` if the client sends it / reject authorize without action. |

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
- **Grant ownership tied to `client_id`, not the RP confKey.** As long as the OAuth `client_id` stays the same, renaming the RP in the manager (changing its confKey) preserves access. Changing a client's `client_id` is what loses access — that's by design (it's a different client).

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

If `oidc-rar` is also loaded, the grant carries `authorization_details` alongside the scope set. Both follow the same per-action semantics:

- **`create`** — the grant is born with the request's `authorization_details`.
- **`update`** — the new entries are unioned into the existing list, deduped by structural (JSON-canonical) equality. So a fintech adding a second account doesn't lose the first one.
- **`replace`** — the existing list is replaced by the request's entries verbatim.

GET on the grant returns the cumulative `authorization_details`.

## See also

- [FAPI Grant Management for OAuth 2.0](https://openid.net/specs/fapi-grant-management.html)
- [`oidc-rar`](../oidc-rar/) — Rich Authorization Requests (RFC 9396)
- [`oidc-resource-indicators`](../oidc-resource-indicators/) — Resource Indicators (RFC 8707)
- [`oidc-acr-claims`](../oidc-acr-claims/) — `acr` + `auth_time` on JWT access tokens
