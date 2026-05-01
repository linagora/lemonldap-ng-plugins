# OIDC Resource Indicators (RFC 8707)

This plugin implements [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707) on the LemonLDAP::NG OIDC Provider side.

It lets clients name the target Resource Server(s) on `/oauth2/authorize` and `/oauth2/token` via the `resource` parameter, evaluates per-RS scope rules against the requesting user, and binds the issued tokens (JWT `aud`, introspection response, refresh token) to the resolved RS identifier(s). The RS itself is just an OIDC RP with `oidcRPMetaDataOptionsEnableRI = 1`.

## Installation

With `lemonldap-ng-store` (LLNG ≥ 2.24.0) or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install oidc-resource-indicators
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/` into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::OIDCResourceIndicators` to _Custom plugins_, and run `llng-build-manager-files`.

## Configuration

For each RP that represents an API (Resource Server), in **Manager → _OIDC Relying Parties_ → `<rp>`** :

| Parameter                           | Type | Description                                                                                                                                                                                                                      |
| ----------------------------------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oidcRPMetaDataOptionsEnableRI`     | bool | Mark this RP as a Resource Server target                                                                                                                                                                                         |
| `oidcRPMetaDataOptionsRIIdentifier` | text | RS identifier (audience). Defaults to `clientId` when empty                                                                                                                                                                      |
| `oidcRPMetaDataRIScopes`            | hash | Hash `scope_name → human description`. Declares which scopes belong to this RS                                                                                                                                                   |
| `oidcRPMetaDataRIScopeRules`        | hash | Hash `scope_name → Perl rule`. The rule is evaluated against `$req->sessionInfo` whenever a client targets this RS and asks for the scope. Truthy grants, falsy denies. `1` / `accept` always grants, `0` / `deny` always denies |

## Flow

```
Client → /oauth2/authorize?...&scope=read:users&resource=https://api.example.com
       ↓
       OP looks up the RP whose RIIdentifier == "https://api.example.com" (= the RS)
       Evaluates oidcRPMetaDataRIScopeRules{<rs>}{read:users} against the user
       If granted: binds the access token to the RS audience
       ↓
       Issues code → client exchanges → JWT access token has
         "aud": ["clientId", "https://api.example.com"]
         "scope": "read:users …"
       Introspection response carries the same audience and scope
       ↓
Client → API at https://api.example.com with Bearer <token>
       API verifies "aud" includes itself before honoring the call
```

`resource` may be repeated (multiple RS) and may also appear on the token endpoint for `client_credentials` grants and on refresh. Refresh sessions persist the resolved audiences so subsequent refreshes echo them automatically.

## Hook strategy

The plugin uses **only existing LLNG ≥ 2.23 hooks**, no core change required. The only subtlety is the access token _session_ (where introspection reads its data from): there is no `oidcGenerateAccessTokenSession` hook in 2.23, so we patch the AT session post-creation via `oidcGenerateTokenResponse` + `Lemonldap::NG::Common::JWT::getAccessTokenSessionId` (which handles JWT ⇒ jti and opaque ⇒ token-as-id).

| Hook                                | Role                                                                                |
| ----------------------------------- | ----------------------------------------------------------------------------------- |
| `oidcGotRequest`                    | Capture `resource` param at /authorize                                              |
| `oidcGotTokenRequest`               | Restore RS audiences from code session (auth_code) / capture for client_credentials |
| `oidcGotOnlineRefresh`              | Re-evaluate RS scopes and audiences on online refresh                               |
| `oidcGotOfflineRefresh`             | Same for offline refresh                                                            |
| `oidcResolveScope`                  | Filter scope list against per-RS rules                                              |
| `oidcGenerateCode`                  | Persist resolved audiences on code session                                          |
| `oidcGenerateRefreshToken`          | Persist resolved audiences on refresh session                                       |
| `oidcGenerateAccessToken`           | Add resolved audiences to JWT `aud` claim                                           |
| `oidcGenerateTokenResponse`         | Patch AT session post-creation so introspection sees the audiences                  |
| `oidcGenerateIntrospectionResponse` | Surface RS audiences in introspection response                                      |

## Origin

Ported from the LLNG core draft for [issue #3542](https://gitlab.ow2.org/lemonldap-ng/lemonldap-ng/-/issues/3542) (branch `3542-rfc-8707`, commit `a035ea96`). The draft adds a new `oidcGenerateAccessTokenSession` hook to core; this port avoids that addition by using an existing hook + post-hoc `updateToken` (same workaround pattern as `oidc-rar`).

## See also

- [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [`oidc-rar`](../oidc-rar/) — Rich Authorization Requests (RFC 9396)
- [`oidc-par`](../oidc-par/) — Pushed Authorization Requests (RFC 9126)
