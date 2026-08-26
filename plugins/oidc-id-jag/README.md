# OIDC ID-JAG — Cross-App Access (Identity Assertion JWT Authorization Grant)

This plugin implements the **Identity Provider Authorization Server** role of
[draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/),
also known as **Cross-App Access (XAA)**, on the LemonLDAP::NG OIDC Provider
side.

> **Draft specification.** Claim names and behaviour may still change before
> the draft becomes an RFC.

Cross-App Access puts the identity provider back in control of
application-to-application access, instead of letting each user grant an OAuth
consent directly between two applications. It is mainly designed for AI agents
and MCP servers accessing enterprise APIs.

The flow relies on a short-lived assertion called the **ID-JAG**:

1. a client application obtains tokens from LemonLDAP::NG through a regular
   OpenID Connect login;
2. it exchanges one of them against an **ID-JAG** targeting another
   authorization server (the _Resource Authorization Server_);
3. it presents the ID-JAG to that server using the JWT Bearer grant
   (`urn:ietf:params:oauth:grant-type:jwt-bearer`);
4. it uses the resulting access token to call the resource APIs.

**This plugin implements step 2 only.** The Resource Authorization Server role
(step 3, consuming an ID-JAG through the JWT Bearer grant) is not implemented.

The exchange is answered through the `oidcGotTokenExchange` hook, so the token
endpoint itself is left untouched and the plugin composes with the other token
exchange consumers (Native SSO, `matrix-token-exchange`, …).

## Installation

With `lemonldap-ng-store` (LLNG ≥ 2.24.0) or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install oidc-id-jag
```

The plugin ships an `autoload` rule, so it loads by itself as soon as one
relying party has _Allow Identity Assertion Grant (ID-JAG)_ enabled.

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-plugins.d/`, add
`::Plugins::OIDCIdentityAssertionGrant` to _Custom plugins_, and run
`llng-build-manager-files`.

## Configuration

### Service-level (Manager → _OpenID Connect Service_ → _Timeouts_)

| Parameter                    | Default | Description                                     |
| ---------------------------- | ------- | ----------------------------------------------- |
| `oidcServiceIdJagExpiration` | `300`   | Default lifetime of the assertions, in seconds. |

### Requesting client

In **Manager → _OIDC Relying Parties_ → `<client>` → _Options_**:

| Parameter                              | Section                     | Default | Description                                                                                                                                                                                            |
| -------------------------------------- | --------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `oidcRPMetaDataOptionsAllowIdJagGrant` | _Security_                  | `0`     | Enables the grant, and triggers the plugin autoload. The client must be **confidential** (`oidcRPMetaDataOptionsPublic` off).                                                                          |
| `oidcRPMetaDataOptionsIdJagClientId`   | _Cross-App Access (ID-JAG)_ | _empty_ | Value of the `client_id` claim of the assertion. Defaults to the client identifier known by LemonLDAP::NG; set it when the client is registered under another name on the remote authorization server. |

### Resource Authorization Server

The remote authorization server must be declared as a relying party too, since
it already trusts LemonLDAP::NG for single sign-on. In its options:

| Parameter                                 | Section                     | Default   | Description                                                                                                                                                                                                               |
| ----------------------------------------- | --------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oidcRPMetaDataOptionsIdJagAudience`      | _Cross-App Access (ID-JAG)_ | _empty_   | Its issuer identifier. This is the value clients must send as `audience`, and it is copied into the `aud` claim. Declaring it is what makes this RP reachable as a target.                                                |
| `oidcRPMetaDataOptionsTokenXAuthorizedRP` | _Advanced_                  | _empty_   | Space (or comma) separated list of relying parties allowed to request an ID-JAG for it. Use the **internal LemonLDAP::NG names**, not the client IDs.                                                                     |
| `oidcRPMetaDataOptionsIdJagSignAlg`       | _Cross-App Access (ID-JAG)_ | _default_ | Signature algorithm. Defaults to `RS256` or `ES256` depending on the service key type. Only asymmetric algorithms are offered, since the remote server verifies the assertion against the JWKS document of LemonLDAP::NG. |
| `oidcRPMetaDataOptionsIdJagExpiration`    | _Cross-App Access (ID-JAG)_ | _empty_   | Assertion lifetime, overriding `oidcServiceIdJagExpiration`.                                                                                                                                                              |

The `sub` claim is computed with the **User attribute** of the _resource_
relying party, and **its access rule is enforced**, exactly like for a regular
login — with the magic variable `_oidc_grant_type` set to `idjag`.

## How to use it

The requesting client authenticates on the token endpoint as usual
(`client_secret_basic`, `private_key_jwt`, …) and posts an RFC 8693 token
exchange request:

| Parameter              | Value                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| `grant_type`           | `urn:ietf:params:oauth:grant-type:token-exchange`                                            |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:id-jag`                                                    |
| `audience`             | identifier of the Resource Authorization Server                                              |
| `subject_token`        | an `id_token`, a `refresh_token` or an `access_token` issued to this client                  |
| `subject_token_type`   | `urn:ietf:params:oauth:token-type:id_token`, `…:refresh_token` or `…:access_token` (default) |
| `scope`                | _(optional)_ requested scopes, narrowed down by the policy of the resource relying party     |
| `resource`             | _(optional)_ copied verbatim into the assertion                                              |

```bash
curl -X POST \
 -u "client-id:client-secret" \
 --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
 --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:id-jag" \
 --data-urlencode "audience=https://api.partner.com/" \
 --data-urlencode "subject_token=refreshTokenString" \
 --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:refresh_token" \
 --data-urlencode "scope=openid profile" \
 http://auth.example.com/oauth2/token
```

Response:

```json
{
  "access_token": "eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0Ii...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "token_type": "N_A",
  "expires_in": 300,
  "scope": "openid profile"
}
```

The assertion is a JWT with a `oauth-id-jag+jwt` type header and this payload:

```json
{
  "iss": "http://auth.example.com/",
  "sub": "dwho",
  "aud": "https://api.partner.com/",
  "client_id": "client-id",
  "jti": "Xh0Zq...",
  "iat": 1756000000,
  "exp": 1756000300,
  "scope": "openid profile"
}
```

### Using an ID Token as subject token

This is the flow described by the draft. The ID Token is verified against the
signature algorithm **declared for the client** — pinned, to avoid algorithm
substitution — then the user session is resolved through its `sid` claim.

> `sid` is only stored by LemonLDAP::NG in refresh token sessions, so the
> requesting client must have **Use refresh tokens** _(or offline access)_
> enabled. Otherwise, use the refresh token or the access token directly as
> `subject_token`.

## Error responses

All errors are returned as RFC 6749 JSON error objects with HTTP 400:

| Error                 | Cause                                                                             |
| --------------------- | --------------------------------------------------------------------------------- |
| `unauthorized_client` | The client has no ID-JAG grant, or is a public client                             |
| `invalid_request`     | `audience` is missing                                                             |
| `invalid_target`      | No relying party declares that `audience`                                         |
| `access_denied`       | The client is not in the target's `TokenXAuthorizedRP`, or its access rule failed |
| `invalid_grant`       | `subject_token` is missing, invalid, or was not issued to this client             |

## Discovery metadata

When at least one relying party is allowed to request an ID-JAG, the
`/.well-known/openid-configuration` document advertises:

- `urn:ietf:params:oauth:grant-type:token-exchange` in `grant_types_supported`
- `["urn:ietf:params:oauth:token-type:id-jag"]` as
  `identity_chaining_requested_token_types_supported`

## Enriching the assertion — the `oidcGenerateIdJag` hook

Another plugin can add claims to the assertion just before it is signed:

```perl
use constant hook => { oidcGenerateIdJag => 'addClaimToIdJag' };

sub addClaimToIdJag {
    my ( $self, $req, $payload, $rp, $target, $sessionInfo ) = @_;
    $payload->{tenant} = $sessionInfo->{tenant};
    return PE_OK;
}
```

Parameters: the claims hashref, the configuration key of the relying party
which requested the assertion, the configuration key of the relying party
representing the target Resource Authorization Server, and the user session
data. Returning anything but `PE_OK` aborts the exchange with `server_error`.

## Limitations

- Only the **Identity Provider** role is implemented; consuming an ID-JAG
  through the JWT Bearer grant (Resource Authorization Server role) is not.
- `authorization_details` (RAR) is not forwarded.
- The `client_id` claim can only be overridden globally per client, not per
  (client, resource) pair.

## Tests

```bash
node mcp/cli.js test oidc-id-jag
```

## See also

- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [LemonLDAP::NG OIDC hooks](https://lemonldap-ng.org/documentation/latest/hooks)

## License

Copyright 2026 [LINAGORA](https://linagora.com).

This plugin is licensed under the **GNU Affero General Public License v3.0**
(AGPL-3.0).
