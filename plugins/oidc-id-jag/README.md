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

This plugin implements **both ends**, as two independent modules you can enable
separately:

| Module                                        | Role                                                                        | Enabled by                                         |
| --------------------------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------- |
| `::Plugins::OIDCIdentityAssertionGrant`       | **Identity Provider AS** — issues the assertion (step 2)                    | an RP with _Allow Identity Assertion Grant_        |
| `::Plugins::OIDCIdentityAssertionGrantServer` | **Resource AS** — consumes an assertion and issues an access token (step 3) | an OP with _Accept ID-JAG issued by this provider_ |

The issuing side is answered through the `oidcGotTokenExchange` hook, so the
token endpoint itself is left untouched and it composes with the other token
exchange consumers (Native SSO, `matrix-token-exchange`, …). The consuming side
plugs into `oidcGotTokenRequest`, the same extension point CIBA and the device
grant use.

## Installation

With `lemonldap-ng-store` (LLNG ≥ 2.24.0) or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install oidc-id-jag
```

Each module ships its own `autoload` rule, so each loads by itself as soon as
its own condition becomes true: the issuing side when a relying party has
_Allow Identity Assertion Grant (ID-JAG)_ enabled, the consuming side when a
provider has _Accept ID-JAG issued by this provider_ enabled. Enabling one does
not load the other.

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-plugins.d/`, add the module(s) you need —
`::Plugins::OIDCIdentityAssertionGrant` and/or
`::Plugins::OIDCIdentityAssertionGrantServer` — to _Custom plugins_, and run
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

### Target resource (the remote authorization server)

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

### Forwarded `authorization_details`

When the subject token carries RFC 9396 `authorization_details` (granted by the
[`oidc-rar`](../oidc-rar) plugin), they travel with the assertion as an
`authorization_details` claim.

The target relying party is a different trust domain, so the entries are
narrowed down by **its** `oidcRPMetaDataOptionsAuthorizationDetailsTypes`
allowlist: an entry whose `type` the target does not accept is dropped rather
than forwarded. An empty allowlist means no restriction, exactly as in
`oidc-rar`. The `oidcGenerateIdJag` hook can still amend the list.

### Using an ID Token as subject token

This is the flow described by the draft. The ID Token is verified against the
signature algorithm **declared for the client** — pinned, to avoid algorithm
substitution — then the user session is resolved through its `sid` claim.

LemonLDAP::NG only persists `sid` on refresh token sessions, so resolving an
ID Token would otherwise require the client to be allowed refresh tokens. The
plugin therefore keeps its own reverse index: one short-lived record per ID
Token issued to a relying party that is allowed to request an ID-JAG, living
exactly as long as the ID Token it describes. Clients without refresh tokens
work out of the box; only RPs with the grant enabled pay for the extra record.

> Resolution falls back to the historical `sid` search when the index has no
> entry — ID Tokens issued before this plugin was installed, and sessions
> opened against an upstream OP, which carry the OP's own `sid`. Only that
> fallback path also carries `authorization_details`.

## Consuming an ID-JAG — the Resource Authorization Server role

The other half of the flow: a client that holds an ID-JAG minted by a trusted
identity provider presents it here, with the RFC 7523 JWT Bearer grant, and
gets a local access token.

```bash
curl -X POST \
 -u "client-id:client-secret" \
 --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
 --data-urlencode "assertion=eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0Ii..." \
 --data-urlencode "scope=openid profile" \
 http://resource-as.example.com/oauth2/token
```

### Declaring the trusted identity provider

The issuing provider is declared as an **OpenID Connect Provider** in the
Manager — the same object LemonLDAP::NG uses when it is an OIDC client, so its
`issuer` and JWKS come from the usual metadata fields
(`oidcOPMetaDataJSON` / `oidcOPMetaDataJWKS`, or a configuration URI).

| Parameter                                 | Default | Description                                                                                       |
| ----------------------------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `oidcOPMetaDataOptionsAllowIdJagGrant`    | `0`     | Accept ID-JAGs issued by this provider. Required to trigger the autoload of the consuming module. |
| `oidcOPMetaDataOptionsIdJagUserAttribute` | `sub`   | Claim of the assertion carrying the local user identifier.                                        |

On the client presenting the assertion:

| Parameter                               | Default | Description                                                  |
| --------------------------------------- | ------- | ------------------------------------------------------------ |
| `oidcRPMetaDataOptionsAllowIdJagBearer` | `0`     | Allow this client to exchange an ID-JAG for an access token. |

Globally (Manager → _OpenID Connect Service_ → _Security_):

| Parameter                     | Default      | Description                                                                                        |
| ----------------------------- | ------------ | -------------------------------------------------------------------------------------------------- |
| `oidcServiceIdJagAudience`    | _the issuer_ | Identifier remote providers must send as `aud`. Set it when they know this server by another name. |
| `oidcServiceIdJagAllowedSkew` | `30`         | Clock skew tolerated on `exp` / `iat` / `nbf`, in seconds.                                         |
| `oidcServiceIdJagChoice`      | _empty_      | `authChoiceModules` entry used to resolve the subject when the server runs `Auth = Choice`.        |

### What is checked

1. `typ` header is `oauth-id-jag+jwt` — a plain JWT is refused, so this grant
   never becomes a generic JWT bearer path.
2. The signature algorithm is asymmetric, and the signature verifies against
   the JWKS of the issuing provider.
3. `iss` names a provider configured with _Accept ID-JAG_, re-checked on the
   **verified** payload.
4. `aud` names this server.
5. `exp` / `nbf` / `iat` are fresh, within the tolerated skew.
6. `client_id` matches the authenticated client.
7. `jti` has not been seen before — **single use is enforced**, recorded until
   the assertion would have expired anyway.

The asserted subject is then resolved through the local user backends
(`getUser` → `setSessionInfo` → groups → macros): no interactive
authentication happens, the provider already vouched for the user. The relying
party access rule is evaluated last, with `_oidc_grant_type` set to `idjag`.

`authorization_details` carried by the assertion are copied onto the access
token session, so `oidc-rar` surfaces them on introspection.

`urn:ietf:params:oauth:grant-type:jwt-bearer` is advertised in
`grant_types_supported` as soon as one provider is trusted.

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

When at least one provider is trusted to issue ID-JAGs, it also advertises:

- `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types_supported`

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

- The draft is not stabilized: claim names and behaviour may still change.
- The `client_id` claim can only be overridden globally per client, not per
  (client, resource) pair.
- On the issuing side, `authorization_details` forwarded from an **ID Token**
  `subject_token` requires that ID Token to resolve through a refresh token
  session — the `sid` index carries the user session, not the grant. Refresh
  and access tokens as `subject_token` are unaffected.
- On the consuming side, the subject must exist in the local user backends;
  there is no just-in-time provisioning.

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
