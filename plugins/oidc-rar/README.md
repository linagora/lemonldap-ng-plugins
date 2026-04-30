# OIDC RAR — Rich Authorization Requests (RFC 9396)

This plugin implements [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396)
on the LemonLDAP::NG OIDC Provider side.

It accepts an `authorization_details` JSON parameter on `/oauth2/authorize`,
validates it against a per-RP allowlist and an optional Perl rule, persists
the granted entries through the authorization_code and refresh_token flows,
and echoes them in the token response, the JWT access token, and the
introspection response. The supported types are advertised in the
`/.well-known/openid-configuration` document.

## What `authorization_details` looks like

A JSON array of objects, each carrying at least a `type` discriminator. The
shape of the remaining fields is type-specific (the spec deliberately does not
constrain it). Example for an open-banking payment initiation:

```json
[
  {
    "type": "payment_initiation",
    "instructedAmount": { "currency": "EUR", "amount": "100.00" },
    "creditorAccount":  { "iban": "FR7612345...." },
    "creditorName":     "Acme Corp"
  }
]
```

The client passes this URL-encoded on the authorize endpoint:

```
GET /oauth2/authorize?response_type=code&client_id=...&redirect_uri=...
    &scope=openid&state=...&authorization_details=%5B%7B...%7D%5D
```

## Installation

With `lemonldap-ng-store` (LLNG ≥ 2.23.0):

```bash
sudo lemonldap-ng-store install oidc-rar
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-plugins.d/`, add
`::Plugins::OIDCRichAuthRequest` to *Custom plugins*, and run
`llng-build-manager-files`.

## Configuration

### Service-level (Manager → *OpenID Connect Service* → *Security*)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcServiceAuthorizationDetailsTypes` | _empty_ | Global allowlist of accepted `type` values, comma-separated. Empty = no global restriction (per-RP allowlist still applies). |

### Per-RP (Manager → *OIDC Relying Parties* → `<rp>` → *Options* → *Security*)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oidcRPMetaDataOptionsAuthorizationDetailsEnabled` | `0` | Accept `authorization_details` from this RP. Required to trigger plugin autoload. |
| `oidcRPMetaDataOptionsAuthorizationDetailsTypes` | _empty_ | Per-RP allowlist of `type` values, comma-separated. Empty = inherit global only. |
| `oidcRPMetaDataOptionsAuthorizationDetailsRule` | _empty_ | Perl expression evaluated for each requested entry. |

### Authorization model — three layers

Every requested `authorization_details` entry must clear all three:

1. **Type allowlist** — entry's `type` must be in
   `oidcServiceAuthorizationDetailsTypes` ∩
   `oidcRPMetaDataOptionsAuthorizationDetailsTypes`. Either set being empty
   means "no restriction at that level". Both empty means any type goes.
2. **Per-RP Perl rule** — if `oidcRPMetaDataOptionsAuthorizationDetailsRule`
   is set, it is evaluated in LLNG's sandbox (`Safe::reval`) for each entry,
   with the user session attributes plus two magic variables:
   - `$type` — the entry's `type` value
   - `$detail` — the full hashref of the entry
   Truthy result grants the entry; falsy rejects it (whole authorize call
   fails).
3. **User consent** — for the `authorization_code` flow only, the operator's
   consent template (`oidcGiveConsent.tpl` / `oidcConsents.tpl`) can display
   `RAR_DETAILS` (a pretty-printed JSON summary of the pending entries) so
   the end-user can decide. The variable is **HTML-escaped before injection**
   (`HTML::Entities::encode_entities`), so it is safe to render verbatim
   inside `<pre>` / `<code>` without `ESCAPE=HTML`. Example template snippet:
   ```html
   <TMPL_IF NAME="RAR_DETAILS">
     <h4>Requested authorization details</h4>
     <pre><TMPL_VAR NAME="RAR_DETAILS"></pre>
   </TMPL_IF>
   ```

#### Example rules

```perl
# Only allow payment_initiation if user is in the banking group
$type ne 'payment_initiation' or $groups =~ /\bbanking\b/

# Cap payment amounts based on authentication level
$type ne 'payment_initiation'
  or ( $detail->{instructedAmount}->{amount} <= 1000
       or $authenticationLevel >= 4 )
```

## Where the granted details surface

| Location | Mechanism |
|----------|-----------|
| `/oauth2/token` JSON response | Top-level `authorization_details` field |
| JWT access token | `authorization_details` claim (only when LLNG issues structured/JWT access tokens for the RP) |
| `/oauth2/introspect` response | Top-level `authorization_details` field |
| `/.well-known/openid-configuration` | `authorization_details_types_supported` array (union of all enabled RPs' allowed types, intersected with the global allowlist when set) |
| Refresh token grant | Persisted on the refresh session, re-emitted in the new token response |

## Limitations & known gaps (v1)

- **No token-endpoint scope-down.** The client cannot submit a sub-set of
  `authorization_details` at the token endpoint to narrow the grant
  (RFC 9396 §3, optional feature).
- **No type-specific structural validation.** The plugin checks the generic
  shape (array of objects, each with a `type` string) but does not validate
  type-specific fields. Combine the Perl rule + a per-type validator plugin
  if you need to enforce structure.
- **No client-side support yet.** This plugin is OP-only. A
  `OIDCRichAuthRequestClient.pm` for LLNG-as-RP is planned as a follow-up.
- **No dynamic registration support.** `authorization_details_types` in the
  client metadata at `/oauth2/register` is not honored. Add it via a custom
  `oidcRegisterClient` hook in your own plugin if needed.
- **Errors do not RFC-redirect.** A failed validation triggers a portal
  error page rather than a `error=invalid_authorization_details` redirect to
  the RP. Acceptable for v1; refining this requires `PE_SENDRESPONSE` with a
  custom redirect.

## Combining with PAR (RFC 9126)

Since this PR also patches `oidc-par`, `authorization_details` is forwarded
correctly through pushed authorization requests. Push it on `/oauth2/par`
along with the other parameters; the resulting `request_uri` carries it to
`/oauth2/authorize` transparently.

## See also

- [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396)
- [LemonLDAP::NG OIDC hooks](https://lemonldap-ng.org/documentation/latest/hooks)
- [`oidc-par`](../oidc-par/) — Pushed Authorization Requests (RFC 9126)
