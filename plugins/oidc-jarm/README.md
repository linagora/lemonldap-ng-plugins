# OIDC JARM - JWT Secured Authorization Response Mode (RFC 9207)

This plugin implements [JARM](https://openid.net/specs/oauth-v2-jarm.html)
for LemonLDAP::NG, both as OIDC Provider and OIDC Client.

## Components

- **`OIDCJarm.pm`** — Provider-side: signs (and optionally encrypts) authorization
  responses as JWTs when a Relying Party has JARM enabled
- **`OIDCJarmClient.pm`** — Client-side: requests JARM response modes from
  remote OPs and verifies received JWT authorization responses
- **`manager-overrides/jarm.json`** — Manager extension adding JARM configuration
  to both OIDC RP and OP metadata

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.23.0)_:

```
sudo lemonldap-ng-store install oidc-jarm --activate
```

Manually: copy `lib/` into your Perl `@INC` path, copy `manager-overrides/` into `/etc/lemonldap-ng/manager-plugins.d/`, add `::Plugins::OIDCJarm, ::Plugins::OIDCJarmClient` to `customPlugins`, and run `llng-build-manager-files`.

## Configuration

### As OIDC Provider (IDP)

For each OIDC RP that should use JARM, set in the Manager:

- **JARM** (`oidcRPMetaDataOptionsJarm`): `Allowed` or `Required`
- **JARM signing algorithm**: default `RS256`
- **JARM encryption** (optional): key management and content encryption algorithms

### As OIDC Client (SP)

For each remote OP, set:

- **Response mode** (`oidcOPMetaDataOptionsResponseMode`): one of `query.jwt`,
  `fragment.jwt`, `form_post.jwt`, or `jwt`

## Optional: OIDC Discovery metadata patch

The plugin works without modifying the core, but the OIDC discovery document
(`.well-known/openid-configuration`) will not advertise JARM support
(`response_modes_supported` and `authorization_*_alg_values_supported`).

To enable JARM advertisement, apply this patch to
`Lemonldap::NG::Common::OpenIDConnect::Metadata`:

```diff
@@ -115,7 +115,18 @@ sub metadataDoc {
         # Scopes
         scopes_supported         => [qw/openid profile email address phone/],
         response_types_supported => $response_types,
-        response_modes_supported => [ "query", "fragment", "form_post", ],
+        response_modes_supported => [
+            "query", "fragment", "form_post",
+            (
+                # Add JARM response modes if at least one RP has JARM enabled
+                grep {
+                    $conf->{oidcRPMetaDataOptions}->{$_}
+                      ->{oidcRPMetaDataOptionsJarm}
+                } keys %{ $conf->{oidcRPMetaDataOptions} // {} }
+            )
+            ? ( "query.jwt", "fragment.jwt", "form_post.jwt", "jwt" )
+            : ()
+        ],
         grant_types_supported    => $grant_types,
@@ -143,6 +154,20 @@ sub metadataDoc {
         introspection_encryption_alg_values_supported => ENC_ALG_SUPPORTED,
         introspection_encryption_enc_values_supported => ENC_SUPPORTED,

+        # JARM (JWT Secured Authorization Response Mode)
+        (
+            grep {
+                $conf->{oidcRPMetaDataOptions}->{$_}
+                  ->{oidcRPMetaDataOptionsJarm}
+            } keys %{ $conf->{oidcRPMetaDataOptions} // {} }
+        )
+        ? (
+            authorization_signing_alg_values_supported    => \@supportedSigAlg,
+            authorization_encryption_alg_values_supported => ENC_ALG_SUPPORTED,
+            authorization_encryption_enc_values_supported => ENC_SUPPORTED,
+          )
+        : (),
+
         # PKCE
```

## Files

- `lib/Lemonldap/NG/Portal/Plugins/OIDCJarm.pm` — Provider-side JARM plugin
- `lib/Lemonldap/NG/Portal/Plugins/OIDCJarmClient.pm` — Client-side JARM plugin
- `manager-overrides/jarm.json` — Manager extension (attributes, ctrees, translations)
- `plugin.json` — Plugin metadata
